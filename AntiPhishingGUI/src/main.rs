#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::{
    fs,
    io::{Cursor, Read, Write},
    net::{TcpStream, ToSocketAddrs},
    panic::{AssertUnwindSafe, catch_unwind},
    path::{Path, PathBuf},
    sync::mpsc::{Receiver, RecvTimeoutError, Sender, TryRecvError},
    sync::{Arc, LazyLock, mpsc},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Local, NaiveDate};
use eframe::egui::{self, ViewportCommand};
use imap::Session;
use mailparse::{MailHeaderMap, parse_mail};
use quick_xml::{Reader, events::Event};
use regex::Regex;
use serde::{Deserialize, Serialize};
use single_instance::SingleInstance;
use tray_icon::{
    TrayIcon, TrayIconBuilder,
    menu::{Menu, MenuEvent, MenuItem},
};
use zip::ZipArchive;

const CONFIG_FILE_NAME: &str = "config.toml";
/// IMAP TCP 連線逾時
const IMAP_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// IMAP 讀寫逾時（避免伺服器停滯時 worker 永久卡死）
const IMAP_IO_TIMEOUT: Duration = Duration::from_secs(60);
/// 搬移確認對話框的最長等待時間；逾時視為全部跳過（不搬移）
const CONFIRM_TIMEOUT: Duration = Duration::from_secs(600);
/// 單一 .rels 檔案的解壓上限（Word 關聯檔極小，僅防壓縮炸彈）
const MAX_DOCX_RELS_BYTES: u64 = 8 * 1024 * 1024;
/// 每日日誌檔保留天數的預設值；可由 `[gui] log_retention_days` 覆寫
const LOG_RETENTION_DAYS: i64 = 30;
/// 啟動時回填到 UI 執行紀錄的今日日誌行數上限
const BACKFILL_LOG_LINES: usize = 200;

#[derive(Clone, Serialize, Deserialize)]
struct Config {
    imap: ImapConfig,
    detection: DetectionConfig,
    gui: GuiConfig,
    #[serde(default)]
    llm: LlmConfig,
}

#[derive(Clone, Serialize, Deserialize)]
struct ImapConfig {
    host: String,
    port: u16,
    protocol: String,
    username: String,
    password: String,
    source_mailbox: String,
    phishing_mailbox: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct DetectionConfig {
    threshold: u32,
    #[serde(default)]
    suspicious_sender_domains: Vec<String>,
    #[serde(default)]
    trusted_sender_domains: Vec<String>,
    #[serde(default = "default_keywords")]
    suspicious_keywords: Vec<String>,
    #[serde(default = "default_external_word_image_score")]
    external_word_image_score: u32,
}

#[derive(Clone, Serialize, Deserialize)]
struct GuiConfig {
    #[serde(default = "default_interval_minutes")]
    check_interval_minutes: u64,
    #[serde(default = "default_true")]
    minimize_to_tray: bool,
    /// 每輪掃描後、搬移前顯示確認對話框（預設 true）
    #[serde(default = "default_true")]
    confirm_before_move: bool,
    #[serde(default)]
    hide_taskbar_when_minimized: bool,
    #[serde(default)]
    start_minimized_to_tray: bool,
    #[serde(default = "default_font_family")]
    font_family: String,
    /// 每日日誌保留天數，超過即於啟動時刪除；0 表示永不清理（預設 30）
    #[serde(default = "default_log_retention_days")]
    log_retention_days: u32,
}

fn default_interval_minutes() -> u64 {
    10
}
fn default_true() -> bool {
    true
}
fn default_log_retention_days() -> u32 {
    LOG_RETENTION_DAYS as u32
}
fn default_external_word_image_score() -> u32 {
    5
}
fn default_font_family() -> String {
    "Noto Sans TC".into()
}
fn default_keywords() -> Vec<String> {
    [
        "verify", "urgent", "password", "login", "帳戶", "驗證", "緊急", "密碼", "掃描", "QR",
        "關稅",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

impl Default for Config {
    fn default() -> Self {
        Self {
            imap: ImapConfig {
                host: String::new(),
                port: 993,
                protocol: "imaps".into(),
                username: String::new(),
                password: String::new(),
                source_mailbox: "INBOX".into(),
                phishing_mailbox: "Phishing".into(),
            },
            detection: DetectionConfig {
                threshold: 5,
                suspicious_sender_domains: Vec::new(),
                trusted_sender_domains: Vec::new(),
                suspicious_keywords: default_keywords(),
                external_word_image_score: 5,
            },
            gui: GuiConfig {
                check_interval_minutes: 10,
                minimize_to_tray: true,
                confirm_before_move: true,
                hide_taskbar_when_minimized: true,
                start_minimized_to_tray: false,
                font_family: default_font_family(),
                log_retention_days: default_log_retention_days(),
            },
            llm: LlmConfig::default(),
        }
    }
}

fn load_app_icon() -> Result<(Vec<u8>, u32, u32)> {
    let bytes = include_bytes!("../AntiPhishing64.png");
    let img = image::load_from_memory(bytes)
        .context("無法解析 AntiPhishing64.png")?
        .to_rgba8();
    let (width, height) = img.dimensions();
    Ok((img.into_raw(), width, height))
}

/// 設定檔完整路徑：與執行檔同目錄（避免捷徑／排程器啟動時 CWD 不同而找不到設定）。
fn config_path() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(|dir| dir.join(CONFIG_FILE_NAME)))
        .unwrap_or_else(|| PathBuf::from(CONFIG_FILE_NAME))
}

// ===== 掃描進度檔（scan_state.toml）：跨重啟記住檢查斷點，避免重複檢查信件 =====

/// 掃描進度狀態檔內容，存於執行檔所在目錄 `scan_state.toml`。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct LastScanState {
    /// 來源信箱 UIDVALIDITY（信箱世代）；不符時 `filter_new_uids` 自動放棄此斷點
    uidvalidity: u32,
    /// 斷點：本世代已完整判定的最大 UID（LLM 判定失敗者不列入，下輪重試）
    max_checked_uid: u32,
    /// 最後完成判定郵件的 UID（參考資訊）
    last_mail_uid: u32,
    /// 最後完成判定郵件的主旨
    last_mail_subject: String,
    /// 該封所屬的搜尋日期
    last_mail_date: NaiveDate,
    /// 本狀態寫入時間（＝最後完成檢查時間，含無新郵件的空掃）
    checked_at: DateTime<Local>,
}

/// 進度檔完整路徑：與執行檔同目錄。
fn scan_state_path() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(|dir| dir.join("scan_state.toml")))
        .unwrap_or_else(|| PathBuf::from("scan_state.toml"))
}

/// 讀取掃描進度檔；檔案不存在＝Ok(None)，解析失敗＝Err（呼叫端轉為警告並全量重掃）。
fn load_scan_state() -> Result<Option<LastScanState>> {
    let text = match fs::read_to_string(scan_state_path()) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    toml::from_str(&text)
        .map(Some)
        .context("scan_state.toml 解析失敗")
}

/// 寫入掃描進度檔（整檔覆寫；內容極小，直接同步寫出）。
fn save_scan_state(state: &LastScanState) -> Result<()> {
    fs::write(scan_state_path(), toml::to_string_pretty(state)?)?;
    Ok(())
}

// ===== 每日日誌檔（logs/YYYY-MM-DD.log） =====

/// 執行紀錄單筆條目：附所屬日期供 UI 只保留最後一天。
struct LogEntry {
    date: NaiveDate,
    line: String,
}

/// 日誌目錄：執行檔所在目錄下的 logs/（.gitignore 已涵蓋 *.log 與 logs/）。
fn log_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(|dir| dir.join("logs")))
        .unwrap_or_else(|| PathBuf::from("logs"))
}

/// 每日日誌檔名：`YYYY-MM-DD.log`。
fn log_file_name(date: NaiveDate) -> String {
    format!("{date}.log")
}

/// 將訊息逐行附加寫入指定日的日誌檔，每行加 `[YYYY-MM-DD HH:MM:SS]` 前綴。
/// 追加模式：同一日多次寫入不覆蓋先前內容。
fn append_log_lines(dir: &Path, date: NaiveDate, messages: &[String]) -> Result<()> {
    fs::create_dir_all(dir)?;
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join(log_file_name(date)))?;
    let stamp = Local::now().format("[%Y-%m-%d %H:%M:%S]");
    for message in messages {
        writeln!(file, "{stamp} {message}")?;
    }
    Ok(())
}

/// 讀取指定日日誌檔的尾端行數（供啟動時回填 UI）；檔案不存在視為空。
fn load_day_log(dir: &Path, date: NaiveDate, max_lines: usize) -> Result<Vec<String>> {
    let text = match fs::read_to_string(dir.join(log_file_name(date))) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let lines: Vec<&str> = text
        .lines()
        .filter(|line| !line.trim().is_empty() && !line.contains("無新郵件"))
        .collect();
    let start = lines.len().saturating_sub(max_lines);
    Ok(lines[start..].iter().map(|line| line.to_string()).collect())
}

/// 刪除超過保留天數的舊日誌檔；僅處理「檔名可解析為日期」的 .log，其餘一律跳過。回傳刪除數。
fn cleanup_old_logs(dir: &Path, today: NaiveDate, retention_days: i64) -> usize {
    let cutoff = today - chrono::Duration::days(retention_days);
    let Ok(entries) = fs::read_dir(dir) else {
        return 0;
    };
    let mut removed = 0;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(stem) = name.strip_suffix(".log") else {
            continue;
        };
        let Ok(date) = NaiveDate::parse_from_str(stem, "%Y-%m-%d") else {
            continue;
        };
        if date < cutoff && fs::remove_file(entry.path()).is_ok() {
            removed += 1;
        }
    }
    removed
}

/// 移除非當日的條目，讓 UI 執行紀錄只保留最後一天（純函式便於測試）。
fn prune_logs(entries: &mut Vec<LogEntry>, today: NaiveDate) {
    entries.retain(|entry| entry.date == today);
}

/// 將設定的保留天數轉為清理參數：0 表示永不清理（回傳 None）。
fn cleanup_retention_days(retention_days: u32) -> Option<i64> {
    (retention_days > 0).then(|| i64::from(retention_days))
}

/// 已有另一個執行個體時顯示的提示視窗，數秒後自動關閉。
struct AlreadyRunningApp {
    deadline: Instant,
}

impl eframe::App for AlreadyRunningApp {
    fn logic(&mut self, ctx: &egui::Context, _: &mut eframe::Frame) {
        if Instant::now() >= self.deadline || ctx.input(|input| input.viewport().close_requested())
        {
            ctx.send_viewport_cmd(ViewportCommand::Close);
        } else {
            ctx.request_repaint_after(Duration::from_millis(250));
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _: &mut eframe::Frame) {
        ui.heading("AntiPhishing 已在執行中");
        ui.label("請從系統匣開啟現有的視窗；本提示視窗將自動關閉。");
    }
}

fn show_already_running_notice() -> eframe::Result {
    let mut viewport = egui::ViewportBuilder::default().with_inner_size([400.0, 150.0]);
    if let Ok((rgba, width, height)) = load_app_icon() {
        viewport = viewport.with_icon(egui::IconData {
            rgba,
            width,
            height,
        });
    }
    let options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };
    eframe::run_native(
        "AntiPhishing",
        options,
        Box::new(|cc| {
            // 提示視窗也必須載入中文字型，否則 egui 內建字型缺 CJK 字符會顯示方框
            let font_family = load_config()
                .map(|config| config.gui.font_family)
                .unwrap_or_default();
            apply_configured_font(&cc.egui_ctx, &font_family);
            Ok(Box::new(AlreadyRunningApp {
                deadline: Instant::now() + Duration::from_secs(5),
            }))
        }),
    )
}

fn main() -> eframe::Result {
    let (single_instance, instance_warning) =
        match SingleInstance::new("anti-phishing-gui-instance-lock") {
            Ok(instance) => (Some(instance), None),
            Err(error) => (
                None,
                Some(format!("單一實例鎖建立失敗（可能重複啟動）：{error}")),
            ),
        };
    if let Some(ref instance) = single_instance
        && !instance.is_single()
    {
        return show_already_running_notice();
    }

    let (config, load_status) = match load_config() {
        Ok(config) => (config, "已載入設定檔。".to_string()),
        Err(error) => (Config::default(), format!("使用預設設定：{error}")),
    };
    let mut status = load_status;
    if let Some(warning) = instance_warning {
        status.push_str(&format!(" {warning}"));
    }
    let mut viewport = egui::ViewportBuilder::default()
        .with_inner_size([760.0, 720.0])
        .with_min_inner_size([620.0, 500.0]);
    if config.gui.start_minimized_to_tray {
        viewport = viewport.with_visible(false);
    }
    if let Ok((rgba, width, height)) = load_app_icon() {
        viewport = viewport.with_icon(egui::IconData {
            rgba,
            width,
            height,
        });
    }
    let options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };
    eframe::run_native(
        "AntiPhishing",
        options,
        Box::new(move |cc| Ok(Box::new(App::new(cc, config, status)))),
    )
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PendingMoveMail {
    uid: u32,
    subject: String,
    score: u32,
    reason: String,
}

#[derive(Clone, Debug)]
struct MoveCandidateItem {
    uid: u32,
    subject: String,
    score: u32,
    reason: String,
    selected: bool,
}

struct PendingMoveDialog {
    candidates: Vec<MoveCandidateItem>,
    reply: Sender<Vec<u32>>,
}

/// 掃描工作執行緒送往 UI 的事件：
/// `Progress`＝目前檢查進度（顯示於狀態列下方，完成即消失）；
/// `Done`＝整輪掃描結束（含失敗與異常中止），攜帶掃描結果。
enum ScanEvent {
    Progress(String),
    Done(ScanOutcome),
}

/// 單輪掃描結果：日誌行與檢查進度（最後檢查到的 UID），供 UI 更新最後檢查狀態。
struct ScanOutcome {
    lines: Vec<String>,
    /// 掃描當下來源信箱的 UIDVALIDITY（信箱世代）
    uidvalidity: u32,
    /// 本輪實際檢查過的最大 UID（含判定略過者）；未檢查任何郵件時為 None
    max_checked_uid: Option<u32>,
    /// 本輪最後完成判定的郵件（所屬搜尋日期、UID、主旨）；空掃或未判定任何信為 None
    last_checked: Option<(NaiveDate, u32, String)>,
    /// 全部日期皆無新郵件（皆已於前輪檢查過）；不寫入執行紀錄，僅更新最後檢查時間
    no_new_mail: bool,
}

struct App {
    config: Config,
    status: String,
    /// 掃描進行中的即時進度（目前檢查哪封信）；空字串表示無掃描進行
    scan_progress: String,
    /// 執行紀錄（僅保留當日條目；完整歷史見每日日誌檔）
    logs: Vec<LogEntry>,
    /// 日誌檔寫入失敗時只提示一次的旗標
    log_error_reported: bool,
    date_text: String,
    next_check: Instant,
    receiver: Option<Receiver<ScanEvent>>,
    /// 搬移確認：worker 送出的待搬移清單（uid、主旨、評分、理由）
    ask_receiver: Option<Receiver<Vec<PendingMoveMail>>>,
    /// 搬移確認：回覆 worker 決定搬移的 uid 清單
    reply_sender: Option<Sender<Vec<u32>>>,
    /// 目前顯示中的待確認對話框狀態
    pending_move: Option<PendingMoveDialog>,
    tray: Option<Tray>,
    allow_exit: bool,
    startup_scan_pending: bool,
    hide_window_on_startup: bool,
    /// 從 IMAP 伺服器取得的信箱清單（原始 UTF-7 名稱）
    mailboxes: Vec<String>,
    /// 背景取得信箱清單的 receiver
    mailbox_receiver: Option<Receiver<Result<Vec<String>>>>,
    /// 上次檢查到的最後一封郵件（UIDVALIDITY、最大 UID）；排程掃描藉此跳過無新郵件的一輪
    last_seen: Option<(u32, u32)>,
    /// 上次完成掃描的時間（含無新郵件的空掃），顯示於狀態列下方；跨重啟由進度檔回復
    last_check: Option<DateTime<Local>>,
    /// 最後完成判定的郵件（UID、主旨、所屬搜尋日期），顯示於狀態列下方
    last_mail: Option<(u32, String, NaiveDate)>,
}

struct Tray {
    _icon: TrayIcon,
    show: MenuItem,
    scan: MenuItem,
    quit: MenuItem,
}

impl App {
    fn new(cc: &eframe::CreationContext<'_>, config: Config, status: String) -> Self {
        let font_status = apply_configured_font(&cc.egui_ctx, &config.gui.font_family);
        let tray = create_tray().ok();
        let hide_window_on_startup = config.gui.start_minimized_to_tray && tray.is_some();
        if config.gui.start_minimized_to_tray && !hide_window_on_startup {
            cc.egui_ctx
                .send_viewport_cmd(ViewportCommand::Visible(true));
        }
        // 跨重啟回復掃描斷點：失敗僅警告，安全側行為＝全量重掃近兩日
        let (scan_state, state_warning) = match load_scan_state() {
            Ok(Some(state)) => (Some(state), String::new()),
            Ok(None) => (None, String::new()),
            Err(error) => (
                None,
                format!(" 掃描進度檔載入失敗，將重新檢查近兩日郵件：{error:#}"),
            ),
        };
        // 清理過期日誌並回填今日日誌尾端到執行紀錄顯示（保留天數可設定，0＝永不清理）
        let today = Local::now().date_naive();
        let removed = cleanup_retention_days(config.gui.log_retention_days)
            .map(|days| cleanup_old_logs(&log_dir(), today, days))
            .unwrap_or(0);
        let (backfill, log_warning) = match load_day_log(&log_dir(), today, BACKFILL_LOG_LINES) {
            Ok(lines) => (lines, String::new()),
            Err(error) => (Vec::new(), format!(" 今日日誌讀取失敗：{error:#}")),
        };
        let mut status = format!("{status} {font_status}");
        if !state_warning.is_empty() || !log_warning.is_empty() {
            status.push_str(&state_warning);
            status.push_str(&log_warning);
        }
        if removed > 0 {
            status.push_str(&format!(" 已清理 {removed} 個過期日誌檔。"));
        }
        let logs = backfill
            .into_iter()
            .map(|line| LogEntry { date: today, line })
            .collect();
        let last_seen = scan_state
            .as_ref()
            .map(|state| (state.uidvalidity, state.max_checked_uid));
        Self {
            next_check: Instant::now() + interval(&config),
            config,
            status,
            scan_progress: String::new(),
            logs,
            log_error_reported: false,
            date_text: Local::now().date_naive().to_string(),
            receiver: None,
            ask_receiver: None,
            reply_sender: None,
            pending_move: None,
            tray,
            allow_exit: false,
            startup_scan_pending: true,
            hide_window_on_startup,
            mailboxes: Vec::new(),
            mailbox_receiver: None,
            last_seen,
            last_check: scan_state.as_ref().map(|state| state.checked_at),
            last_mail: scan_state.map(|state| {
                (
                    state.last_mail_uid,
                    state.last_mail_subject,
                    state.last_mail_date,
                )
            }),
        }
    }

    fn fetch_mailboxes(&mut self) {
        if self.mailbox_receiver.is_some() {
            return;
        }
        if let Some(problem) = imap_credentials_problem(&self.config.imap) {
            self.status = problem;
            return;
        }
        let config = self.config.imap.clone();
        let (tx, rx) = mpsc::channel();
        self.mailbox_receiver = Some(rx);
        self.status = "連線取得信箱清單中…".into();
        thread::spawn(move || {
            let res = fetch_mailbox_list(&config);
            let _ = tx.send(res);
        });
    }

    fn save(&mut self) {
        let result: Result<()> = (|| {
            let text = toml::to_string_pretty(&self.config)?;
            fs::write(config_path(), text)?;
            Ok(())
        })();
        match result {
            Ok(()) => self.status = "設定已儲存。".into(),
            Err(error) => self.status = format!("儲存失敗：{error}"),
        }
    }

    /// 統一日誌入口：附加寫入當日日誌檔並加入 UI 執行紀錄（僅保留當日條目）。
    fn push_log(&mut self, message: String) {
        let now = Local::now();
        let date = now.date_naive();
        let line = format!("[{}] {}", now.format("%Y-%m-%d %H:%M:%S"), message);
        if let Err(error) = append_log_lines(&log_dir(), date, std::slice::from_ref(&message)) {
            // 磁碟異常不得影響掃描與 UI：僅在狀態列提示一次
            if !self.log_error_reported {
                self.log_error_reported = true;
                self.status = format!("日誌檔寫入失敗（不再重複提示）：{error:#}");
            }
        }
        prune_logs(&mut self.logs, date);
        self.logs.push(LogEntry { date, line });
    }

    /// 掃描結束後將最新進度寫回掃描進度檔（斷點＋最後一封郵件資訊）；失敗僅提示不中斷。
    fn persist_scan_state(&mut self) {
        let (Some(last_seen), Some(last_check)) = (self.last_seen, self.last_check) else {
            return;
        };
        let Some((uid, subject, mail_date)) = &self.last_mail else {
            return;
        };
        let state = LastScanState {
            uidvalidity: last_seen.0,
            max_checked_uid: last_seen.1,
            last_mail_uid: *uid,
            last_mail_subject: subject.clone(),
            last_mail_date: *mail_date,
            checked_at: last_check,
        };
        if let Err(error) = save_scan_state(&state)
            && !self.log_error_reported
        {
            self.log_error_reported = true;
            self.status = format!("掃描進度檔寫入失敗（不再重複提示）：{error:#}");
        }
    }

    fn start_scan(&mut self, scheduled: bool) {
        let date = match NaiveDate::parse_from_str(&self.date_text, "%Y-%m-%d") {
            Ok(value) => value,
            Err(_) => {
                self.status = "日期格式須為 YYYY-MM-DD。".into();
                return;
            }
        };
        // 手動指定日期掃描時不帶 last_seen（執行全量檢查不套用 UID 過濾），排程掃描才帶 last_seen
        let last_seen = if scheduled { self.last_seen } else { None };
        self.start_scan_dates(vec![date], last_seen, scheduled);
    }

    fn start_scan_dates(
        &mut self,
        dates: Vec<NaiveDate>,
        last_seen: Option<(u32, u32)>,
        scheduled: bool,
    ) {
        if self.receiver.is_some() {
            self.status = "已有掃描進行中，請稍候。".into();
            return;
        }
        if dates.is_empty() {
            return;
        }
        // 掃描前先驗證設定，避免啟動時帶著空設定連線失敗卻無明確提示
        if let Some(problem) = imap_credentials_problem(&self.config.imap) {
            self.status = problem;
            return;
        }
        if let Some(problem) = imap_mailbox_problem(&self.config.imap) {
            self.status = problem;
            return;
        }
        let config = self.config.clone();
        let (sender, receiver) = mpsc::channel::<ScanEvent>();
        self.receiver = Some(receiver);
        // 搬移確認通道：worker 於掃描結束前送出待搬移清單並阻塞等待決定
        let (ask, ask_receiver) = mpsc::channel::<Vec<PendingMoveMail>>();
        let (reply_sender, reply_receiver) = mpsc::channel::<Vec<u32>>();
        self.ask_receiver = Some(ask_receiver);
        self.reply_sender = Some(reply_sender);
        self.scan_progress.clear();
        self.status = if dates.len() > 1 {
            "啟動掃描前一日與今日郵件中…".into()
        } else if scheduled {
            "排程掃描中…".into()
        } else {
            "手動全量掃描中…".into()
        };
        thread::spawn(move || {
            // catch_unwind：worker panic 時仍回傳結果，避免 UI 端 receiver 永久卡住
            let outcome = match catch_unwind(AssertUnwindSafe(|| {
                scan_mail(&config, &dates, last_seen, &ask, &reply_receiver, &sender)
            })) {
                Ok(Ok(outcome)) => outcome,
                Ok(Err(error)) => ScanOutcome {
                    lines: vec![format!("掃描失敗：{error:#}")],
                    uidvalidity: 0,
                    max_checked_uid: None,
                    last_checked: None,
                    no_new_mail: false,
                },
                Err(panic) => {
                    let detail = panic
                        .downcast_ref::<&str>()
                        .map(|s| (*s).to_string())
                        .or_else(|| panic.downcast_ref::<String>().cloned())
                        .unwrap_or_else(|| "未知原因".into());
                    ScanOutcome {
                        lines: vec![format!("掃描執行緒異常中止：{detail}")],
                        uidvalidity: 0,
                        max_checked_uid: None,
                        last_checked: None,
                        no_new_mail: false,
                    }
                }
            };
            let _ = sender.send(ScanEvent::Done(outcome));
        });
    }

    fn poll(&mut self, ctx: &egui::Context) {
        if self.hide_window_on_startup {
            self.hide_window_on_startup = false;
            ctx.send_viewport_cmd(ViewportCommand::Visible(false));
        }
        // 掃描事件排水：Progress 更新進度行；Done＝整輪結束。
        // Disconnected＝worker 結束但未送結果（理論上已被 catch_unwind 攔住）
        let mut done: Option<ScanOutcome> = None;
        let mut worker_lost = false;
        if let Some(receiver) = &self.receiver {
            loop {
                match receiver.try_recv() {
                    Ok(ScanEvent::Progress(text)) => self.scan_progress = text,
                    Ok(ScanEvent::Done(outcome)) => {
                        done = Some(outcome);
                        break;
                    }
                    Err(TryRecvError::Disconnected) => {
                        worker_lost = true;
                        break;
                    }
                    Err(TryRecvError::Empty) => break,
                }
            }
        }
        if worker_lost || done.is_some() {
            if worker_lost {
                self.status = "掃描執行緒異常結束，未回傳任何結果。".into();
                self.push_log("掃描執行緒異常結束，未回傳任何結果。".into());
                send_notification(
                    "AntiPhishing 掃描失敗",
                    "掃描執行緒異常結束，未回傳任何結果。",
                );
            } else if let Some(outcome) = done {
                self.last_check = Some(Local::now());
                if outcome.no_new_mail {
                    // 無新郵件的排程空掃：只更新最後檢查時間，不寫入執行紀錄、日誌檔與進度檔
                    self.status =
                        format!("最後檢查 {}：無新郵件。", Local::now().format("%H:%M:%S"));
                } else {
                    for line in &outcome.lines {
                        self.push_log(line.clone());
                    }
                    self.status = outcome.lines.last().cloned().unwrap_or_default();
                    // 記住本輪檢查進度：若在相同信箱世代下，取原有進度與本輪最大進度之較大者，
                    // 避免手動掃描過去歷史日期時將全域進度降級
                    if let Some(max_uid) = outcome.max_checked_uid {
                        self.last_seen = Some(match self.last_seen {
                            Some((validity, seen_max)) if validity == outcome.uidvalidity => {
                                (validity, seen_max.max(max_uid))
                            }
                            _ => (outcome.uidvalidity, max_uid),
                        });
                    }
                    if let Some((mail_date, uid, subject)) = &outcome.last_checked {
                        self.last_mail = Some((*uid, subject.clone(), *mail_date));
                    }
                    // 本輪有新檢查進度時才寫回進度檔，重啟後即可從斷點續掃
                    self.persist_scan_state();
                }
                // 失敗時以系統匣通知提醒（視窗可能縮在系統匣看不到）
                if let Some(first_failure) = outcome
                    .lines
                    .iter()
                    .find(|line| line.starts_with("掃描失敗") || line.starts_with("掃描執行緒異常"))
                {
                    send_notification("AntiPhishing 掃描失敗", first_failure);
                }
            }
            self.receiver = None;
            self.ask_receiver = None;
            self.reply_sender = None;
            self.pending_move = None;
            self.scan_progress.clear();
            self.next_check = Instant::now() + interval(&self.config);
        }
        // worker 請求確認搬移：先暫存，視窗顯示時由 Dialog 呈現（eframe 不允許在 logic 繪製 UI）
        if let Some(ask) = &self.ask_receiver {
            match ask.try_recv() {
                Ok(list) => {
                    let detected = list.len();
                    if let Some(reply) = self.reply_sender.clone() {
                        self.status = format!(
                            "掃描完成：{detected} 封疑似釣魚／惡意廣告郵件，請確認是否隔離"
                        );
                        send_notification(
                            "AntiPhishing 偵測警告",
                            &format!(
                                "偵測到 {detected} 封疑似釣魚／惡意廣告郵件，請確認是否隔離。"
                            ),
                        );
                        let candidates = list
                            .into_iter()
                            .map(|m| MoveCandidateItem {
                                uid: m.uid,
                                subject: m.subject,
                                score: m.score,
                                reason: m.reason,
                                selected: true,
                            })
                            .collect();
                        self.pending_move = Some(PendingMoveDialog { candidates, reply });
                        // 偵測到疑似釣魚／惡意廣告郵件需確認時：解除系統匣縮小/隱藏狀態，顯示視窗並置中螢幕
                        ctx.send_viewport_cmd(ViewportCommand::Visible(true));
                        ctx.send_viewport_cmd(ViewportCommand::Minimized(false));
                        ctx.send_viewport_cmd(ViewportCommand::Focus);
                        ctx.send_viewport_cmd(ViewportCommand::RequestUserAttention(
                            egui::UserAttentionType::Critical,
                        ));
                        if let Some(cmd) = ViewportCommand::center_on_screen(ctx) {
                            ctx.send_viewport_cmd(cmd);
                        }
                    }
                }
                Err(TryRecvError::Disconnected) => {
                    // worker 在等待確認前異常結束：清空確認狀態，等 receiver 分支收尾
                    self.ask_receiver = None;
                    self.reply_sender = None;
                    self.pending_move = None;
                }
                Err(TryRecvError::Empty) => {}
            }
        }
        // 處理信箱清單接收
        if let Some(receiver) = &self.mailbox_receiver {
            match receiver.try_recv() {
                Ok(Ok(mailboxes)) => {
                    let count = mailboxes.len();
                    self.mailboxes = mailboxes;
                    self.status = format!("已成功取得 {count} 個信箱。");
                    self.mailbox_receiver = None;
                }
                Ok(Err(err)) => {
                    self.status = format!("取得信箱清單失敗：{err:#}");
                    self.mailbox_receiver = None;
                }
                Err(TryRecvError::Disconnected) => {
                    self.status = "取得信箱清單失敗：背景執行緒異常結束。".into();
                    self.mailbox_receiver = None;
                }
                Err(TryRecvError::Empty) => {}
            }
        }
        if self.receiver.is_none() && self.startup_scan_pending {
            self.startup_scan_pending = false;
            let today = Local::now().date_naive();
            self.date_text = today.to_string();
            self.start_scan_dates(startup_scan_dates(today).to_vec(), self.last_seen, false);
        } else if self.receiver.is_none() && Instant::now() >= self.next_check {
            let today = Local::now().date_naive();
            self.date_text = today.to_string();
            // 排程定時掃描自動涵蓋前一日與今日（應對 UTC 時區落差），並傳入 last_seen 斷點續掃
            self.start_scan_dates(startup_scan_dates(today).to_vec(), self.last_seen, true);
        }
        if let Some(tray) = &self.tray {
            let show_id = tray.show.id().clone();
            let scan_id = tray.scan.id().clone();
            let quit_id = tray.quit.id().clone();
            while let Ok(event) = MenuEvent::receiver().try_recv() {
                if event.id == show_id {
                    ctx.send_viewport_cmd(ViewportCommand::Visible(true));
                    ctx.send_viewport_cmd(ViewportCommand::Minimized(false));
                    ctx.send_viewport_cmd(ViewportCommand::Focus);
                    if let Some(cmd) = ViewportCommand::center_on_screen(ctx) {
                        ctx.send_viewport_cmd(cmd);
                    }
                }
                if event.id == scan_id {
                    let today = Local::now().date_naive();
                    self.date_text = today.to_string();
                    self.start_scan_dates(
                        startup_scan_dates(today).to_vec(),
                        self.last_seen,
                        false,
                    );
                }
                if event.id == quit_id {
                    self.allow_exit = true;
                    ctx.send_viewport_cmd(ViewportCommand::Close);
                }
            }
        }
        // 掃描中提高重繪頻率，讓進度行即時更新；閒置維持每秒一次
        ctx.request_repaint_after(if self.receiver.is_some() {
            Duration::from_millis(300)
        } else {
            Duration::from_secs(1)
        });
    }

    /// 搬移確認對話框；回傳 true 表示使用者已做出決定（隔離選取項／全部跳過）。
    fn show_move_confirmation(ctx: &egui::Context, dialog: &mut PendingMoveDialog) -> bool {
        let mut decided = false;

        // 繪製半透明全螢幕暗色背景遮罩，突顯對話框
        let painter = ctx.layer_painter(egui::LayerId::new(
            egui::Order::Middle,
            egui::Id::new("modal_backdrop"),
        ));
        let screen_rect = ctx
            .input(|i| i.viewport().inner_rect)
            .unwrap_or(egui::Rect::EVERYTHING);
        painter.rect_filled(screen_rect, 0.0, egui::Color32::from_black_alpha(170));

        let frame = egui::Frame::default()
            .fill(egui::Color32::from_rgb(32, 34, 38))
            .inner_margin(egui::Margin::same(20))
            .corner_radius(8)
            .stroke(egui::Stroke::new(2.0, egui::Color32::from_rgb(230, 80, 80)))
            .shadow(egui::Shadow {
                offset: [0, 8],
                blur: 16,
                spread: 0,
                color: egui::Color32::from_black_alpha(180),
            });

        egui::Window::new("隔離確認")
            .title_bar(false) // 無標題列＝無關閉鈕，只能以按鈕決定
            .collapsible(false)
            .resizable(false)
            .frame(frame)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .default_size([650.0, 460.0])
            .order(egui::Order::Foreground)
            .show(ctx, |ui| {
                ui.spacing_mut().item_spacing = egui::vec2(8.0, 10.0);

                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new("⚠️ 偵測到疑似釣魚／惡意廣告郵件！")
                            .size(22.0)
                            .strong()
                            .color(egui::Color32::from_rgb(240, 80, 80)),
                    );
                });

                ui.label(
                    egui::RichText::new(format!(
                        "本次掃描共發現 {} 封疑似釣魚／惡意廣告郵件，請勾選要隔離（搬移至指定信箱）的項目，未勾選的郵件將保留：",
                        dialog.candidates.len()
                    ))
                    .size(15.0)
                    .strong(),
                );

                // 批次勾選快捷按鈕列
                ui.horizontal(|ui| {
                    if ui.button("全選").clicked() {
                        for item in &mut dialog.candidates {
                            item.selected = true;
                        }
                    }
                    if ui.button("全不選").clicked() {
                        for item in &mut dialog.candidates {
                            item.selected = false;
                        }
                    }
                    if ui.button("反選").clicked() {
                        for item in &mut dialog.candidates {
                            item.selected = !item.selected;
                        }
                    }
                    let selected_count = dialog.candidates.iter().filter(|i| i.selected).count();
                    ui.label(
                        egui::RichText::new(format!(
                            "（已選取 {} / {} 封）",
                            selected_count,
                            dialog.candidates.len()
                        ))
                        .color(egui::Color32::LIGHT_GRAY),
                    );
                });

                ui.separator();

                egui::ScrollArea::vertical()
                    .max_height(250.0)
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        for (idx, item) in dialog.candidates.iter_mut().enumerate() {
                            let item_frame = egui::Frame::group(ui.style())
                                .inner_margin(egui::Margin::symmetric(12, 8))
                                .stroke(egui::Stroke::new(
                                    1.0,
                                    if item.selected {
                                        egui::Color32::from_rgb(230, 80, 80)
                                    } else {
                                        egui::Color32::from_white_alpha(30)
                                    },
                                ));

                            item_frame.show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    ui.checkbox(&mut item.selected, "");
                                    ui.vertical(|ui| {
                                        ui.label(
                                            egui::RichText::new(format!(
                                                "{}. 主旨：{}（評分：{}）",
                                                idx + 1,
                                                item.subject,
                                                item.score
                                            ))
                                            .size(15.0)
                                            .strong(),
                                        );
                                        ui.label(
                                            egui::RichText::new(format!("   理由：{}", item.reason))
                                                .size(14.0)
                                                .color(egui::Color32::from_rgb(230, 170, 70)),
                                        );
                                    });
                                });
                            });
                            ui.add_space(4.0);
                        }
                    });

                ui.separator();

                ui.horizontal(|ui| {
                    let selected_count = dialog.candidates.iter().filter(|i| i.selected).count();
                    let move_btn = egui::Button::new(
                        egui::RichText::new(format!("  🚨 隔離選取郵件 ({} 封)  ", selected_count))
                            .size(16.0)
                            .strong()
                            .color(egui::Color32::WHITE),
                    )
                    .fill(if selected_count > 0 {
                        egui::Color32::from_rgb(180, 40, 40)
                    } else {
                        egui::Color32::from_rgb(100, 100, 100)
                    })
                    .min_size(egui::vec2(220.0, 38.0));

                    if ui.add_enabled(selected_count > 0, move_btn).clicked() {
                        let selected_uids: Vec<u32> = dialog
                            .candidates
                            .iter()
                            .filter(|i| i.selected)
                            .map(|i| i.uid)
                            .collect();
                        let _ = dialog.reply.send(selected_uids);
                        decided = true;
                    }

                    ui.add_space(12.0);

                    let skip_btn =
                        egui::Button::new(egui::RichText::new("  全部跳過（不隔離）  ").size(15.0))
                            .min_size(egui::vec2(160.0, 38.0));

                    if ui.add(skip_btn).clicked() {
                        let _ = dialog.reply.send(Vec::new());
                        decided = true;
                    }
                });
            });
        decided
    }
}

impl eframe::App for App {
    fn logic(&mut self, ctx: &egui::Context, _: &mut eframe::Frame) {
        self.poll(ctx);
        if !self.allow_exit
            && ctx.input(|input| input.viewport().close_requested())
            && self.config.gui.minimize_to_tray
            && self.tray.is_some()
        {
            ctx.send_viewport_cmd(ViewportCommand::CancelClose);
            if self.config.gui.hide_taskbar_when_minimized {
                ctx.send_viewport_cmd(ViewportCommand::Visible(false));
            } else {
                ctx.send_viewport_cmd(ViewportCommand::Minimized(true));
            }
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _: &mut eframe::Frame) {
        // 上方最多 2/3：設定區（可捲動，恆顯示垂直捲軸）
        let settings_max = ui.available_height() * 2.0 / 3.0;
        egui::ScrollArea::vertical()
            .id_salt("settings_scroll_area")
            .auto_shrink([false, false])
            .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysVisible)
            .max_height(settings_max)
            .show(ui, |ui| {
                ui.heading("AntiPhishing 郵件防護");
                ui.label(&self.status);
                // 上次完成掃描的時間（含無新郵件的空掃）；空掃不寫執行紀錄，只更新此處
                if let Some(last_check) = self.last_check {
                    ui.small(format!(
                        "最後檢查時間：{}",
                        last_check.format("%Y-%m-%d %H:%M:%S")
                    ));
                }
                // 跨重啟由進度檔回復的最後判定郵件資訊
                if let Some((uid, subject, mail_date)) = &self.last_mail {
                    ui.small(format!("上次檢查至 UID {uid}〈{subject}〉（{mail_date}）"));
                }
                // 掃描進行中顯示即時進度（目前檢查哪封信）；完成後自動消失
                if !self.scan_progress.is_empty() {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(egui::RichText::new(&self.scan_progress).small().strong());
                    });
                }
                ui.separator();
                ui.heading("IMAP 信箱");
                egui::Grid::new("imap").num_columns(2).show(ui, |ui| {
                    field(ui, "伺服器", &mut self.config.imap.host);
                    ui.label("連接埠");
                    ui.add(egui::DragValue::new(&mut self.config.imap.port).range(1..=65535));
                    ui.end_row();
                    ui.label("協定");
                    ui.horizontal(|ui| {
                        ui.radio_value(&mut self.config.imap.protocol, "imaps".into(), "IMAPS");
                        ui.radio_value(&mut self.config.imap.protocol, "starttls".into(), "STARTTLS");
                    });
                    ui.end_row();
                    field(ui, "帳號", &mut self.config.imap.username);
                    ui.end_row();
                    ui.label("密碼 / App Password");
                    ui.add(egui::TextEdit::singleline(&mut self.config.imap.password).password(true));
                    ui.end_row();
                    ui.label("信箱清單");
                    ui.horizontal(|ui| {
                        let is_fetching = self.mailbox_receiver.is_some();
                        let btn_text = if is_fetching {
                            "取得中…"
                        } else {
                            "從伺服器取得信箱清單"
                        };
                        if ui.add_enabled(!is_fetching, egui::Button::new(btn_text)).clicked() {
                            self.fetch_mailboxes();
                        }
                        if !self.mailboxes.is_empty() {
                            ui.label(format!("（已載入 {} 個信箱）", self.mailboxes.len()));
                        }
                    });
                    ui.end_row();
                    mailbox_field(
                        ui,
                        "來源信箱",
                        "source_mailbox_combo",
                        &mut self.config.imap.source_mailbox,
                        &self.mailboxes,
                    );
                    ui.end_row();
                    mailbox_field(
                        ui,
                        "釣魚信箱",
                        "phishing_mailbox_combo",
                        &mut self.config.imap.phishing_mailbox,
                        &self.mailboxes,
                    );
                    ui.end_row();
                });
                ui.separator();
                ui.heading("LLM 判定（地端或雲端模型）");
                egui::Grid::new("llm_grid").num_columns(2).show(ui, |ui| {
                    field(ui, "伺服器網址", &mut self.config.llm.base_url);
                    ui.end_row();
                    field(ui, "模型名稱", &mut self.config.llm.model);
                    ui.end_row();
                    ui.label("API 金鑰");
                    ui.add(egui::TextEdit::singleline(&mut self.config.llm.api_key).password(true));
                    ui.end_row();
                    ui.label("逾時（秒）");
                    ui.add(egui::DragValue::new(&mut self.config.llm.timeout_secs).range(10..=600));
                    ui.end_row();
                    ui.label("內文最大字數");
                    ui.add(egui::DragValue::new(&mut self.config.llm.max_chars).range(500..=50000));
                    ui.end_row();
                });
                ui.small("留空伺服器網址或模型名稱即停用 LLM 判定；地端免認證模型（如 Ollama / LM Studio）API 金鑰可留空。");
                ui.separator();
                ui.heading("偵測規則");
                ui.horizontal(|ui| {
                    ui.label("判定門檻");
                    ui.add(egui::DragValue::new(&mut self.config.detection.threshold).range(1..=100));
                    ui.label("Word 外部圖片分數");
                    ui.add(egui::DragValue::new(&mut self.config.detection.external_word_image_score).range(0..=100));
                });
                multiline(ui, "可疑寄件網域（每行一個）", &mut self.config.detection.suspicious_sender_domains);
                multiline(ui, "信任寄件網域（每行一個）", &mut self.config.detection.trusted_sender_domains);
                multiline(ui, "可疑關鍵字（每行一個）", &mut self.config.detection.suspicious_keywords);
                ui.separator();
                ui.heading("排程與系統匣");
                ui.horizontal(|ui| {
                    ui.label("每隔（分鐘）");
                    ui.add(egui::DragValue::new(&mut self.config.gui.check_interval_minutes).range(1..=1440));
                    ui.label(format!(
                        "下次檢查：{} 秒後",
                        self.next_check.saturating_duration_since(Instant::now()).as_secs()
                    ));
                });
                ui.checkbox(&mut self.config.gui.minimize_to_tray, "關閉視窗時縮小至 Windows 系統匣");
                ui.checkbox(&mut self.config.gui.hide_taskbar_when_minimized, "縮小至系統匣時隱藏工作列項目");
                ui.checkbox(&mut self.config.gui.start_minimized_to_tray, "啟動時直接縮小至 Windows 系統匣（下次啟動生效）");
                ui.checkbox(&mut self.config.gui.confirm_before_move, "搬移前先確認（可個別選取要隔離的郵件）");
                ui.horizontal(|ui| {
                    ui.label("中文字型（重啟後套用）");
                    ui.text_edit_singleline(&mut self.config.gui.font_family);
                });
                ui.small("系統匣選單提供顯示視窗、立即掃描與結束程式。密碼會以明文儲存在 config.toml，請使用 App Password 並保護該檔案。");
                ui.separator();
                ui.horizontal(|ui| {
                    if ui.button("儲存設定").clicked() {
                        self.save();
                    }
                    // 掃描進行中停用按鈕，避免按下被靜默忽略
                    let scan_busy = self.receiver.is_some();
                    let scan_button = egui::Button::new("立即掃描指定日期");
                    if ui
                        .add_enabled(!scan_busy, scan_button)
                        .clicked()
                    {
                        self.start_scan(false);
                    } else if scan_busy {
                        ui.small("掃描進行中…");
                    }
                    ui.label("日期");
                    ui.text_edit_singleline(&mut self.date_text);
                });
            });
        // 下方 1/3：執行紀錄（恆顯示，最新優先）
        ui.separator();
        ui.heading("執行紀錄");
        egui::ScrollArea::vertical()
            .id_salt("logs_scroll_area")
            .auto_shrink([false, false])
            .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysVisible)
            .max_height(ui.available_height())
            .show(ui, |ui| {
                if self.logs.is_empty() {
                    ui.small("尚無執行紀錄");
                } else {
                    for entry in self.logs.iter().rev().take(20) {
                        ui.label(&entry.line);
                    }
                }
            });
        // 搬移確認對話框：使用者決定後清空，未決定則保留等下次繪製
        if let Some(mut dialog) = self.pending_move.take()
            && !Self::show_move_confirmation(ui.ctx(), &mut dialog)
        {
            self.pending_move = Some(dialog);
        }
    }
}

fn field(ui: &mut egui::Ui, name: &str, value: &mut String) {
    ui.label(name);
    ui.text_edit_singleline(value);
}

fn mailbox_field(
    ui: &mut egui::Ui,
    label: &str,
    combo_id: &str,
    selected: &mut String,
    mailboxes: &[String],
) {
    ui.label(label);
    ui.horizontal(|ui| {
        if !mailboxes.is_empty() {
            let current_display = if selected.is_empty() {
                "（請選擇）".to_string()
            } else {
                let decoded = decode_imap_utf7(selected);
                if decoded == *selected {
                    selected.clone()
                } else {
                    format!("{decoded} ({selected})")
                }
            };
            egui::ComboBox::from_id_salt(combo_id)
                .selected_text(current_display)
                .show_ui(ui, |ui| {
                    for mb in mailboxes {
                        let decoded = decode_imap_utf7(mb);
                        let text = if decoded == *mb {
                            mb.clone()
                        } else {
                            format!("{decoded} ({mb})")
                        };
                        ui.selectable_value(selected, mb.clone(), text);
                    }
                });
        }
        ui.text_edit_singleline(selected);
    });
}
fn multiline(ui: &mut egui::Ui, label: &str, items: &mut Vec<String>) {
    ui.label(label);
    let mut text = items.join("\n");
    if ui
        .add(egui::TextEdit::multiline(&mut text).desired_rows(2))
        .changed()
    {
        *items = text
            .lines()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();
    }
}
fn interval(config: &Config) -> Duration {
    Duration::from_secs(config.gui.check_interval_minutes.max(1) * 60)
}

/// IMAP 帳號相關設定檢查；回傳錯誤訊息表示設定不完整。
fn imap_credentials_problem(config: &ImapConfig) -> Option<String> {
    if config.host.trim().is_empty() {
        Some("請先填寫 IMAP 伺服器。".into())
    } else if config.username.trim().is_empty() {
        Some("請先填寫 IMAP 帳號。".into())
    } else if config.password.trim().is_empty() {
        Some("請先填寫 IMAP 密碼。".into())
    } else {
        None
    }
}

/// 信箱名稱設定檢查；回傳錯誤訊息表示設定不完整。
fn imap_mailbox_problem(config: &ImapConfig) -> Option<String> {
    if config.source_mailbox.trim().is_empty() {
        Some("請先設定來源信箱。".into())
    } else if config.phishing_mailbox.trim().is_empty() {
        Some("請先設定釣魚信箱（隔離目標）。".into())
    } else {
        None
    }
}

/// 送出系統匣通知（背景執行緒，避免阻塞 UI）。
fn send_notification(summary: &str, body: &str) {
    let summary = summary.to_string();
    let body = body.chars().take(200).collect::<String>();
    thread::spawn(move || {
        let _ = notify_rust::Notification::new()
            .appname("AntiPhishing")
            .summary(&summary)
            .body(&body)
            .show();
    });
}
fn load_config() -> Result<Config> {
    let path = config_path();
    let text =
        fs::read_to_string(&path).with_context(|| format!("找不到設定檔：{}", path.display()))?;
    toml::from_str(&text).with_context(|| format!("{} 格式不正確", path.display()))
}

fn apply_configured_font(ctx: &egui::Context, requested: &str) -> String {
    let Some((font_name, font_bytes)) = find_font(requested) else {
        return format!("找不到字型「{requested}」，使用內建字型。請重啟後確認。",);
    };
    let mut definitions = egui::FontDefinitions::default();
    definitions.font_data.insert(
        font_name.clone(),
        Arc::new(egui::FontData::from_owned(font_bytes)),
    );
    for family in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
        definitions
            .families
            .entry(family)
            .or_default()
            .insert(0, font_name.clone());
    }
    ctx.set_fonts(definitions);
    format!("已套用字型「{font_name}」。")
}

fn find_font(requested: &str) -> Option<(String, Vec<u8>)> {
    let requested = requested.trim();
    let mut candidates = if Path::new(requested).is_file() {
        vec![(requested.to_owned(), requested.to_owned())]
    } else if requested.eq_ignore_ascii_case("noto sans tc") {
        vec![(
            "Noto Sans TC".into(),
            r"C:\Windows\Fonts\NotoSansTC-VF.ttf".into(),
        )]
    } else if requested.eq_ignore_ascii_case("microsoft jhenghei") || requested == "微軟正黑體"
    {
        vec![(
            "Microsoft JhengHei".into(),
            r"C:\Windows\Fonts\msjh.ttc".into(),
        )]
    } else {
        Vec::new()
    };
    // 指定字型不存在時，退回系統內建的繁體中文字型，避免中文顯示為方框
    candidates.push((
        "Microsoft JhengHei".into(),
        r"C:\Windows\Fonts\msjh.ttc".into(),
    ));
    candidates.push(("DFKai-SB".into(), r"C:\Windows\Fonts\kaiu.ttf".into()));
    candidates
        .into_iter()
        .find_map(|(name, path)| fs::read(&path).ok().map(|bytes| (name, bytes)))
}

fn create_tray() -> Result<Tray> {
    let menu = Menu::new();
    let show = MenuItem::new("顯示視窗", true, None);
    let scan = MenuItem::new("立即掃描", true, None);
    let quit = MenuItem::new("結束", true, None);
    menu.append_items(&[&show, &scan, &quit])?;
    let icon = match load_app_icon() {
        Ok((rgba, width, height)) => tray_icon::Icon::from_rgba(rgba, width, height)?,
        Err(_) => {
            let rgba = vec![30, 120, 190, 255]
                .into_iter()
                .cycle()
                .take(16 * 16 * 4)
                .collect();
            tray_icon::Icon::from_rgba(rgba, 16, 16)?
        }
    };
    let icon = TrayIconBuilder::new()
        .with_tooltip("AntiPhishing")
        .with_menu(Box::new(menu))
        .with_icon(icon)
        .build()?;
    Ok(Tray {
        _icon: icon,
        show,
        scan,
        quit,
    })
}

/// LLM 判定設定，存於 config.toml 的 `[llm]`（OpenAI 相容 API）；
/// `base_url` 或 `model` 為空字串即視為未設定。
#[derive(Clone, Serialize, Deserialize)]
struct LlmConfig {
    #[serde(default)]
    base_url: String,
    #[serde(default)]
    model: String,
    #[serde(default)]
    api_key: String,
    #[serde(default = "default_llm_timeout_secs")]
    timeout_secs: u64,
    #[serde(default = "default_llm_max_chars")]
    max_chars: usize,
}

fn default_llm_timeout_secs() -> u64 {
    120
}
fn default_llm_max_chars() -> usize {
    6000
}

impl Default for LlmConfig {
    fn default() -> Self {
        Self {
            base_url: String::new(),
            model: String::new(),
            api_key: String::new(),
            timeout_secs: default_llm_timeout_secs(),
            max_chars: default_llm_max_chars(),
        }
    }
}

/// LLM 對單一郵件的判定結果。
#[derive(Deserialize)]
struct LlmVerdict {
    is_phishing: bool,
    #[serde(default)]
    reason: String,
}

/// 由 Config 取得有效的 LLM 設定；未設定（URL 或 model 為空）回 None。
fn llm_config(config: &Config) -> Option<LlmConfig> {
    if config.llm.base_url.trim().is_empty() || config.llm.model.trim().is_empty() {
        return None;
    }
    Some(config.llm.clone())
}

/// 送 LLM 判斷的 system 提示：要求嚴格 JSON 輸出，判定釣魚/詐欺/惡意行銷廣告/垃圾推銷/仿冒品牌。
const LLM_SYSTEM_PROMPT: &str = "你是郵件安全判官。根據使用者提供的郵件內容，判斷該郵件是否為「釣魚、詐欺、詐騙郵件」或「惡意行銷廣告、垃圾推銷、仿冒知名品牌或販賣一般性物品的垃圾廣告郵件」。\
高風險與排除目標訊號包括：\
1. 惡意行銷與垃圾廣告：未經請求的推銷廣告、仿冒知名品牌促銷、販賣一般性物品或商品（如香薰瀑布、健康器材、保健品、手錶名品等）、含可疑轉址或假退訂連結（Opt Out）、寄件者與商品內容不合的垃圾郵件。\
2. 偽裝機構或品牌：寄件網域非其所稱品牌（如 DHL、FedEx、快遞、銀行或知名企業）的官方網域。\
3. 詐騙與個資竊取：要求付款或繳費（關稅、手續費、驗證費）、要求提供帳號密碼、緊急施壓、可疑連結、附件追蹤、內含 QR code 或要求用手機掃描（quishing）、籠統稱呼（如「親愛的顧客」）搭配假單號或要求更新地址/電話。\
\
僅輸出嚴格 JSON，不要任何其他文字：{\"is_phishing\": true 或 false, \"reason\": \"簡短理由\"}。\
只要符合上述釣魚、詐騙或惡意推銷廣告/垃圾信特徵，is_phishing 必須為 true；若為正常商務或私人往來郵件（非垃圾廣告與釣魚），is_phishing 必須為 false。若證據不足或不確定，is_phishing 設為 false。";

/// 組裝送 LLM 的郵件內容：From/Subject/內文（截斷），並附 Word 外部圖片提示。
fn llm_user_prompt(
    from: &str,
    subject: &str,
    body: &str,
    max_chars: usize,
    docx_targets: &[String],
) -> String {
    let mut text = String::new();
    text.push_str("From: ");
    text.push_str(from);
    text.push('\n');
    text.push_str("Subject: ");
    text.push_str(subject);
    text.push('\n');
    text.push_str("Body:\n");
    text.push_str(&body.chars().take(max_chars).collect::<String>());
    if !docx_targets.is_empty() {
        text.push('\n');
        text.push_str("附件提示：Word 文件含外部圖片連結（追蹤）：");
        text.push_str(&docx_targets.join("、"));
    }
    text
}

/// 解碼單一 part 的文字。mailparse 在 charset 未指定時預設 us-ascii，
/// 會把 UTF-8 高字節解成亂碼，故該情況改以 UTF-8 解碼（from_utf8_lossy）。
fn decode_part_text(mail: &mailparse::ParsedMail<'_>) -> Option<String> {
    if mail.ctype.charset.eq_ignore_ascii_case("us-ascii") {
        mail.get_body_raw()
            .ok()
            .map(|raw| String::from_utf8_lossy(&raw).into_owned())
    } else {
        mail.get_body().ok()
    }
}

/// 遞迴收集郵件各 subpart 的 text/plain 與 text/html（原始 HTML）內容。
/// mailparse 的 `get_body()` 對 multipart 訊息只回傳第一個 boundary 前的
/// preamble（通常為空），真正的內文都在 subparts 裡，必須自己找。
fn collect_text_parts(mail: &mailparse::ParsedMail<'_>, plain: &mut String, html: &mut String) {
    // 附件（Content-Disposition: attachment）不納入內文
    let is_attachment = mail
        .headers
        .get_first_value("Content-Disposition")
        .map(|v| v.to_lowercase().contains("attachment"))
        .unwrap_or(false);
    if !is_attachment {
        let mime = mail.ctype.mimetype.to_ascii_lowercase();
        if let Some(body) = decode_part_text(mail)
            && !body.is_empty()
        {
            if mime == "text/plain" {
                plain.push_str(&body);
                plain.push('\n');
            } else if mime == "text/html" {
                html.push_str(&body);
            }
        }
    }
    for part in &mail.subparts {
        collect_text_parts(part, plain, html);
    }
}

// 固定正規表示式集中為靜態編譯，避免每封郵件重複編譯
static RE_STYLE_SCRIPT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?is)<style\b.*?</style>|<script\b.*?</script>").expect("固定正規表示式")
});
static RE_DATA_URI: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"data:[^"'\s>]+"#).expect("固定正規表示式"));
static RE_IMG_ALT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)<img\b[^>]*?\balt="([^"]*)"[^>]*>"#).expect("固定正規表示式")
});
static RE_HTML_TAG: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"<[^>]+>").expect("固定正規表示式"));
static RE_INLINE_WS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[ \t\r\f\v]+").expect("固定正規表示式"));
static RE_MULTIPLE_NEWLINES: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\n{3,}").expect("固定正規表示式"));
static RE_ANY_LINK: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"https?://").expect("固定正規表示式"));
static RE_LINK_WITH_AT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"https?://[^\s]*@").expect("固定正規表示式"));
static RE_QR_IMAGE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"img[^>]*alt=["'][^"']*qr"#).expect("固定正規表示式"));
static RE_EMAIL_DOMAIN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"@([a-z0-9.-]+\.[a-z]{2,})").expect("固定正規表示式"));
static RE_THINKING_TAGS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?is)<think(?:ing)?\b.*?</think(?:ing)?>").expect("固定正規表示式")
});

/// HTML 轉純文字：移除 style/script、base64 內嵌圖（保留 img 的 alt 文字，
/// 例如「QR Code」），剝離其餘標籤並解譯常見實體字。
fn html_to_text(html: &str) -> String {
    let text = RE_STYLE_SCRIPT.replace_all(html, " ");
    // base64 內嵌圖（data: URI）是巨量噪音，先移除
    let text = RE_DATA_URI.replace_all(&text, " ");
    // 保留 img 的 alt 文字（如 QR Code），其餘屬性丟棄
    let text = RE_IMG_ALT.replace_all(&text, " [$1] ");
    let text = RE_HTML_TAG.replace_all(&text, " ");
    // 實體解碼：&amp; 必須最後才解，避免 "&amp;lt;" 被二次解碼成 "<"
    let text = text
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&nbsp;", " ")
        .replace("&amp;", "&");
    let text = RE_INLINE_WS.replace_all(&text, " ");
    RE_MULTIPLE_NEWLINES.replace_all(&text, "\n\n").into_owned()
}

/// 組裝送 LLM 的內文：text/plain + text/html（轉純文字）。
fn extract_body_text(mail: &mailparse::ParsedMail<'_>) -> (String, String) {
    let mut plain = String::new();
    let mut html = String::new();
    collect_text_parts(mail, &mut plain, &mut html);
    // 評分用原始 HTML（保留 <img alt> 等標籤特徵）
    let score_body = format!("{plain}\n{html}");
    let llm_body = if html.is_empty() {
        plain
    } else {
        format!("{plain}\n{}", html_to_text(&html))
    };
    (llm_body, score_body)
}

/// 解析 LLM 回傳的判定 JSON；容許多段 <think>/<thinking> 思考標籤、```json 圍欄與前後文字；解析失敗回 Err。
fn parse_llm_verdict(text: &str) -> Result<LlmVerdict> {
    // 1. 全域移除所有 <think>...</think> 或 <thinking>...</thinking> 標籤區塊（不分大小寫、支援多段）
    let cleaned = RE_THINKING_TAGS.replace_all(text, " ");
    let mut text = cleaned.trim();
    // 2. 剝離 Markdown 程式碼圍欄（```json ... ``` 或 ``` ... ```）
    if let Some(stripped) = text.strip_prefix("```") {
        let rest = stripped
            .strip_prefix("json")
            .unwrap_or(stripped)
            .trim_start();
        text = rest;
    }
    if let Some(index) = text.rfind("```") {
        text = text[..index].trim();
    }
    // 3. 容錯：若仍含有非 JSON 前綴或後綴文字，擷取第一個 '{' 到最後一個 '}' 的 JSON 區塊
    if let (Some(start), Some(end)) = (text.find('{'), text.rfind('}'))
        && start <= end
    {
        text = &text[start..=end];
    }
    serde_json::from_str(text).context("LLM 回應不是有效的判定 JSON")
}

/// 呼叫 OpenAI 相容的 /chat/completions 取得單一郵件判定。
fn llm_judge(
    config: &LlmConfig,
    from: &str,
    subject: &str,
    body: &str,
    docx_targets: &[String],
) -> Result<LlmVerdict> {
    let payload = serde_json::json!({
        "model": config.model,
        "temperature": 0,
        "messages": [
            { "role": "system", "content": LLM_SYSTEM_PROMPT },
            { "role": "user", "content": llm_user_prompt(from, subject, body, config.max_chars, docx_targets) }
        ]
    });
    let url = format!("{}/chat/completions", config.base_url.trim_end_matches('/'));
    // ureq 3.x 的逾時設在 Agent 上；max_redirects(0) 避免 POST 被自動重定向時拋出 redirect failed
    let agent_config = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(config.timeout_secs)))
        .max_redirects(0)
        .http_status_as_error(false)
        .build();
    let agent = ureq::Agent::new_with_config(agent_config);
    let mut request = agent.post(&url);
    let api_key = config.api_key.trim();
    if !api_key.is_empty() {
        request = request.header("Authorization", &format!("Bearer {api_key}"));
    }
    let mut response = request
        .send_json(payload)
        .map_err(|error| anyhow::anyhow!("LLM 請求失敗：{error}"))?;

    let status = response.status();
    if (300..=399).contains(&status.as_u16()) {
        let location = response
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("未知");
        anyhow::bail!(
            "LLM 伺服器回傳重定向 (HTTP {}) 至 {}，請檢查 [llm].base_url 設定",
            status.as_u16(),
            location
        );
    }
    if !status.is_success() {
        let err_body = response
            .body_mut()
            .read_to_string()
            .unwrap_or_else(|_| "(無法讀取回應內文)".into());
        anyhow::bail!(
            "LLM 伺服器回傳錯誤 (HTTP {})：{}",
            status.as_u16(),
            err_body
        );
    }

    let response: serde_json::Value = response
        .body_mut()
        .read_json()
        .map_err(|error| anyhow::anyhow!("LLM 回應不是 JSON：{error}"))?;
    let content = response["choices"]
        .get(0)
        .and_then(|choice| choice["message"]["content"].as_str())
        .context("LLM 回應缺少 choices[0].message.content")?;
    parse_llm_verdict(content)
}

/// 搬移前確認：未啟用或無待搬移郵件 → 直接核准全部 uid（與舊行為一致）；
/// 否則向 UI 送出清單並等待決定；送出失敗（UI 已關閉）、無回覆或逾時 → 視為跳過（回傳空清單，不搬移）。
fn confirm_move(
    enabled: bool,
    pending: &[(u32, String, u32, String)],
    ask: &mpsc::Sender<Vec<PendingMoveMail>>,
    reply: &mpsc::Receiver<Vec<u32>>,
) -> Vec<u32> {
    confirm_move_with_timeout(enabled, pending, ask, reply, CONFIRM_TIMEOUT)
}

fn confirm_move_with_timeout(
    enabled: bool,
    pending: &[(u32, String, u32, String)],
    ask: &mpsc::Sender<Vec<PendingMoveMail>>,
    reply: &mpsc::Receiver<Vec<u32>>,
    timeout: Duration,
) -> Vec<u32> {
    if !enabled || pending.is_empty() {
        return pending.iter().map(|(uid, _, _, _)| *uid).collect();
    }
    let list = pending
        .iter()
        .map(|(uid, subject, score, reason)| PendingMoveMail {
            uid: *uid,
            subject: subject.clone(),
            score: *score,
            reason: reason.clone(),
        })
        .collect();
    if ask.send(list).is_err() {
        return Vec::new();
    }
    // 等待 UI 決定；逾時或通道斷線都視為「全部跳過」，避免 worker 永久卡死
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Vec::new();
        }
        match reply.recv_timeout(remaining.min(Duration::from_millis(200))) {
            Ok(uids) => return uids,
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return Vec::new(),
        }
    }
}

/// 掃描指定日期郵件：逐封送 LLM 判定；判定為釣魚/惡意廣告者先暫存，
/// 該輪結束後依 `confirm_before_move` 向 UI 請求確認，核准之個別郵件才搬移至 phishing_mailbox。
/// `last_seen` 為上次檢查到的最後一封郵件（UIDVALIDITY、最大 UID），同信箱世代下只檢查其後的新信。
/// 回傳掃描結果（日誌行與檢查進度）。LLM 未設定或判定失敗時不搬移。
/// 掃描期間透過 `progress` 回報目前檢查進度供狀態列顯示。
fn scan_mail(
    config: &Config,
    dates: &[NaiveDate],
    last_seen: Option<(u32, u32)>,
    ask: &mpsc::Sender<Vec<PendingMoveMail>>,
    reply: &mpsc::Receiver<Vec<u32>>,
    progress: &mpsc::Sender<ScanEvent>,
) -> Result<ScanOutcome> {
    let mut session = connect(&config.imap)?;
    let selected = session
        .select(&config.imap.source_mailbox)
        .with_context(|| format!("無法開啟來源信箱：{}", config.imap.source_mailbox))?;
    // 伺服器未回報 UIDVALIDITY 時以 0 代稱（仍可與搬移前重查的值比對）
    let original_uidvalidity = selected.uid_validity.unwrap_or(0);
    let llm = llm_config(config);
    let mut lines: Vec<String> = Vec::new();
    let mut scanned = 0;
    // 本輪實際檢查過（完成判定）的最大 UID；LLM 判定失敗的信不列入，下輪會重試
    let mut max_checked_uid: Option<u32> = None;
    // 本輪最後完成判定的郵件（搜尋日期、UID、主旨），供進度檔記錄
    let mut last_checked: Option<(NaiveDate, u32, String)> = None;
    let mut aborted_by_llm_error = false;
    // 疑似釣魚/惡意廣告郵件暫存（uid、主旨、評分、LLM 理由），該輪結束後確認再搬移
    let mut pending: Vec<(u32, String, u32, String)> = Vec::new();
    // 確保日期由舊到新排序且不重複，保證 UID 嚴格遞增處理
    let mut sorted_dates = dates.to_vec();
    sorted_dates.sort_unstable();
    sorted_dates.dedup();

    'dates: for date in &sorted_dates {
        let mut uids: Vec<u32> = session
            .uid_search(format!("ON {}", date.format("%d-%b-%Y")))
            .with_context(|| format!("搜尋 {date} 郵件失敗"))?
            .into_iter()
            .collect();
        // 由小到大排序：處理順序穩定，進度計數也與 UID 對應
        uids.sort_unstable();
        // 只檢查上次之後的新信：同信箱世代（UIDVALIDITY）下捨棄已檢查過的 UID
        uids = filter_new_uids(uids, last_seen, original_uidvalidity);
        if !uids.is_empty() {
            progress
                .send(ScanEvent::Progress(format!(
                    "搜尋 {date}：找到 {} 封待檢查",
                    uids.len()
                )))
                .ok();
        }
        let total = uids.len();
        for (index, uid) in uids.into_iter().enumerate() {
            let messages = match session.uid_fetch(uid.to_string(), "RFC822") {
                Ok(messages) => messages,
                Err(error) => {
                    lines.push(format!("無法讀取郵件 UID {uid}（略過）：{error:#}"));
                    continue;
                }
            };
            let Some(bytes) = messages.iter().next().and_then(|message| message.body()) else {
                lines.push(format!("郵件 UID {uid} 內容為空或已被刪除，略過。"));
                continue;
            };
            let mail = match parse_mail(bytes) {
                Ok(mail) => mail,
                Err(error) => {
                    lines.push(format!("無法解析郵件 UID {uid} 內容（略過）：{error:#}"));
                    continue;
                }
            };
            let from = mail.headers.get_first_value("From").unwrap_or_default();
            let subject = mail.headers.get_first_value("Subject").unwrap_or_default();
            // mailparse 對 multipart 的 get_body() 回傳空，改從 subparts 提取
            let (body, score_body) = extract_body_text(&mail);
            scanned += 1;
            // 即時回報目前檢查的郵件（主旨），避免使用者誤以為程式卡住
            progress
                .send(ScanEvent::Progress(progress_text(
                    index + 1,
                    total,
                    &subject,
                )))
                .ok();
            let targets = external_word_image_targets(&mail);
            // 現行啟發式評分僅供 log 參考，不再作為搬移依據
            let (score, _) =
                phishing_score(&from, &subject, &score_body, &targets, &config.detection);
            match &llm {
                Some(llm_config) => {
                    match llm_judge(llm_config, &from, &subject, &body, &targets) {
                        Ok(verdict) => {
                            // 本封已完成判定（不論結果），記住檢查進度
                            max_checked_uid =
                                Some(max_checked_uid.map_or(uid, |seen| seen.max(uid)));
                            last_checked = Some((*date, uid, subject.clone()));
                            if verdict.is_phishing {
                                pending.push((uid, subject.clone(), score, verdict.reason));
                            } else {
                                lines.push(format!(
                                    "略過〈{}〉（評分 {score}；LLM：{}）",
                                    subject, verdict.reason
                                ));
                            }
                        }
                        Err(error) => {
                            // LLM 判定失敗多半是 API 設定錯誤或服務不可用：提前中止本輪，
                            // 避免每封信都等滿逾時、整輪耗時數小時且全部略過
                            lines.push(format!(
                                "LLM 判斷失敗，中止本輪掃描（剩餘郵件未檢查）：〈{subject}〉：{error:#}"
                            ));
                            aborted_by_llm_error = true;
                            break 'dates;
                        }
                    }
                }
                None => {
                    // LLM 未設定：僅計數不判定；仍記住進度，完整警告只在首輪顯示
                    max_checked_uid = Some(max_checked_uid.map_or(uid, |seen| seen.max(uid)));
                    last_checked = Some((*date, uid, subject.clone()));
                }
            }
        }
    }
    // 全部日期皆無新郵件：不搬移、不寫日誌，僅回報空掃讓 UI 更新最後檢查時間
    if scanned == 0 {
        session.logout().ok();
        return Ok(ScanOutcome {
            lines: Vec::new(),
            uidvalidity: original_uidvalidity,
            max_checked_uid: None,
            last_checked: None,
            no_new_mail: true,
        });
    }
    if aborted_by_llm_error && llm.is_some() {
        session.logout().ok();
        lines.push(format!(
            "{}：已掃描 {scanned} 封後因 LLM 判定失敗中止，未搬移。",
            dates_summary(&sorted_dates)
        ));
        return Ok(ScanOutcome {
            lines,
            uidvalidity: original_uidvalidity,
            max_checked_uid,
            last_checked,
            no_new_mail: false,
        });
    }
    // 該輪結束、搬移前：依設定向 UI 請求確認；核准選取的 uid 才搬移
    if !pending.is_empty() && config.gui.confirm_before_move {
        progress
            .send(ScanEvent::Progress("等待搬移確認…".into()))
            .ok();
    }
    let approved_uids = confirm_move(config.gui.confirm_before_move, &pending, ask, reply);
    let mut approved_set: std::collections::HashSet<u32> = approved_uids.into_iter().collect();
    let mut moved = 0;
    let mut failed = 0;
    let mut moved_uids: Vec<String> = Vec::new();
    if !approved_set.is_empty() {
        // 搬移前重新 SELECT 刷新狀態並比對 UIDVALIDITY，避免信箱重建後搬錯信
        match session.select(&config.imap.source_mailbox) {
            Ok(refreshed) if refreshed.uid_validity == Some(original_uidvalidity) => {}
            Ok(_) => {
                lines.push("來源信箱 UIDVALIDITY 已變更，為避免誤搬本輪取消搬移。".into());
                approved_set.clear();
            }
            Err(error) => {
                lines.push(format!("無法重新確認來源信箱狀態，本輪取消搬移：{error:#}"));
                approved_set.clear();
            }
        }
    }
    if !approved_set.is_empty()
        && let Err(error) = ensure_phishing_mailbox(&mut session, &config.imap.phishing_mailbox)
    {
        // 目標信箱不存在又建不出來：逐封標記失敗但保留全部日誌，不再中斷
        lines.push(format!(
            "目標信箱「{}」無法使用，本輪取消搬移：{error:#}",
            config.imap.phishing_mailbox
        ));
        approved_set.clear();
    }
    for (uid, subject, score, reason) in &pending {
        if !approved_set.contains(uid) {
            lines.push(format!(
                "跳過搬移〈{}〉（評分 {}；LLM：{}）",
                subject, score, reason
            ));
            continue;
        }
        match move_message(&mut session, *uid, &config.imap.phishing_mailbox) {
            Ok(()) => {
                lines.push(format!(
                    "搬移〈{}〉（評分 {}；LLM：{}）",
                    subject, score, reason
                ));
                moved += 1;
                moved_uids.push(uid.to_string());
            }
            Err(error) => {
                // 單封失敗只記錄並繼續，不再丟棄先前累積的所有日誌
                lines.push(format!("搬移〈{}〉失敗：{error:#}", subject));
                failed += 1;
            }
        }
    }
    if !moved_uids.is_empty() {
        // 優先 UID EXPUNGE 只清除本輪已搬移的信件，避免連帶清掉使用者在他端手動刪除的信
        let uid_set = moved_uids.join(",");
        if let Err(error) = session.uid_expunge(&uid_set) {
            lines.push(format!("UID EXPUNGE 失敗（改用 EXPUNGE）：{error:#}"));
            if let Err(error) = session.expunge() {
                lines.push(format!("刪除來源信箱中已搬移郵件失敗：{error:#}"));
            }
        }
    }
    session.logout().ok();
    let scanned_dates = dates_summary(dates);
    if llm.is_none() {
        lines.push(format!(
            "LLM 未設定（config.toml 的 [llm] base_url 或 model 為空）。{scanned_dates}：已掃描 {scanned} 封，未搬移。"
        ));
    } else {
        let skipped = pending.len().saturating_sub(moved + failed);
        let mut summary = format!("{scanned_dates}：已掃描 {scanned} 封，搬移 {moved} 封");
        if failed > 0 {
            summary.push_str(&format!("，搬移失敗 {failed} 封"));
        }
        if skipped > 0 {
            summary.push_str(&format!("，保留 {skipped} 封疑似釣魚／惡意廣告郵件"));
        }
        summary.push('。');
        lines.push(summary);
    }
    Ok(ScanOutcome {
        lines,
        uidvalidity: original_uidvalidity,
        max_checked_uid,
        last_checked,
        no_new_mail: false,
    })
}

/// 過濾掉已檢查過的 UID：僅在相同 UIDVALIDITY（信箱世代）下，捨棄 ≤ 上次最大 UID 的舊信。
/// 信箱世代不同（重建、換信箱）時保留全部，避免誤跳過。
fn filter_new_uids(uids: Vec<u32>, last_seen: Option<(u32, u32)>, uidvalidity: u32) -> Vec<u32> {
    match last_seen {
        Some((seen_validity, seen_max)) if seen_validity == uidvalidity => {
            uids.into_iter().filter(|&uid| uid > seen_max).collect()
        }
        _ => uids,
    }
}

fn dates_summary(dates: &[NaiveDate]) -> String {
    dates
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("、")
}

/// 掃描進度文字；無主旨（或全空白）時以「(無主旨)」後備。
fn progress_text(current: usize, total: usize, subject: &str) -> String {
    let subject = subject.trim();
    let subject = if subject.is_empty() {
        "(無主旨)"
    } else {
        subject
    };
    format!("檢查第 {current}/{total} 封〈{subject}〉")
}

/// 確認目標信箱存在，不存在則嘗試建立。
fn ensure_phishing_mailbox(session: &mut Session<imap::Connection>, name: &str) -> Result<()> {
    let exists = session
        .list(Some(""), Some(name))
        .with_context(|| format!("無法查詢信箱是否存在：{name}"))?
        .iter()
        .any(|mailbox| mailbox.name() == name);
    if !exists {
        session
            .create(name)
            .with_context(|| format!("無法建立信箱：{name}"))?;
    }
    Ok(())
}

fn startup_scan_dates(today: NaiveDate) -> [NaiveDate; 2] {
    [today - chrono::Duration::days(1), today]
}

/// 建立 IMAP 連線：手動 TCP+TLS 以確保連線與讀寫皆有逾時，
/// 避免伺服器停滯時 worker 永久卡死、排程掃描全面癱瘓。
fn connect(config: &ImapConfig) -> Result<Session<imap::Connection>> {
    let host = config.host.trim();
    if host.is_empty() {
        bail!("IMAP 伺服器位址為空");
    }
    let tcp = tcp_stream_with_timeout(host, config.port)?;
    match config.protocol.as_str() {
        "imaps" => {
            let connector = native_tls::TlsConnector::new().context("無法建立 TLS 連接器")?;
            let tls = connector.connect(host, tcp).context("IMAP TLS 交握失敗")?;
            let mut client = imap::Client::<imap::Connection>::new(Box::new(tls));
            client.read_greeting().context("讀取 IMAP 問候訊息失敗")?;
            finish_login(client, config)
        }
        "starttls" => {
            // imap crate 未公開「升級前送出任意指令」的 API，
            // 故 STARTTLS 前置交談（問候＋STARTTLS 指令）在此手工完成。
            let mut plain = tcp;
            let greeting = read_imap_line(&mut plain)?;
            if !greeting.starts_with("* ") {
                bail!("非預期的 IMAP 問候訊息：{greeting}");
            }
            const TAG: &str = "AP1";
            use std::io::Write as _;
            write!(plain, "{TAG} STARTTLS\r\n").context("送出 STARTTLS 指令失敗")?;
            plain.flush().context("送出 STARTTLS 指令失敗")?;
            let done_line = loop {
                let line = read_imap_line(&mut plain)?;
                if line.starts_with(TAG) {
                    break line;
                }
                // 忽略未標記回應（如 * CAPABILITY）
            };
            if !done_line
                .split_whitespace()
                .nth(1)
                .is_some_and(|status| status.eq_ignore_ascii_case("OK"))
            {
                // 伺服器拒絕即中止，絕不退回明文登入，避免降級攻擊
                bail!("STARTTLS 升級被伺服器拒絕：{}", done_line.trim());
            }
            let connector = native_tls::TlsConnector::new().context("無法建立 TLS 連接器")?;
            let tls = connector
                .connect(host, plain)
                .context("IMAP TLS 交握失敗")?;
            let mut client = imap::Client::<imap::Connection>::new(Box::new(tls));
            // 問候訊息已在升級前讀取
            client.greeting_read = true;
            finish_login(client, config)
        }
        other => bail!("不支援的 protocol：{other}"),
    }
}

/// 以 connect_timeout 逐一嘗試所有解析出的位址，並設定讀寫逾時。
fn tcp_stream_with_timeout(host: &str, port: u16) -> Result<TcpStream> {
    let addrs = (host, port)
        .to_socket_addrs()
        .with_context(|| format!("無法解析 IMAP 伺服器位址：{host}"))?;
    let mut last_error = None;
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, IMAP_CONNECT_TIMEOUT) {
            Ok(stream) => {
                stream
                    .set_read_timeout(Some(IMAP_IO_TIMEOUT))
                    .context("設定讀取逾時失敗")?;
                stream
                    .set_write_timeout(Some(IMAP_IO_TIMEOUT))
                    .context("設定寫入逾時失敗")?;
                return Ok(stream);
            }
            Err(error) => last_error = Some(error),
        }
    }
    bail!(last_error.map_or_else(
        || format!("IMAP TCP 連線失敗：{host}:{port}（沒有可嘗試的位址）"),
        |error| format!("IMAP TCP 連線失敗：{host}:{port}（{error}）")
    ))
}

/// 逐位元組讀取一行 IMAP 回應（不含行尾 CRLF）；
/// 逐位元組是為了避免緩衝區超讚吃掉 TLS 交握後的第一批資料。
fn read_imap_line(stream: &mut TcpStream) -> Result<String> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let read = stream.read(&mut byte).context("IMAP 連線讀取失敗")?;
        if read == 0 {
            bail!("IMAP 連線意外中斷");
        }
        if byte[0] == b'\n' {
            break;
        }
        line.push(byte[0]);
        if line.len() > 8192 {
            bail!("IMAP 回應行過長");
        }
    }
    let mut text = String::from_utf8_lossy(&line).into_owned();
    if text.ends_with('\r') {
        text.pop();
    }
    Ok(text)
}

fn finish_login(
    client: imap::Client<imap::Connection>,
    config: &ImapConfig,
) -> Result<Session<imap::Connection>> {
    client
        .login(&config.username, &config.password)
        .map_err(|(error, _)| error)
        .context("IMAP 登入失敗")
}
fn move_message(session: &mut Session<imap::Connection>, uid: u32, target: &str) -> Result<()> {
    session
        .uid_copy(uid.to_string(), target)
        .with_context(|| format!("無法複製郵件到：{target}"))?;
    session.uid_store(uid.to_string(), "+FLAGS.SILENT (\\Deleted)")?;
    Ok(())
}

/// 從 IMAP 伺服器取得所有 mailbox 清單（原始名稱）。
fn fetch_mailbox_list(config: &ImapConfig) -> Result<Vec<String>> {
    let mut session = connect(config)?;
    let names = session
        .list(Some(""), Some("*"))
        .context("無法取得信箱清單")?;
    let mut list: Vec<String> = names.iter().map(|n| n.name().to_string()).collect();
    session.logout().ok();
    list.sort();
    list.dedup();
    Ok(list)
}

/// 將 IMAP Modified Base64 解碼為 bytes。
/// IMAP Modified Base64 使用 ',' 取代 '/'，且不含 '=' padding。
fn imap_modified_base64_decode(input: &str) -> Option<Vec<u8>> {
    let mut table = [255u8; 256];
    for (i, &b) in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+"
        .iter()
        .enumerate()
    {
        table[b as usize] = i as u8;
    }
    table[b',' as usize] = 63;
    table[b'/' as usize] = 63;

    let clean: Vec<u8> = input
        .bytes()
        .filter(|&b| b != b'=' && !b.is_ascii_whitespace())
        .collect();
    let mut out = Vec::with_capacity(clean.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0;

    for &b in &clean {
        let val = table[b as usize];
        if val == 255 {
            return None;
        }
        buf = (buf << 6) | (val as u32);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// 將 UTF-16BE bytes 轉換為 UTF-8 String。
fn utf16be_bytes_to_string(bytes: &[u8]) -> String {
    let mut u16_vec = Vec::with_capacity(bytes.len() / 2);
    for chunk in bytes.chunks_exact(2) {
        u16_vec.push(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    String::from_utf16_lossy(&u16_vec)
}

/// 將 IMAP modified UTF-7 字串解碼為 UTF-8 Unicode 字串（例如將 Mail2000 的 &...- 解回中文）。
pub fn decode_imap_utf7(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut rest = s;

    while let Some(start_idx) = rest.find('&') {
        result.push_str(&rest[..start_idx]);
        let after_amp = &rest[start_idx + 1..];
        if let Some(end_idx) = after_amp.find('-') {
            let inner = &after_amp[..end_idx];
            if inner.is_empty() {
                // "&-" 表示字元 '&'
                result.push('&');
            } else if let Some(bytes) = imap_modified_base64_decode(inner) {
                result.push_str(&utf16be_bytes_to_string(&bytes));
            } else {
                // 解碼失敗時保留原始字串
                result.push('&');
                result.push_str(inner);
                result.push('-');
            }
            rest = &after_amp[end_idx + 1..];
        } else {
            // 沒有找到結尾 '-'，保留剩餘字串
            result.push('&');
            result.push_str(after_amp);
            rest = "";
            break;
        }
    }
    result.push_str(rest);
    result
}
/// 常見快遞品牌及其官方網域（小寫）：用於偵測 From 顯示名稱偽裝。
const BRAND_OFFICIAL_DOMAINS: [(&str, &str); 3] = [
    ("dhl", "dhl.com"),
    ("fedex", "fedex.com"),
    ("ups", "ups.com"),
];
fn phishing_score(
    from: &str,
    subject: &str,
    body: &str,
    targets: &[String],
    config: &DetectionConfig,
) -> (u32, Vec<String>) {
    let text = format!("{subject}\n{body}").to_lowercase();
    let from = from.to_lowercase();
    let mut score = 0;
    let mut reasons = Vec::new();
    if config
        .suspicious_sender_domains
        .iter()
        .any(|d| from.contains(&d.to_lowercase()))
    {
        score += 4;
        reasons.push("寄件網域在可疑清單".into());
    }
    let count = config
        .suspicious_keywords
        .iter()
        .filter(|k| text.contains(&k.to_lowercase()))
        .count();
    if count > 0 {
        score += count.min(3) as u32;
        reasons.push(format!("含 {count} 個可疑關鍵字"));
    }
    let links = RE_ANY_LINK.find_iter(&text).count();
    if links >= 2 {
        score += 2;
        reasons.push("含多個連結".into());
    }
    if RE_LINK_WITH_AT.is_match(&text) {
        score += 3;
        reasons.push("連結含 @，可能偽裝網域".into());
    }
    // QR code 內嵌圖（quishing）：整封無連結、叫用戶拿手機掃碼
    if RE_QR_IMAGE.is_match(&text) {
        score += 4;
        reasons.push("含 QR code 圖片（quishing）".into());
    }
    // 品牌偽裝：From 顯示名稱含品牌（如 DHL），但寄件網域非該品牌官方網域
    let email_domain = RE_EMAIL_DOMAIN.captures(&from).map(|c| c[1].to_string());
    let display_name = from.split('<').next().unwrap_or(from.as_str()).trim();
    if let Some(domain) = email_domain {
        for (brand, official) in BRAND_OFFICIAL_DOMAINS {
            if display_name.contains(brand) && !domain.ends_with(official) {
                score += 3;
                reasons.push(format!("品牌偽裝：顯示名稱含 {brand} 但網域非 {official}"));
                break;
            }
        }
    }
    if !targets.is_empty() {
        score += config.external_word_image_score;
        reasons.push("Word 附件含外部圖片連結".into());
    }
    if config
        .trusted_sender_domains
        .iter()
        .any(|d| from.contains(&d.to_lowercase()))
    {
        score = score.saturating_sub(3);
        reasons.push("寄件網域在信任清單".into());
    }
    (score, reasons)
}
fn external_word_image_targets(mail: &mailparse::ParsedMail<'_>) -> Vec<String> {
    mail.parts()
        .filter(|part| is_docx_part(part))
        .filter_map(|part| part.get_body_raw().ok())
        .flat_map(|bytes| external_word_image_targets_from_docx(&bytes))
        .collect()
}

/// 只對 Word（docx/docm）附件做 zip 解析，避免把所有附件都解 base64 並嘗試開 zip。
fn is_docx_part(part: &mailparse::ParsedMail<'_>) -> bool {
    let mime = part.ctype.mimetype.to_ascii_lowercase();
    if mime.contains("wordprocessingml.document") {
        return true;
    }
    part.get_content_disposition()
        .params
        .get("filename")
        .map(|name| {
            let lower = name.to_lowercase();
            lower.ends_with(".docx") || lower.ends_with(".docm")
        })
        .unwrap_or(false)
}

fn external_word_image_targets_from_docx(bytes: &[u8]) -> Vec<String> {
    let Ok(mut archive) = ZipArchive::new(Cursor::new(bytes)) else {
        return Vec::new();
    };
    let mut targets = Vec::new();
    for index in 0..archive.len() {
        let Ok(mut entry) = archive.by_index(index) else {
            continue;
        };
        let Ok(name) = entry.name() else {
            continue;
        };
        if !name.starts_with("word/") || !name.ends_with(".rels") {
            continue;
        }
        // .rels 檔案極小；超過上限視為壓縮炸彈，直接略過
        if entry.size() > MAX_DOCX_RELS_BYTES {
            continue;
        }
        let mut xml = String::new();
        if entry.read_to_string(&mut xml).is_ok() {
            targets.extend(external_image_targets_from_relationships(&xml));
        }
    }
    targets
}
fn external_image_targets_from_relationships(xml: &str) -> Vec<String> {
    let mut reader = Reader::from_str(xml);
    let mut targets = Vec::new();
    loop {
        match reader.read_event() {
            Ok(Event::Empty(event)) | Ok(Event::Start(event))
                if event.name().as_ref() == b"Relationship" =>
            {
                let mut relationship_type = None;
                let mut target = None;
                let mut target_mode = None;
                for attribute in event.attributes().flatten() {
                    let value = String::from_utf8_lossy(attribute.value.as_ref()).into_owned();
                    match attribute.key.as_ref() {
                        b"Type" => relationship_type = Some(value),
                        b"Target" => target = Some(value),
                        b"TargetMode" => target_mode = Some(value),
                        _ => {}
                    }
                }
                if relationship_type.is_some_and(|value| value.ends_with("/image"))
                    && target_mode.as_deref() == Some("External")
                    && target.as_ref().is_some_and(|value| {
                        value.starts_with("http://") || value.starts_with("https://")
                    })
                {
                    targets.push(target.expect("已檢查 target 存在"));
                }
            }
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
    }
    targets
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn detects_external_word_image_relationship() {
        let xml = r#"<Relationships><Relationship Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="https://track.example/pixel.png" TargetMode="External" /></Relationships>"#;
        assert_eq!(
            external_image_targets_from_relationships(xml),
            ["https://track.example/pixel.png"]
        );
    }

    #[test]
    fn startup_scans_previous_day_and_today() {
        let today = NaiveDate::from_ymd_opt(2026, 8, 5).expect("固定測試日期");
        assert_eq!(
            startup_scan_dates(today),
            [
                NaiveDate::from_ymd_opt(2026, 8, 4).expect("固定測試日期"),
                today
            ]
        );
    }

    #[test]
    fn parses_plain_json_verdict() {
        let verdict = parse_llm_verdict(r#"{"is_phishing": true, "reason": "偽裝銀行"}"#)
            .expect("純 JSON 應可解析");
        assert!(verdict.is_phishing);
        assert_eq!(verdict.reason, "偽裝銀行");
    }

    #[test]
    fn parses_spam_marketing_json_verdict() {
        let verdict =
            parse_llm_verdict(r#"{"is_phishing": true, "reason": "惡意行銷廣告與推銷商品"}"#)
                .expect("純 JSON 應可解析");
        assert!(verdict.is_phishing);
        assert_eq!(verdict.reason, "惡意行銷廣告與推銷商品");
    }

    #[test]
    fn parses_thinking_model_json_verdict() {
        let response = r#"
        <think>
        Let me analyze this email carefully.
        1. The sender domain is official.
        2. No phishing indicators.
        Conclusion: not phishing.
        </think>

        {"is_phishing": false, "reason": "內部正常公務通知"}
        "#;
        let verdict = parse_llm_verdict(response).expect("思考模型 <think> 標籤應可正確剝除並解析");
        assert!(!verdict.is_phishing);
        assert_eq!(verdict.reason, "內部正常公務通知");
    }

    #[test]
    fn parses_conversational_wrapped_json_verdict() {
        let response = r#"
        根據分析，這是一封釣魚郵件：
        ```json
        {
            "is_phishing": true,
            "reason": "偽裝知名快遞索取個資"
        }
        ```
        請盡速隔離。
        "#;
        let verdict =
            parse_llm_verdict(response).expect("前後包裝文字與 markdown 圍欄應可正確擷取解析");
        assert!(verdict.is_phishing);
        assert_eq!(verdict.reason, "偽裝知名快遞索取個資");
    }

    #[test]
    fn parses_multiple_thinking_tags_json_verdict() {
        let response = r#"
        <thinking>
        初步觀察：這封信主旨是優惠活動。
        </thinking>
        進一步分析：
        <think>
        寄件者不是官方網域，含有可疑連結。
        </think>
        最終判定：
        ```json
        {
            "is_phishing": true,
            "reason": "多段思考後判定為詐騙"
        }
        ```
        "#;
        let verdict = parse_llm_verdict(response).expect("多段 think 與 thinking 標籤應被全數過濾");
        assert!(verdict.is_phishing);
        assert_eq!(verdict.reason, "多段思考後判定為詐騙");
    }

    #[test]
    fn extracts_spam_eml_content() {
        if let Ok(bytes) = std::fs::read("Spam.eml") {
            let mail = parse_mail(&bytes).expect("Spam.eml 應可解析");
            let from = mail.headers.get_first_value("From").unwrap_or_default();
            let subject = mail.headers.get_first_value("Subject").unwrap_or_default();
            let (llm_body, _) = extract_body_text(&mail);
            assert!(from.contains("fote-hotel.biz") || from.contains("Waterfal"));
            assert!(subject.contains("裝飾") || subject.contains("健康"));
            assert!(llm_body.contains("Spirual") || llm_body.contains("香薰"));
            let prompt = llm_user_prompt(&from, &subject, &llm_body, 6000, &[]);
            assert!(prompt.contains("From:"));
            assert!(prompt.contains("Subject:"));
            assert!(prompt.contains("Body:"));
        }
    }

    #[test]
    fn parses_fenced_json_verdict() {
        let text = "```json\n{\"is_phishing\": false, \"reason\": \"正常\"}\n```";
        let verdict = parse_llm_verdict(text).expect("圍欄 JSON 應可解析");
        assert!(!verdict.is_phishing);
    }

    #[test]
    fn rejects_invalid_verdict() {
        assert!(parse_llm_verdict("這不是 JSON").is_err());
        assert!(parse_llm_verdict("").is_err());
    }

    #[test]
    fn llm_prompt_truncates_body_and_includes_docx_hint() {
        let body = "a".repeat(5000);
        let targets = vec!["https://track.example/pixel.png".into()];
        let prompt = llm_user_prompt("a@b.com", "主旨", &body, 100, &targets);
        // 內文被截斷至 100 字元
        assert!(prompt.contains(&"a".repeat(100)));
        assert!(!prompt.contains(&"a".repeat(101)));
        // 附帶 Word 外部圖片提示
        assert!(prompt.contains("外部圖片連結（追蹤）"));
        assert!(prompt.contains("https://track.example/pixel.png"));
    }

    #[test]
    fn llm_prompt_omits_docx_hint_when_empty() {
        let prompt = llm_user_prompt("a@b.com", "主旨", "內文", 100, &[]);
        assert!(!prompt.contains("附件提示"));
    }

    fn test_detection_config() -> DetectionConfig {
        DetectionConfig {
            threshold: 5,
            suspicious_sender_domains: Vec::new(),
            trusted_sender_domains: Vec::new(),
            suspicious_keywords: Vec::new(),
            external_word_image_score: 5,
        }
    }

    // 回歸：multipart/alternative 的內文在 subparts 裡，get_body() 回傳空。
    // 送 LLM 的內文必須包含 HTML 正文（含 QR alt），且不含 base64/style 噪音。
    #[test]
    fn extracts_body_from_multipart_subparts() {
        let raw = concat!(
            "Content-Type: multipart/alternative; boundary=b\r\n\r\n",
            "--b\r\nContent-Type: text/plain\r\n\r\nHi\r\n",
            "--b\r\nContent-Type: text/html; charset=\"utf-8\"\r\n\r\n",
            "<style>body{color:red}</style>",
            "<img src=\"data:image/png;base64,iVBORw0KGgo\" alt=\"QR Code\">",
            "請使用手機掃描\r\n",
            "--b--\r\n"
        );
        let mail = parse_mail(raw.as_bytes()).expect("應可解析 multipart");
        let (llm_body, score_body) = extract_body_text(&mail);
        assert!(llm_body.contains("Hi"));
        assert!(llm_body.contains("[QR Code]"));
        assert!(llm_body.contains("請使用手機掃描"));
        assert!(!llm_body.contains("iVBORw0KGgo"), "base64 圖片資料應被移除");
        assert!(!llm_body.contains("color:red"), "style 區塊應被移除");
        // 評分用原始 HTML 仍保留 <img alt> 特徵供 QR 因子比對
        assert!(score_body.contains("alt=\"QR Code\""));
    }

    // 部分寄件者省略 charset；mailparse 預設 us-ascii 會把 UTF-8 解成亂碼
    #[test]
    fn decodes_utf8_when_charset_missing() {
        let raw = "Content-Type: text/plain\r\n\r\n請使用手機掃描";
        let mail = parse_mail(raw.as_bytes()).expect("應可解析");
        let (llm_body, _) = extract_body_text(&mail);
        assert!(llm_body.contains("請使用手機掃描"));
    }

    // 實體解碼順序：&amp; 最後才解，避免 "&amp;lt;" 被二次解碼成 "<"
    #[test]
    fn html_entities_decode_ampersand_last() {
        assert_eq!(html_to_text("&amp;lt;b&amp;gt;"), "&lt;b&gt;");
        assert_eq!(html_to_text("&lt;b&gt;"), "<b>");
        assert_eq!(html_to_text("a &amp;&amp; b"), "a && b");
    }

    // 只對 Word 附件做 zip 解析：依副檔名或 MIME 判別
    #[test]
    fn only_docx_attachments_are_selected_for_zip_parsing() {
        let raw = concat!(
            "Content-Type: multipart/mixed; boundary=b\r\n\r\n",
            "--b\r\nContent-Disposition: attachment; filename=\"report.docx\"\r\n",
            "Content-Type: application/octet-stream\r\n\r\nzzz\r\n",
            "--b\r\nContent-Disposition: attachment; filename=\"notes.txt\"\r\n",
            "Content-Type: text/plain\r\n\r\nhello\r\n",
            "--b\r\nContent-Disposition: attachment\r\n",
            "Content-Type: application/vnd.openxmlformats-officedocument.wordprocessingml.document\r\n\r\nzzz\r\n",
            "--b--\r\n"
        );
        let mail = parse_mail(raw.as_bytes()).expect("應可解析 multipart");
        let attachments = &mail.subparts;
        assert_eq!(attachments.len(), 3);
        assert!(is_docx_part(&attachments[0]), ".docx 副檔名應命中");
        assert!(!is_docx_part(&attachments[1]), ".txt 不應命中");
        assert!(is_docx_part(&attachments[2]), "Word MIME 應命中");
        // 非 zip 內容不應 panic 且回傳空
        assert!(external_word_image_targets_from_docx(b"not a zip").is_empty());
    }

    #[test]
    fn scores_qr_inline_image_as_quishing() {
        let (score, reasons) = phishing_score(
            "a@b.com",
            "主旨",
            "<img src=\"x.png\" alt=\"QR Code\">",
            &[],
            &test_detection_config(),
        );
        assert!(score >= 4);
        assert!(reasons.iter().any(|r| r.contains("QR")));
    }

    #[test]
    fn scores_brand_spoofing_when_domain_mismatches() {
        let (score, reasons) = phishing_score(
            "DHL Express <noreply@mail.us.somacis.com>",
            "包裹",
            "",
            &[],
            &test_detection_config(),
        );
        assert!(score >= 3);
        assert!(reasons.iter().any(|r| r.contains("品牌偽裝")));
    }

    #[test]
    fn does_not_score_brand_spoofing_for_official_domain() {
        let (_, reasons) = phishing_score(
            "DHL Express <noreply@dhl.com>",
            "包裹",
            "",
            &[],
            &test_detection_config(),
        );
        assert!(!reasons.iter().any(|r| r.contains("品牌偽裝")));
    }

    // ===== 搬移確認 =====

    #[test]
    fn gui_confirm_before_move_defaults_to_true_when_absent() {
        // 既有 config.toml 缺此欄位時，預設應為「要確認」
        let gui: GuiConfig = toml::from_str("").expect("所有欄位皆有 serde 預設值");
        assert!(gui.confirm_before_move);
    }

    #[test]
    fn gui_confirm_before_move_can_be_disabled() {
        let gui: GuiConfig = toml::from_str("confirm_before_move = false").expect("應可解析");
        assert!(!gui.confirm_before_move);
    }

    #[test]
    fn gui_log_retention_days_defaults_to_30_when_absent() {
        // 既有 config.toml 缺此欄位時，預設保留 30 天
        let gui: GuiConfig = toml::from_str("").expect("所有欄位皆有 serde 預設值");
        assert_eq!(gui.log_retention_days, 30);
    }

    #[test]
    fn cleanup_retention_days_zero_means_never_cleanup() {
        assert_eq!(cleanup_retention_days(0), None);
        assert_eq!(cleanup_retention_days(30), Some(30));
        assert_eq!(cleanup_retention_days(7), Some(7));
    }

    #[test]
    fn confirm_move_auto_approves_when_disabled_or_empty() {
        let (ask, _ask_rx) = mpsc::channel::<Vec<PendingMoveMail>>();
        let (_reply_tx, reply_rx) = mpsc::channel::<Vec<u32>>();
        assert_eq!(confirm_move(false, &[], &ask, &reply_rx), Vec::<u32>::new());
        let pending = vec![(1, "主旨".to_string(), 3, "理由".to_string())];
        // 未啟用確認＝自動搬移（核准全部 uid）
        assert_eq!(confirm_move(false, &pending, &ask, &reply_rx), vec![1]);
        // 無待搬移郵件不需確認
        assert_eq!(confirm_move(true, &[], &ask, &reply_rx), Vec::<u32>::new());
    }

    #[test]
    fn confirm_move_rejects_when_ui_receiver_dropped() {
        // UI 已關閉：send 失敗 → 視為跳過（不搬移）
        let (ask, ask_rx) = mpsc::channel::<Vec<PendingMoveMail>>();
        drop(ask_rx);
        let (_reply_tx, reply_rx) = mpsc::channel::<Vec<u32>>();
        let pending = vec![(1, "主旨".to_string(), 3, "理由".to_string())];
        assert_eq!(
            confirm_move(true, &pending, &ask, &reply_rx),
            Vec::<u32>::new()
        );
    }

    #[test]
    fn confirm_move_round_trip_partial_selection() {
        let (ask, ask_rx) = mpsc::channel::<Vec<PendingMoveMail>>();
        let (reply_tx, reply_rx) = mpsc::channel::<Vec<u32>>();
        let pending = vec![
            (101, "主旨A".to_string(), 3, "理由A".to_string()),
            (102, "主旨B".to_string(), 4, "理由B".to_string()),
        ];
        let worker = thread::spawn(move || confirm_move(true, &pending, &ask, &reply_rx));
        // 模擬 UI：收到清單後，只選取 102 進行隔離
        let received = ask_rx.recv().expect("應收到待搬移清單");
        assert_eq!(received.len(), 2);
        assert_eq!(received[0].uid, 101);
        assert_eq!(received[1].uid, 102);
        reply_tx.send(vec![102]).expect("應可回覆");
        let approved = worker.join().expect("worker 應結束");
        assert_eq!(approved, vec![102]);
    }

    #[test]
    fn confirm_move_round_trip_reject() {
        let (ask, ask_rx) = mpsc::channel::<Vec<PendingMoveMail>>();
        let (reply_tx, reply_rx) = mpsc::channel::<Vec<u32>>();
        let pending = vec![(1, "主旨A".to_string(), 3, "理由A".to_string())];
        let worker = thread::spawn(move || confirm_move(true, &pending, &ask, &reply_rx));
        // 模擬 UI：收到清單後回覆跳過（空清單）
        assert!(ask_rx.recv().is_ok());
        reply_tx.send(Vec::new()).expect("應可回覆");
        let approved = worker.join().expect("worker 應結束");
        assert!(approved.is_empty());
    }

    #[test]
    fn confirm_move_times_out_and_skips() {
        let (ask, _ask_rx) = mpsc::channel::<Vec<PendingMoveMail>>();
        let (_reply_tx, reply_rx) = mpsc::channel::<Vec<u32>>();
        let pending = vec![(1, "主旨".to_string(), 3, "理由".to_string())];
        // UI 遲遲不回覆 → 逾時視為全部跳過，worker 不會永久卡死
        assert_eq!(
            confirm_move_with_timeout(true, &pending, &ask, &reply_rx, Duration::from_millis(50)),
            Vec::<u32>::new()
        );
    }

    // 掃描進度文字：含計數與主旨；無主旨時以「(無主旨)」後備
    #[test]
    fn progress_text_formats_counter_and_subject() {
        assert_eq!(
            progress_text(3, 17, "您的帳戶即將被凍結"),
            "檢查第 3/17 封〈您的帳戶即將被凍結〉"
        );
        assert_eq!(progress_text(1, 2, ""), "檢查第 1/2 封〈(無主旨)〉");
        assert_eq!(progress_text(2, 5, "  "), "檢查第 2/5 封〈(無主旨)〉");
    }

    // ===== IMAP UTF-7 解碼測試 =====

    #[test]
    fn decodes_plain_ascii_mailbox_names() {
        assert_eq!(decode_imap_utf7("INBOX"), "INBOX");
        assert_eq!(decode_imap_utf7("Sent Items"), "Sent Items");
        assert_eq!(decode_imap_utf7("Drafts/2026"), "Drafts/2026");
    }

    #[test]
    fn decodes_ampersand_escape() {
        assert_eq!(decode_imap_utf7("&-"), "&");
        assert_eq!(decode_imap_utf7("a&-b"), "a&b");
    }

    #[test]
    fn decodes_utf7_chinese_mailbox_names() {
        // "垃圾信件" -> &V4NXPk,hTvb-
        assert_eq!(decode_imap_utf7("&V4NXPk,hTvb-"), "垃圾信件");
        // 中英路徑組合
        assert_eq!(decode_imap_utf7("INBOX/&V4NXPk,hTvb-"), "INBOX/垃圾信件");
        // 多個區段
        assert_eq!(
            decode_imap_utf7("&V4NXPk,hTvb-/&V4NXPk,hTvb-"),
            "垃圾信件/垃圾信件"
        );
    }

    #[test]
    fn handles_malformed_utf7_gracefully() {
        // 沒有結尾 '-'
        assert_eq!(decode_imap_utf7("&V4NX"), "&V4NX");
        // 空字串
        assert_eq!(decode_imap_utf7(""), "");
    }

    #[test]
    #[ignore = "需連線真實 IMAP 與 LLM 進行測試"]
    fn test_scan_live_date() {
        let config_str = std::fs::read_to_string("config.toml").expect("需有 config.toml");
        let config: Config = toml::from_str(&config_str).expect("需可解析 config.toml");
        let date = chrono::NaiveDate::from_ymd_opt(2026, 8, 19).unwrap();
        let (ask_tx, ask_rx) = mpsc::channel::<Vec<PendingMoveMail>>();
        let (reply_tx, reply_rx) = mpsc::channel::<Vec<u32>>();
        let (progress_tx, progress_rx) = mpsc::channel::<ScanEvent>();

        // 背景 thread：收到待搬移清單後印出，並回傳空清單（不搬移，僅測試判定）
        thread::spawn(move || {
            if let Ok(pending) = ask_rx.recv() {
                println!("\n[測試] 待搬移釣魚郵件清單（本次測試不執行搬移）：");
                for item in pending {
                    println!("  - 主旨：{}，原因：{}", item.subject, item.reason);
                }
                reply_tx.send(Vec::new()).ok();
            }
        });
        // 背景 thread：印出掃描進度
        thread::spawn(move || {
            while let Ok(event) = progress_rx.recv() {
                if let ScanEvent::Progress(text) = event {
                    println!("  [進度] {text}");
                }
            }
        });

        let outcome = scan_mail(&config, &[date], None, &ask_tx, &reply_rx, &progress_tx)
            .expect("scan_mail 應成功執行");
        println!("\n=== 2026-08-19 掃描日誌結果 ===");
        for log in outcome.lines {
            println!("{log}");
        }
        println!("===============================\n");
    }

    // ===== 無新郵件過濾 =====

    #[test]
    fn filters_already_checked_uids_within_same_validity() {
        let uids = vec![3, 7, 9];
        // 上輪檢查到 UID 7：只剩 9 是新信
        assert_eq!(filter_new_uids(uids, Some((42, 7)), 42), [9]);
        // 上輪檢查到 UID 3：7、9 皆為新信
        assert_eq!(filter_new_uids(vec![3, 7, 9], Some((42, 3)), 42), [7, 9]);
        // 全部都檢查過：空掃
        assert!(filter_new_uids(vec![3, 7], Some((42, 9)), 42).is_empty());
    }

    #[test]
    fn keeps_all_uids_when_validity_changes_or_unknown() {
        // 信箱重建（UIDVALIDITY 改變）：保留全部，避免誤跳過新信
        assert_eq!(filter_new_uids(vec![3, 7], Some((42, 9)), 43), [3, 7]);
        // 從未掃描過：保留全部
        assert_eq!(filter_new_uids(vec![3, 7], None, 42), [3, 7]);
    }

    // ===== 掃描進度檔與每日日誌 =====

    /// 建立唯一的暫存目錄供檔案型測試使用。
    fn temp_test_dir(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("系統時間應晚於 UNIX_EPOCH")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("apgui-{tag}-{nanos}"));
        fs::create_dir_all(&dir).expect("應能建立暫存目錄");
        dir
    }

    #[test]
    fn scan_state_round_trips_through_toml() {
        let state = LastScanState {
            uidvalidity: 42,
            max_checked_uid: 999,
            last_mail_uid: 999,
            last_mail_subject: "DHL：包裹待領取「引號」".into(),
            last_mail_date: NaiveDate::from_ymd_opt(2026, 8, 25).unwrap(),
            checked_at: Local
                .with_ymd_and_hms(2026, 8, 25, 10, 30, 0)
                .single()
                .expect("應可建構時間"),
        };
        let text = toml::to_string_pretty(&state).expect("應可序列化");
        let parsed: LastScanState = toml::from_str(&text).expect("應可反序列化");
        assert_eq!(parsed, state);
    }

    #[test]
    fn malformed_scan_state_text_is_rejected() {
        assert!(toml::from_str::<LastScanState>("不是 TOML 內容").is_err());
        // 缺欄位亦不可靜默接受，避免半殘斷點造成漏掃或誤跳
        assert!(toml::from_str::<LastScanState>("uidvalidity = 42").is_err());
    }

    #[test]
    fn log_file_name_formats_daily_path() {
        let date = NaiveDate::from_ymd_opt(2026, 8, 5).unwrap();
        assert_eq!(log_file_name(date), "2026-08-05.log");
    }

    #[test]
    fn append_log_lines_creates_and_appends_with_timestamp() {
        let dir = temp_test_dir("append");
        let date = NaiveDate::from_ymd_opt(2026, 8, 25).unwrap();
        append_log_lines(&dir, date, &["第一行".into()]).expect("首次寫入應成功");
        append_log_lines(&dir, date, &["第二行".into()]).expect("第二次寫入應為附加");
        let text = fs::read_to_string(dir.join(log_file_name(date))).expect("應有日誌檔");
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "同一日兩次寫入不得覆蓋");
        assert!(lines[0].ends_with("第一行"));
        assert!(
            lines[0].contains("[2026-") && lines[0].starts_with('['),
            "應有時間戳前綴：{}",
            lines[0]
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn load_day_log_caps_tail_and_scopes_to_requested_date() {
        let dir = temp_test_dir("loadday");
        let day = NaiveDate::from_ymd_opt(2026, 8, 25).unwrap();
        fs::write(
            dir.join(log_file_name(day)),
            "a\n[2026-08-25 13:40:46] 檢查完成：無新郵件。\nb\nc\n",
        )
        .unwrap();
        fs::write(
            dir.join(log_file_name(NaiveDate::from_ymd_opt(2026, 8, 24).unwrap())),
            "昨日內容\n",
        )
        .unwrap();
        // 只讀指定日、只取尾端上限行數、過濾無新郵件空掃紀錄；缺檔視為空
        assert_eq!(load_day_log(&dir, day, 2).unwrap(), ["b", "c"]);
        assert_eq!(load_day_log(&dir, day, 10).unwrap(), ["a", "b", "c"]);
        let missing = NaiveDate::from_ymd_opt(2026, 8, 1).unwrap();
        assert!(load_day_log(&dir, missing, 5).unwrap().is_empty());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn prune_logs_keeps_only_today_entries() {
        let today = NaiveDate::from_ymd_opt(2026, 8, 25).unwrap();
        let yesterday = NaiveDate::from_ymd_opt(2026, 8, 24).unwrap();
        let mut entries = vec![
            LogEntry {
                date: yesterday,
                line: "舊".into(),
            },
            LogEntry {
                date: today,
                line: "新".into(),
            },
        ];
        prune_logs(&mut entries, today);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].line, "新");
    }

    #[test]
    fn cleanup_old_logs_removes_only_expired_dated_files() {
        let dir = temp_test_dir("cleanup");
        let today = NaiveDate::from_ymd_opt(2026, 8, 25).unwrap();
        let expired = dir.join(log_file_name(NaiveDate::from_ymd_opt(2026, 7, 1).unwrap()));
        let kept_recent = dir.join(log_file_name(NaiveDate::from_ymd_opt(2026, 8, 24).unwrap()));
        let kept_unparsed = dir.join("notes.log");
        for path in [&expired, &kept_recent, &kept_unparsed] {
            fs::write(path, "x").unwrap();
        }
        let removed = cleanup_old_logs(&dir, today, LOG_RETENTION_DAYS);
        assert_eq!(removed, 1);
        assert!(!expired.exists(), "超過保留天數的日誌應被刪除");
        assert!(kept_recent.exists(), "保留期內的日誌不應被刪");
        assert!(kept_unparsed.exists(), "非日期檔名一律跳過");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn dates_sorting_and_dedup_orders_oldest_first() {
        let d1 = NaiveDate::from_ymd_opt(2026, 8, 27).unwrap();
        let d2 = NaiveDate::from_ymd_opt(2026, 8, 25).unwrap();
        let d3 = NaiveDate::from_ymd_opt(2026, 8, 26).unwrap();
        let mut dates = vec![d1, d2, d3, d2];
        dates.sort_unstable();
        dates.dedup();
        assert_eq!(dates, vec![d2, d3, d1]);
    }

    #[test]
    fn last_seen_merging_keeps_maximum_uid_within_same_validity() {
        let current_last_seen = Some((1000u32, 500u32));
        // 手動掃描過去日期（最大 UID 為 300），不應降級目前進度 500
        let outcome_uidvalidity = 1000u32;
        let outcome_max_uid = 300u32;
        let updated = match current_last_seen {
            Some((validity, seen_max)) if validity == outcome_uidvalidity => {
                (validity, seen_max.max(outcome_max_uid))
            }
            _ => (outcome_uidvalidity, outcome_max_uid),
        };
        assert_eq!(updated, (1000, 500));

        // 手動/排程掃描到新信（最大 UID 為 600），應升級為 600
        let outcome_max_uid_new = 600u32;
        let updated_new = match current_last_seen {
            Some((validity, seen_max)) if validity == outcome_uidvalidity => {
                (validity, seen_max.max(outcome_max_uid_new))
            }
            _ => (outcome_uidvalidity, outcome_max_uid_new),
        };
        assert_eq!(updated_new, (1000, 600));

        // 信箱重建（UIDVALIDITY 變為 2000），應直接採用新 validity
        let outcome_new_validity = 2000u32;
        let updated_rebuild = match current_last_seen {
            Some((validity, seen_max)) if validity == outcome_new_validity => {
                (validity, seen_max.max(100))
            }
            _ => (outcome_new_validity, 100),
        };
        assert_eq!(updated_rebuild, (2000, 100));
    }

    #[test]
    fn llm_config_defaults_api_key_to_empty_when_absent() {
        let config: LlmConfig = toml::from_str(
            r#"
            base_url = "http://127.0.0.1:11434/v1"
            model = "llama3.1"
            "#,
        )
        .expect("缺 api_key 時應正常反序列化");
        assert_eq!(config.api_key, "");
        assert_eq!(config.base_url, "http://127.0.0.1:11434/v1");
        assert_eq!(config.model, "llama3.1");
    }

    #[test]
    fn llm_config_parses_api_key_when_present() {
        let config: LlmConfig = toml::from_str(
            r#"
            base_url = "https://api.openai.com/v1"
            model = "gpt-4o-mini"
            api_key = "sk-test123456"
            "#,
        )
        .expect("有 api_key 時應正常解析");
        assert_eq!(config.api_key, "sk-test123456");
    }
}
