#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::{
    fs,
    io::Write,
    panic::{AssertUnwindSafe, catch_unwind},
    path::{Path, PathBuf},
    sync::mpsc::{Receiver, TryRecvError},
    sync::{Arc, mpsc},
    thread,
    time::{Duration, Instant},
};

use antiphishing_core::*;
use anyhow::{Context, Result, bail};
use chrono::{DateTime, Datelike, Local, Months, NaiveDate, Weekday};
use eframe::egui::{self, ViewportCommand};
use mailparse::{MailHeaderMap, parse_mail};
use serde::{Deserialize, Serialize};
use single_instance::SingleInstance;
use tray_icon::{
    TrayIcon, TrayIconBuilder,
    menu::{Menu, MenuEvent, MenuItem},
};

mod theme;

const CONFIG_FILE_NAME: &str = "config.toml";
/// 連假或跨日追溯補掃的最高天數上限（避免無限回溯）
const MAX_CATCHUP_DAYS: i64 = 60;
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
    /// 外觀主題：system（跟隨系統）、light、dark
    #[serde(default = "default_theme")]
    theme: String,
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
fn default_theme() -> String {
    "system".into()
}
fn default_font_family() -> String {
    "Noto Sans TC".into()
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
                threshold: 8,
                suspicious_sender_domains: Vec::new(),
                trusted_sender_domains: Vec::new(),
                trusted_relay_ips: Vec::new(),
                suspicious_keywords: default_keywords(),
                external_word_image_score: 6,
            },
            gui: GuiConfig {
                check_interval_minutes: 10,
                minimize_to_tray: true,
                confirm_before_move: true,
                hide_taskbar_when_minimized: true,
                start_minimized_to_tray: false,
                font_family: default_font_family(),
                log_retention_days: default_log_retention_days(),
                theme: default_theme(),
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

/// 判斷應用程式的資料儲存目錄：
/// 1. 若當前執行檔同目錄下已存在 config.toml（如可攜模式、開發偵錯），優先以執行檔所在目錄為基準。
/// 2. 在 macOS 環境且處於 .app bundle 內部時，改用標準使用者目錄：
///    ~/Library/Application Support/AntiPhishing/
/// 3. 其他情況回退至執行檔所在目錄。
fn app_base_dir() -> PathBuf {
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            // 若執行檔旁邊已經有 config.toml，直接使用該目錄（優先支援本機開發或可攜模式）
            let local_config = exe_dir.join(CONFIG_FILE_NAME);
            if local_config.is_file() {
                return exe_dir.to_path_buf();
            }

            #[cfg(target_os = "macos")]
            {
                // 若位於 macOS App Bundle 內部（.../Contents/MacOS）
                let path_str = exe_path.to_string_lossy();
                if path_str.contains(".app/Contents/MacOS") {
                    if let Ok(home) = std::env::var("HOME") {
                        let app_support =
                            PathBuf::from(home).join("Library/Application Support/AntiPhishing");
                        let _ = fs::create_dir_all(&app_support);
                        return app_support;
                    }
                }
            }

            return exe_dir.to_path_buf();
        }
    }
    PathBuf::from(".")
}

/// 設定檔完整路徑：支援本機開發模式與 macOS App Bundle（儲存於 Application Support）。
fn config_path() -> PathBuf {
    let base = app_base_dir();
    let config = base.join(CONFIG_FILE_NAME);

    #[cfg(target_os = "macos")]
    if !config.exists() {
        // 若在 macOS .app 中且 ~/Library/Application Support/AntiPhishing/config.toml 尚不存在，
        // 嘗試自 App Bundle 內的 Resources 複製 config.example.toml 作為起始範本
        if let Ok(exe_path) = std::env::current_exe() {
            if let Some(bundle_dir) = exe_path.parent().and_then(|p| p.parent()) {
                let template = bundle_dir.join("Resources").join("config.example.toml");
                if template.is_file() {
                    let _ = fs::copy(&template, &config);
                }
            }
        }
    }

    config
}

// ===== 掃描進度檔（scan_state.toml）：跨重啟記住檢查斷點，避免重複檢查信件 =====

/// 待隔離郵件項目（儲存於待處理佇列中，亦持久化於 scan_state.toml）
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct PendingMoveItem {
    uid: u32,
    subject: String,
    score: u32,
    reason: String,
    #[serde(default = "default_true")]
    selected: bool,
}

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
    /// 待確認隔離的郵件清單（跨重啟保留）
    #[serde(default)]
    pending_moves: Vec<PendingMoveItem>,
}

/// 進度檔完整路徑：存於應用程式資料目錄下。
fn scan_state_path() -> PathBuf {
    app_base_dir().join("scan_state.toml")
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

/// 安全原子寫入檔案：先寫入同目錄暫存檔，寫入完成後再覆寫替換目標檔案，
/// 避免寫入中途因突發斷電或系統強制終止造成檔案被截斷為 0 位元組。
fn safe_write_file(path: &Path, content: &str) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("temp");
    let tmp_path = parent.join(format!(".{file_name}.tmp"));

    // 完整寫入暫存檔並落盤；沿用目標檔既有權限，新檔在 Unix 上預設僅擁有者可讀寫（內含帳密）
    let write_tmp = || -> std::io::Result<()> {
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let mut file = options.open(&tmp_path)?;
        file.write_all(content.as_bytes())?;
        if let Ok(meta) = fs::metadata(path) {
            file.set_permissions(meta.permissions())?;
        }
        file.sync_all()
    };

    // rename 在各平台（含 Windows）皆會直接取代既有目標檔，不需先刪除
    if let Err(err) = write_tmp().and_then(|()| fs::rename(&tmp_path, path)) {
        let _ = fs::remove_file(&tmp_path);
        return Err(err.into());
    }
    Ok(())
}

/// 寫入掃描進度檔（整檔覆寫；內容極小，透過 safe_write_file 安全原子寫入）。
fn save_scan_state(state: &LastScanState) -> Result<()> {
    safe_write_file(&scan_state_path(), &toml::to_string_pretty(state)?)?;
    Ok(())
}

// ===== 每日日誌檔（logs/YYYY-MM-DD.log） =====

/// 執行紀錄單筆條目：附所屬日期供 UI 只保留最後一天。
struct LogEntry {
    date: NaiveDate,
    line: String,
}

/// 日誌目錄：存於應用程式資料目錄下的 logs/（.gitignore 已涵蓋 *.log 與 logs/）。
fn log_dir() -> PathBuf {
    let dir = app_base_dir().join("logs");
    let _ = fs::create_dir_all(&dir);
    dir
}

/// 每日日誌檔名：`YYYY-MM-DD.log`。
/// 日期選擇按鈕：點擊後彈出小月曆，點選日期即套用並關閉
fn date_picker(ui: &mut egui::Ui, date: &mut NaiveDate, month: &mut NaiveDate) {
    let response = ui.button(format!("📅 {date}"));
    if response.clicked() {
        *month = date.with_day(1).unwrap_or(*date);
    }
    egui::Popup::from_toggle_button_response(&response)
        .close_behavior(egui::PopupCloseBehavior::CloseOnClickOutside)
        .show(|ui| {
            ui.horizontal(|ui| {
                if ui.button("◀").on_hover_text("上個月").clicked() {
                    *month = month.checked_sub_months(Months::new(1)).unwrap_or(*month);
                }
                ui.label(format!("{} 年 {} 月", month.year(), month.month()));
                if ui.button("▶").on_hover_text("下個月").clicked() {
                    *month = month.checked_add_months(Months::new(1)).unwrap_or(*month);
                }
            });
            egui::Grid::new("date_picker_grid").show(ui, |ui| {
                for name in ["日", "一", "二", "三", "四", "五", "六"] {
                    ui.label(name);
                }
                ui.end_row();
                for _ in 0..month.weekday().num_days_from_sunday() {
                    ui.label("");
                }
                for day in month.iter_days().take_while(|d| d.month() == month.month()) {
                    if ui
                        .selectable_label(day == *date, day.day().to_string())
                        .clicked()
                    {
                        *date = day;
                        ui.close();
                    }
                    if day.weekday() == Weekday::Sat {
                        ui.end_row();
                    }
                }
            });
            if ui.button("今天").clicked() {
                *date = Local::now().date_naive();
                ui.close();
            }
        });
}

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

/// 獨立搬移任務回報結果
struct MoveOutcome {
    lines: Vec<String>,
    moved_uids: Vec<u32>,
    failed_uids: Vec<u32>,
    not_found_uids: Vec<u32>,
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
    /// 本輪發現的疑似釣魚／惡意廣告郵件清單（若啟用確認，由 UI 入列處理）
    pending_moves: Vec<PendingMoveItem>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ActiveView {
    Dashboard,
    Settings(SettingsTab),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SettingsTab {
    Imap,
    Llm,
    Detection,
    Schedule,
}

struct App {
    config: Config,
    status: String,
    /// 目前顯示的視圖（主畫面或設定各大項）
    active_view: ActiveView,
    /// 儲存設定成功後的提示時間戳（用於暫時顯示已儲存提示）
    settings_saved_toast: Option<Instant>,
    /// 掃描進行中的即時進度（目前檢查哪封信）；空字串表示無掃描進行
    scan_progress: String,
    /// 執行紀錄（僅保留當日條目；完整歷史見每日日誌檔）
    logs: Vec<LogEntry>,
    /// 日誌檔寫入失敗時只提示一次的旗標
    log_error_reported: bool,
    /// 手動掃描指定的日期
    scan_date: NaiveDate,
    /// 日曆彈窗目前顯示的月份（該月 1 日）
    calendar_month: NaiveDate,
    next_check: Instant,
    receiver: Option<Receiver<ScanEvent>>,
    /// 待確認隔離的郵件清單（Queue/List，可跨重啟保留）
    pending_queue: Vec<PendingMoveItem>,
    /// 是否顯示隔離確認對話框
    show_confirm_dialog: bool,
    /// 獨立搬移任務的 receiver
    move_receiver: Option<Receiver<MoveOutcome>>,
    /// 搬移進行中的狀態提示
    move_status: String,
    tray: Option<Tray>,
    allow_exit: bool,
    startup_scan_pending: bool,
    hide_window_on_startup: bool,
    /// 從 IMAP 伺服器取得的信箱清單（原始 UTF-7 名稱）
    mailboxes: Vec<String>,
    /// 背景取得信箱清單的 receiver
    mailbox_receiver: Option<Receiver<Result<Vec<String>>>>,
    /// 取得信箱清單失敗時的錯誤訊息（供設定介面即時顯示）
    mailbox_fetch_error: Option<String>,
    /// 上次檢查到的最後一封郵件（UIDVALIDITY、最大 UID）；排程掃描藉此跳過無新郵件的一輪
    last_seen: Option<(u32, u32)>,
    /// 上次完成掃描的時間（含無新郵件的空掃），顯示於狀態列下方；跨重啟由進度檔回復
    last_check: Option<DateTime<Local>>,
    /// 最後完成判定的郵件（UID、主旨、所屬搜尋日期），顯示於狀態列下方
    last_mail: Option<(u32, String, NaiveDate)>,
    /// 偵測到疑似郵件彈出確認時的多幀焦點強制重試計數
    focus_restore_ticks: u8,
    /// 本機 .eml 路徑輸入框（檔案或資料夾）
    eml_path_text: String,
    /// .eml 判定進行中的 receiver（唯讀判定，不碰待搬移佇列與掃描狀態）
    eml_receiver: Option<Receiver<std::result::Result<Vec<EmlRow>, String>>>,
    /// 最近一次 .eml 判定結果（僅存記憶體，不寫日誌）
    eml_results: Vec<EmlRow>,
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
        theme::install_style(&cc.egui_ctx);
        theme::apply_theme(&cc.egui_ctx, &config.gui.theme);
        let tray = create_tray().ok();
        let (active_view, hide_window_on_startup, startup_scan_pending) =
            determine_initial_view(&config, tray.is_some());
        let config_invalid = matches!(active_view, ActiveView::Settings(_));
        if config_invalid {
            // 無設定或設定無效時：主動進入設定畫面，並強制顯示視窗避免靜默縮小到系統匣
            cc.egui_ctx
                .send_viewport_cmd(ViewportCommand::Visible(true));
        } else if config.gui.start_minimized_to_tray && !hide_window_on_startup {
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
        if config_invalid {
            status.push_str(" ⚠ 設定不完整，請先完成 IMAP 信箱等設定後儲存。");
        }
        let logs = backfill
            .into_iter()
            .map(|line| LogEntry { date: today, line })
            .collect();
        let last_seen = scan_state
            .as_ref()
            .map(|state| (state.uidvalidity, state.max_checked_uid));
        let pending_queue = scan_state
            .as_ref()
            .map(|state| state.pending_moves.clone())
            .unwrap_or_default();
        let show_confirm_dialog = !pending_queue.is_empty();
        Self {
            next_check: Instant::now() + interval(&config),
            config,
            status,
            active_view,
            settings_saved_toast: None,
            scan_progress: String::new(),
            logs,
            log_error_reported: false,
            scan_date: Local::now().date_naive(),
            calendar_month: Local::now().date_naive(),
            receiver: None,
            pending_queue,
            show_confirm_dialog,
            move_receiver: None,
            move_status: String::new(),
            tray,
            allow_exit: false,
            startup_scan_pending,
            hide_window_on_startup,
            mailboxes: Vec::new(),
            mailbox_receiver: None,
            mailbox_fetch_error: None,
            last_seen,
            last_check: scan_state.as_ref().map(|state| state.checked_at),
            last_mail: scan_state.map(|state| {
                (
                    state.last_mail_uid,
                    state.last_mail_subject,
                    state.last_mail_date,
                )
            }),
            focus_restore_ticks: 0,
            eml_path_text: String::new(),
            eml_receiver: None,
            eml_results: Vec::new(),
        }
    }

    /// 取得上次完成掃描的最後日期（優先使用最後檢查時間所屬日期，次選最後郵件日期）
    fn last_scanned_date(&self) -> Option<NaiveDate> {
        self.last_check
            .as_ref()
            .map(|dt| dt.date_naive())
            .or_else(|| self.last_mail.as_ref().map(|(_, _, date)| *date))
    }

    fn fetch_mailboxes(&mut self) {
        if self.mailbox_receiver.is_some() {
            return;
        }
        self.mailbox_fetch_error = None;
        if let Some(problem) = imap_credentials_problem(&self.config.imap) {
            self.mailbox_fetch_error = Some(problem.clone());
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
            safe_write_file(&config_path(), &text)?;
            Ok(())
        })();
        match result {
            Ok(()) => {
                self.status = "設定已儲存。".into();
                self.settings_saved_toast = Some(Instant::now());
            }
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

    /// 掃描結束後將最新進度寫回掃描進度檔（斷點＋最後一封郵件資訊＋待隔離清單）；失敗僅提示不中斷。
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
            pending_moves: self.pending_queue.clone(),
        };
        if let Err(error) = save_scan_state(&state)
            && !self.log_error_reported
        {
            self.log_error_reported = true;
            self.status = format!("掃描進度檔寫入失敗（不再重複提示）：{error:#}");
        }
    }

    /// 啟動獨立的隔離搬移任務（於獨立短暫的背景 IMAP 連線執行）
    fn start_move_task(&mut self, items: Vec<PendingMoveItem>) {
        if self.move_receiver.is_some() {
            self.status = "已有隔離搬移作業進行中，請稍候。".into();
            return;
        }
        if items.is_empty() {
            return;
        }
        let config = self.config.clone();
        let (sender, receiver) = mpsc::channel::<MoveOutcome>();
        self.move_receiver = Some(receiver);
        let count = items.len();
        self.move_status = format!("正在隔離搬移 {count} 封郵件中…");
        self.status = format!("正在隔離搬移 {count} 封郵件中…");
        thread::spawn(move || {
            let outcome =
                match catch_unwind(AssertUnwindSafe(|| execute_move_task(&config, &items))) {
                    Ok(Ok(outcome)) => outcome,
                    Ok(Err(error)) => MoveOutcome {
                        lines: vec![format!("隔離搬移失敗：{error:#}")],
                        moved_uids: Vec::new(),
                        failed_uids: items.iter().map(|i| i.uid).collect(),
                        not_found_uids: Vec::new(),
                    },
                    Err(panic) => {
                        let detail = panic
                            .downcast_ref::<&str>()
                            .map(|s| (*s).to_string())
                            .or_else(|| panic.downcast_ref::<String>().cloned())
                            .unwrap_or_else(|| "未知原因".into());
                        MoveOutcome {
                            lines: vec![format!("隔離搬移執行緒異常中止：{detail}")],
                            moved_uids: Vec::new(),
                            failed_uids: items.iter().map(|i| i.uid).collect(),
                            not_found_uids: Vec::new(),
                        }
                    }
                };
            let _ = sender.send(outcome);
        });
    }

    /// 跳過選取的待隔離郵件（不連線 IMAP，直接自清單移除）
    fn skip_pending_items(&mut self, uids: &[u32]) {
        if uids.is_empty() {
            return;
        }
        let uid_set: std::collections::HashSet<u32> = uids.iter().copied().collect();
        let log_lines: Vec<String> = self
            .pending_queue
            .iter()
            .filter(|item| uid_set.contains(&item.uid))
            .map(|item| {
                format!(
                    "跳過隔離〈{}〉（評分 {}；LLM：{}）",
                    item.subject, item.score, item.reason
                )
            })
            .collect();
        for line in log_lines {
            self.push_log(line);
        }
        self.pending_queue.retain(|i| !uid_set.contains(&i.uid));
        self.persist_scan_state();
        if self.pending_queue.is_empty() {
            self.show_confirm_dialog = false;
        }
    }

    fn start_scan(&mut self, scheduled: bool) {
        let date = self.scan_date;
        // 手動指定日期掃描時不帶 last_seen（執行全量檢查不套用 UID 過濾），排程掃描才帶 last_seen
        let last_seen = if scheduled { self.last_seen } else { None };
        // 自動納入前一日以消除伺服器 UTC 時差落差（例如臺灣 UTC+8 凌晨信件會落在伺服器前一日）
        self.start_scan_dates(startup_scan_dates(date).to_vec(), last_seen, scheduled);
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
        self.scan_progress.clear();
        self.status = if scheduled {
            "排程掃描中…".into()
        } else {
            "手動全量掃描中…".into()
        };
        thread::spawn(move || {
            // catch_unwind：worker panic 時仍回傳結果，避免 UI 端 receiver 永久卡住
            let outcome = match catch_unwind(AssertUnwindSafe(|| {
                scan_mail(&config, &dates, last_seen, &sender)
            })) {
                Ok(Ok(outcome)) => outcome,
                Ok(Err(error)) => ScanOutcome {
                    lines: vec![format!("掃描失敗：{error:#}")],
                    uidvalidity: 0,
                    max_checked_uid: None,
                    last_checked: None,
                    no_new_mail: false,
                    pending_moves: Vec::new(),
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
                        pending_moves: Vec::new(),
                    }
                }
            };
            let _ = sender.send(ScanEvent::Done(outcome));
        });
    }

    /// 啟動背景 .eml 判定（唯讀：不連 IMAP、不搬移、不更新掃描狀態）
    fn start_eml(&mut self, inputs: Vec<PathBuf>) {
        if self.eml_receiver.is_some() || self.receiver.is_some() {
            self.status = "已有掃描或 .eml 判定進行中，請稍候。".into();
            return;
        }
        let config = self.config.clone();
        let (sender, receiver) = mpsc::channel();
        self.eml_receiver = Some(receiver);
        self.status = "本機 .eml 判定中…".into();
        thread::spawn(move || {
            // catch_unwind：worker panic 時仍回傳結果，避免 UI 端 receiver 永久卡住
            let result =
                match catch_unwind(AssertUnwindSafe(|| evaluate_eml_batch(&inputs, &config))) {
                    Ok(Ok(rows)) => Ok(rows),
                    Ok(Err(error)) => Err(format!("{error:#}")),
                    Err(_) => Err("判定執行緒異常中止".to_string()),
                };
            let _ = sender.send(result);
        });
    }

    fn poll(&mut self, ctx: &egui::Context) {
        if self.hide_window_on_startup {
            self.hide_window_on_startup = false;
            ctx.send_viewport_cmd(ViewportCommand::Visible(false));
        }
        // 拖放 .eml（檔案或資料夾）到視窗即判定
        let dropped: Vec<PathBuf> = ctx.input(|i| {
            i.raw
                .dropped_files
                .iter()
                .filter_map(|f| f.path.clone())
                .collect()
        });
        if !dropped.is_empty() {
            self.active_view = ActiveView::Dashboard;
            self.start_eml(dropped);
        }
        match self.eml_receiver.as_ref().map(|rx| rx.try_recv()) {
            Some(Ok(Ok(rows))) => {
                self.eml_receiver = None;
                self.status = format!("已判定 {} 個 .eml（唯讀，未搬移任何郵件）。", rows.len());
                self.eml_results = rows;
            }
            Some(Ok(Err(error))) => {
                self.eml_receiver = None;
                self.status = format!(".eml 判定失敗：{error}");
            }
            Some(Err(TryRecvError::Disconnected)) => {
                self.eml_receiver = None;
                self.status = ".eml 判定執行緒意外結束。".into();
            }
            Some(Err(TryRecvError::Empty)) => {
                ctx.request_repaint_after(Duration::from_millis(200));
            }
            None => {}
        }
        if self.focus_restore_ticks > 0 {
            self.focus_restore_ticks -= 1;
            ctx.send_viewport_cmd(ViewportCommand::Visible(true));
            ctx.send_viewport_cmd(ViewportCommand::Minimized(false));
            ctx.send_viewport_cmd(ViewportCommand::Focus);
            ctx.request_repaint();
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
                }
                // 將本輪發現的待隔離郵件加入 pending_queue（去重）
                let mut new_pending_count = 0;
                for item in outcome.pending_moves {
                    if !self
                        .pending_queue
                        .iter()
                        .any(|existing| existing.uid == item.uid)
                    {
                        self.pending_queue.push(item);
                        new_pending_count += 1;
                    }
                }
                if new_pending_count > 0 {
                    let total_pending = self.pending_queue.len();
                    self.status = format!(
                        "掃描完成：目前有 {total_pending} 封疑似釣魚／惡意廣告郵件待確認隔離"
                    );
                    send_notification(
                        "AntiPhishing 偵測警告",
                        &format!(
                            "偵測到 {new_pending_count} 封疑似釣魚／惡意廣告郵件，請確認是否隔離。"
                        ),
                    );
                    self.show_confirm_dialog = true;
                    // 偵測到疑似釣魚／惡意廣告郵件需確認時：解除系統匣縮小/隱藏狀態，設定置頂、取得焦點並置中螢幕
                    ctx.send_viewport_cmd(ViewportCommand::WindowLevel(
                        egui::WindowLevel::AlwaysOnTop,
                    ));
                    ctx.send_viewport_cmd(ViewportCommand::Visible(true));
                    ctx.send_viewport_cmd(ViewportCommand::Minimized(false));
                    ctx.send_viewport_cmd(ViewportCommand::Focus);
                    ctx.send_viewport_cmd(ViewportCommand::RequestUserAttention(
                        egui::UserAttentionType::Critical,
                    ));
                    if let Some(cmd) = ViewportCommand::center_on_screen(ctx) {
                        ctx.send_viewport_cmd(cmd);
                    }
                    self.focus_restore_ticks = 3;
                    ctx.request_repaint();
                }
                // 本輪有新檢查進度時才寫回進度檔，重啟後即可從斷點續掃
                self.persist_scan_state();
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
            self.scan_progress.clear();
            // 若上次掃描日期早於今日（如連假或多日未確認），立即觸發補掃直到最新；否則排入正常間隔
            let today = Local::now().date_naive();
            let checked_today = self.last_check.map_or(false, |dt| dt.date_naive() == today);
            let needs_catchup =
                !checked_today && self.last_scanned_date().map_or(false, |d| d < today);
            self.next_check = if needs_catchup {
                Instant::now()
            } else {
                Instant::now() + interval(&self.config)
            };
        }
        // 處理獨立搬移任務接收
        if let Some(receiver) = &self.move_receiver {
            match receiver.try_recv() {
                Ok(outcome) => {
                    for line in &outcome.lines {
                        self.push_log(line.clone());
                    }
                    let moved_count = outcome.moved_uids.len();
                    let failed_count = outcome.failed_uids.len();
                    let removed_set: std::collections::HashSet<u32> = outcome
                        .moved_uids
                        .iter()
                        .chain(outcome.not_found_uids.iter())
                        .copied()
                        .collect();
                    self.pending_queue.retain(|i| !removed_set.contains(&i.uid));
                    if failed_count > 0 {
                        self.status = format!(
                            "隔離完成：成功搬移 {moved_count} 封，失敗 {failed_count} 封。"
                        );
                        send_notification(
                            "AntiPhishing 隔離結果",
                            &format!("成功搬移 {moved_count} 封，失敗 {failed_count} 封。"),
                        );
                    } else if moved_count > 0 {
                        self.status = format!("隔離完成：成功搬移 {moved_count} 封。");
                        send_notification(
                            "AntiPhishing 隔離完成",
                            &format!("已成功隔離搬移 {moved_count} 封疑似釣魚／惡意廣告郵件。"),
                        );
                    } else {
                        self.status = "隔離作業結束。".into();
                    }
                    if self.pending_queue.is_empty() {
                        self.show_confirm_dialog = false;
                        ctx.send_viewport_cmd(ViewportCommand::WindowLevel(
                            egui::WindowLevel::Normal,
                        ));
                    }
                    self.move_receiver = None;
                    self.move_status.clear();
                    self.persist_scan_state();
                }
                Err(TryRecvError::Disconnected) => {
                    self.status = "隔離搬移執行緒異常結束。".into();
                    self.push_log("隔離搬移執行緒異常結束。".into());
                    self.move_receiver = None;
                    self.move_status.clear();
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
                    self.mailbox_fetch_error = None;
                    self.status = format!("已成功取得 {count} 個信箱。");
                    self.mailbox_receiver = None;
                    ctx.request_repaint();
                }
                Ok(Err(err)) => {
                    let err_msg = format!("取得信箱清單失敗：{err:#}");
                    self.mailbox_fetch_error = Some(err_msg.clone());
                    self.status = err_msg;
                    self.mailbox_receiver = None;
                    ctx.request_repaint();
                }
                Err(TryRecvError::Disconnected) => {
                    let err_msg = "取得信箱清單失敗：背景執行緒異常結束。".to_string();
                    self.mailbox_fetch_error = Some(err_msg.clone());
                    self.status = err_msg;
                    self.mailbox_receiver = None;
                    ctx.request_repaint();
                }
                Err(TryRecvError::Empty) => {}
            }
        }
        if self.receiver.is_none() && self.move_receiver.is_none() && self.startup_scan_pending {
            self.startup_scan_pending = false;
            let today = Local::now().date_naive();
            self.scan_date = today;
            let dates = scan_dates_since_last(today, self.last_scanned_date());
            self.start_scan_dates(dates, self.last_seen, false);
        } else if self.receiver.is_none()
            && self.move_receiver.is_none()
            && Instant::now() >= self.next_check
        {
            let today = Local::now().date_naive();
            self.scan_date = today;
            // 排程定時掃描自上次掃描日期一路涵蓋至今日（防跨日與連假遺漏），並傳入 last_seen 斷點續掃
            let dates = scan_dates_since_last(today, self.last_scanned_date());
            self.start_scan_dates(dates, self.last_seen, true);
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
                if event.id == scan_id && self.receiver.is_none() && self.move_receiver.is_none() {
                    let today = Local::now().date_naive();
                    self.scan_date = today;
                    let dates = scan_dates_since_last(today, self.last_scanned_date());
                    self.start_scan_dates(dates, self.last_seen, false);
                }
                if event.id == quit_id {
                    self.allow_exit = true;
                    ctx.send_viewport_cmd(ViewportCommand::Close);
                }
            }
        }
        // 掃描、搬移或抓取信箱清單中提高重繪頻率，讓進度即時更新；閒置維持每秒一次
        ctx.request_repaint_after(
            if self.receiver.is_some()
                || self.move_receiver.is_some()
                || self.mailbox_receiver.is_some()
            {
                Duration::from_millis(300)
            } else {
                Duration::from_secs(1)
            },
        );
    }

    /// 搬移確認對話框
    fn show_move_confirmation(ctx: &egui::Context, app: &mut App) {
        let painter = ctx.layer_painter(egui::LayerId::new(
            egui::Order::Middle,
            egui::Id::new("modal_backdrop"),
        ));
        let screen_rect = ctx
            .input(|i| i.viewport().inner_rect)
            .unwrap_or(egui::Rect::EVERYTHING);
        painter.rect_filled(screen_rect, 0.0, egui::Color32::from_black_alpha(170));

        let visuals = ctx.global_style().visuals.clone();
        let pal = theme::palette(&visuals);
        let frame = egui::Frame::default()
            .fill(visuals.window_fill)
            .inner_margin(egui::Margin::same(20))
            .corner_radius(8)
            .stroke(egui::Stroke::new(2.0, pal.danger))
            .shadow(egui::Shadow {
                offset: [0, 8],
                blur: 16,
                spread: 0,
                color: egui::Color32::from_black_alpha(180),
            });

        let mut close_dialog = false;
        let mut trigger_move = false;
        let mut trigger_skip = false;
        let is_moving = app.move_receiver.is_some();

        egui::Window::new("隔離確認")
            .title_bar(false)
            .collapsible(false)
            .resizable(false)
            .frame(frame)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .default_size([650.0, 480.0])
            .order(egui::Order::Foreground)
            .show(ctx, |ui| {
                ui.spacing_mut().item_spacing = egui::vec2(8.0, 10.0);

                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new("⚠️ 偵測到疑似釣魚／惡意廣告郵件！")
                            .size(22.0)
                            .strong()
                            .color(pal.danger),
                    );
                });

                ui.label(
                    egui::RichText::new(format!(
                        "目前待隔離清單共 {} 封疑似郵件，請勾選要隔離（搬移至指定信箱）的項目，未勾選者將保留：",
                        app.pending_queue.len()
                    ))
                    .size(15.0)
                    .strong(),
                );

                // 批次勾選快捷按鈕列
                ui.horizontal(|ui| {
                    if ui.add_enabled(!is_moving, egui::Button::new("全選")).clicked() {
                        for item in &mut app.pending_queue {
                            item.selected = true;
                        }
                    }
                    if ui.add_enabled(!is_moving, egui::Button::new("全不選")).clicked() {
                        for item in &mut app.pending_queue {
                            item.selected = false;
                        }
                    }
                    if ui.add_enabled(!is_moving, egui::Button::new("反選")).clicked() {
                        for item in &mut app.pending_queue {
                            item.selected = !item.selected;
                        }
                    }
                    let selected_count = app.pending_queue.iter().filter(|i| i.selected).count();
                    ui.label(
                        egui::RichText::new(format!(
                            "（已選取 {} / {} 封）",
                            selected_count,
                            app.pending_queue.len()
                        ))
                        .color(pal.muted),
                    );
                });

                ui.separator();

                egui::ScrollArea::vertical()
                    .max_height(250.0)
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        for (idx, item) in app.pending_queue.iter_mut().enumerate() {
                            let item_frame = egui::Frame::group(ui.style())
                                .inner_margin(egui::Margin::symmetric(12, 8))
                                .stroke(egui::Stroke::new(
                                    1.0,
                                    if item.selected {
                                        pal.danger
                                    } else {
                                        visuals.widgets.noninteractive.bg_stroke.color
                                    },
                                ));

                            item_frame.show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    ui.add_enabled(!is_moving, egui::Checkbox::without_text(&mut item.selected));
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
                                                .color(pal.warn),
                                        );
                                    });
                                });
                            });
                            ui.add_space(4.0);
                        }
                    });

                ui.separator();

                if is_moving {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(
                            egui::RichText::new(&app.move_status)
                                .color(pal.danger)
                                .strong(),
                        );
                    });
                } else {
                    ui.horizontal(|ui| {
                        let selected_count = app.pending_queue.iter().filter(|i| i.selected).count();
                        let move_btn = egui::Button::new(
                            egui::RichText::new(format!("  🚨 隔離選取郵件 ({} 封)  ", selected_count))
                                .size(16.0)
                                .strong()
                                .color(egui::Color32::WHITE),
                        )
                        .fill(if selected_count > 0 {
                            egui::Color32::from_rgb(180, 40, 40)
                        } else {
                            visuals.widgets.inactive.weak_bg_fill
                        })
                        .min_size(egui::vec2(200.0, 38.0));

                        if ui.add_enabled(selected_count > 0, move_btn).clicked() {
                            trigger_move = true;
                        }

                        ui.add_space(8.0);

                        let skip_btn = egui::Button::new(egui::RichText::new("  全部跳過（不隔離）  ").size(15.0))
                            .min_size(egui::vec2(150.0, 38.0));

                        if ui.add(skip_btn).clicked() {
                            trigger_skip = true;
                        }

                        ui.add_space(8.0);

                        let later_btn = egui::Button::new(egui::RichText::new("  稍後處理  ").size(15.0))
                            .min_size(egui::vec2(100.0, 38.0));

                        if ui.add(later_btn).clicked() {
                            close_dialog = true;
                        }
                    });
                }
            });

        if trigger_move {
            let items: Vec<PendingMoveItem> = app
                .pending_queue
                .iter()
                .filter(|i| i.selected)
                .cloned()
                .collect();
            app.start_move_task(items);
        } else if trigger_skip {
            let all_uids: Vec<u32> = app.pending_queue.iter().map(|i| i.uid).collect();
            app.skip_pending_items(&all_uids);
            ctx.send_viewport_cmd(ViewportCommand::WindowLevel(egui::WindowLevel::Normal));
        } else if close_dialog {
            app.show_confirm_dialog = false;
            ctx.send_viewport_cmd(ViewportCommand::WindowLevel(egui::WindowLevel::Normal));
        }
    }

    fn ui_dashboard(&mut self, ui: &mut egui::Ui) {
        let pal = theme::palette(ui.visuals());

        // 頂部列：標題、深淺色切換與系統設定按鈕
        ui.horizontal(|ui| {
            ui.heading("AntiPhishing 郵件防護");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("⚙ 系統設定").clicked() {
                    self.active_view = ActiveView::Settings(SettingsTab::Imap);
                }
                let dark = ui.visuals().dark_mode;
                let (icon, hint) = if dark {
                    ("☀", "切換為淺色")
                } else {
                    ("🌙", "切換為深色")
                };
                if ui.button(icon).on_hover_text(hint).clicked() {
                    self.config.gui.theme = if dark { "light" } else { "dark" }.into();
                    theme::apply_theme(ui.ctx(), &self.config.gui.theme);
                }
            });
        });
        ui.add_space(6.0);

        // 待確認隔離提醒橫條
        if !self.pending_queue.is_empty() {
            egui::Frame::new()
                .fill(pal.danger.gamma_multiply(0.18))
                .stroke(egui::Stroke::new(1.0, pal.danger))
                .corner_radius(8)
                .inner_margin(egui::Margin::symmetric(12, 8))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| {
                        ui.label(
                            egui::RichText::new(format!(
                                "⚠ 目前有 {} 封疑似釣魚／惡意廣告郵件待確認隔離",
                                self.pending_queue.len()
                            ))
                            .color(pal.danger)
                            .strong(),
                        );
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.button("檢視並隔離").clicked() {
                                self.show_confirm_dialog = true;
                            }
                        });
                    });
                });
            ui.add_space(8.0);
        }

        // 狀態卡片：掃描進度只在這裡顯示一次
        theme::card(ui, "狀態", |ui| {
            if self.receiver.is_some() {
                ui.horizontal(|ui| {
                    ui.spinner();
                    let text = if self.scan_progress.is_empty() {
                        self.status.as_str()
                    } else {
                        self.scan_progress.as_str()
                    };
                    ui.label(egui::RichText::new(text).color(pal.warn).strong());
                });
            } else {
                ui.label(&self.status);
            }
            if self.move_receiver.is_some() {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(
                        egui::RichText::new(&self.move_status)
                            .color(pal.danger)
                            .strong(),
                    );
                });
            }
            // 上次完成掃描的時間（含無新郵件的空掃）；空掃不寫執行紀錄，只更新此處
            if let Some(last_check) = self.last_check {
                ui.label(
                    egui::RichText::new(format!(
                        "最後檢查時間：{}",
                        last_check.format("%Y-%m-%d %H:%M:%S")
                    ))
                    .small()
                    .color(pal.muted),
                );
            }
            // 跨重啟由進度檔回復的最後判定郵件資訊
            if let Some((uid, subject, mail_date)) = &self.last_mail {
                ui.label(
                    egui::RichText::new(format!(
                        "上次檢查至 UID {uid}〈{subject}〉（{mail_date}）"
                    ))
                    .small()
                    .color(pal.muted),
                );
            }
        });
        ui.add_space(8.0);

        // 掃描卡片：立即掃描、排程資訊與本機 .eml 判定
        theme::card(ui, "掃描", |ui| {
            ui.horizontal_wrapped(|ui| {
                // 掃描進行中停用按鈕，避免按下被靜默忽略
                let scan_busy = self.receiver.is_some();
                if ui
                    .add_enabled(!scan_busy, egui::Button::new("立即掃描指定日期"))
                    .clicked()
                {
                    self.start_scan(false);
                }
                ui.label("日期");
                date_picker(ui, &mut self.scan_date, &mut self.calendar_month);
                ui.label(
                    egui::RichText::new(format!(
                        "下次檢查：{} 秒後",
                        self.next_check
                            .saturating_duration_since(Instant::now())
                            .as_secs()
                    ))
                    .color(pal.muted),
                );
            });

            // 本機 .eml 判定（唯讀；可拖放檔案或資料夾到視窗）
            ui.separator();
            ui.horizontal(|ui| {
                let busy = self.eml_receiver.is_some() || self.receiver.is_some();
                ui.label("本機 .eml（可拖放到視窗）");
                ui.text_edit_singleline(&mut self.eml_path_text);
                let can_run = !busy && !self.eml_path_text.trim().is_empty();
                if ui
                    .add_enabled(can_run, egui::Button::new("判定 .eml"))
                    .clicked()
                {
                    let path = PathBuf::from(self.eml_path_text.trim().trim_matches('"'));
                    self.start_eml(vec![path]);
                }
                if self.eml_receiver.is_some() {
                    ui.spinner();
                }
            });
            if !self.eml_results.is_empty() {
                let threshold = self.config.detection.threshold;
                let mut clear = false;
                egui::CollapsingHeader::new(format!(
                    "本機 .eml 判定結果（{} 封，唯讀）",
                    self.eml_results.len()
                ))
                .default_open(true)
                .show(ui, |ui| {
                    if ui.small_button("清除結果").clicked() {
                        clear = true;
                    }
                    egui::ScrollArea::vertical()
                        .id_salt("eml_scroll_area")
                        .max_height(220.0)
                        .show(ui, |ui| {
                            for (name, result) in &self.eml_results {
                                match result {
                                    Ok(ev) => {
                                        let mark = if ev.flagged { "⚠" } else { "✔" };
                                        egui::CollapsingHeader::new(format!(
                                            "{mark} {}｜總分 {}｜{}",
                                            ev.subject.trim(),
                                            ev.final_score,
                                            name
                                        ))
                                        .id_salt(name)
                                        .show(ui, |ui| {
                                            ui.add(
                                                egui::Label::new(format_evaluation(
                                                    name, ev, threshold,
                                                ))
                                                .selectable(true),
                                            );
                                        });
                                    }
                                    Err(error) => {
                                        ui.label(
                                            egui::RichText::new(format!("✖ {name}：{error}"))
                                                .color(pal.danger),
                                        );
                                    }
                                }
                            }
                        });
                });
                if clear {
                    self.eml_results.clear();
                }
            }
        });
        ui.add_space(8.0);

        // 執行紀錄卡片（佔據剩餘垂直空間）
        theme::card(ui, "執行紀錄", |ui| {
            egui::ScrollArea::vertical()
                .id_salt("logs_scroll_area")
                .auto_shrink([false, false])
                .max_height(ui.available_height())
                .show(ui, |ui| {
                    if self.logs.is_empty() {
                        ui.label(egui::RichText::new("尚無執行紀錄").small().color(pal.muted));
                    } else {
                        for entry in self.logs.iter().rev().take(50) {
                            ui.label(egui::RichText::new(&entry.line).size(12.5));
                        }
                    }
                });
        });
    }

    fn ui_settings(&mut self, ui: &mut egui::Ui, current_tab: SettingsTab) {
        let pal = theme::palette(ui.visuals());
        // 頂部控制列：返回與儲存
        ui.horizontal(|ui| {
            if ui
                .button(egui::RichText::new("◀ 返回監控主畫面").strong())
                .clicked()
            {
                self.active_view = ActiveView::Dashboard;
            }

            ui.add_space(10.0);

            let save_button = egui::Button::new(
                egui::RichText::new("💾 儲存設定")
                    .strong()
                    .color(egui::Color32::WHITE),
            )
            .fill(pal.primary);
            if ui.add(save_button).clicked() {
                self.save();
            }

            if let Some(saved_at) = self.settings_saved_toast {
                if saved_at.elapsed() < Duration::from_secs(4) {
                    ui.label(
                        egui::RichText::new("✔ 設定已成功儲存")
                            .color(pal.ok)
                            .strong(),
                    );
                } else {
                    self.settings_saved_toast = None;
                }
            }
        });

        ui.separator();

        // 四大項導覽列
        ui.horizontal(|ui| {
            let tabs = [
                (SettingsTab::Imap, "📧 IMAP 信箱"),
                (SettingsTab::Llm, "🤖 LLM 智慧判定"),
                (SettingsTab::Detection, "🛡 偵測規則"),
                (SettingsTab::Schedule, "⏱ 排程與系統匣"),
            ];

            for (tab, label) in tabs {
                let is_selected = current_tab == tab;
                let rich_text = if is_selected {
                    egui::RichText::new(label).strong()
                } else {
                    egui::RichText::new(label)
                };
                let btn = egui::Button::new(rich_text).selected(is_selected);
                if ui.add(btn).clicked() {
                    self.active_view = ActiveView::Settings(tab);
                }
            }
        });

        ui.separator();

        // 細項設定內容區
        egui::ScrollArea::vertical()
            .id_salt("settings_tab_scroll")
            .auto_shrink([false, false])
            .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysVisible)
            .max_height(ui.available_height())
            .show(ui, |ui| {
                theme::card(ui, "", |ui| match current_tab {
                    SettingsTab::Imap => self.ui_settings_imap(ui),
                    SettingsTab::Llm => self.ui_settings_llm(ui),
                    SettingsTab::Detection => self.ui_settings_detection(ui),
                    SettingsTab::Schedule => self.ui_settings_schedule(ui),
                });
            });
    }

    fn ui_settings_imap(&mut self, ui: &mut egui::Ui) {
        let pal = theme::palette(ui.visuals());
        ui.heading("IMAP 信箱設定");
        ui.add_space(4.0);
        egui::Grid::new("imap_settings_grid")
            .num_columns(2)
            .min_col_width(130.0)
            .spacing([12.0, 8.0])
            .show(ui, |ui| {
                field(ui, "伺服器", &mut self.config.imap.host);
                ui.end_row();
                ui.label("連接埠");
                ui.add(egui::DragValue::new(&mut self.config.imap.port).range(1..=65535));
                ui.end_row();
                ui.label("協定");
                ui.horizontal(|ui| {
                    ui.radio_value(&mut self.config.imap.protocol, "imaps".into(), "IMAPS");
                    ui.radio_value(
                        &mut self.config.imap.protocol,
                        "starttls".into(),
                        "STARTTLS",
                    );
                });
                ui.end_row();
                field(ui, "帳號", &mut self.config.imap.username);
                ui.end_row();
                ui.label("密碼 / App Password");
                ui.add(egui::TextEdit::singleline(&mut self.config.imap.password).password(true));
                ui.end_row();
                ui.label("信箱清單");
                ui.vertical(|ui| {
                    ui.horizontal(|ui| {
                        let is_fetching = self.mailbox_receiver.is_some();
                        let btn_text = if is_fetching {
                            "取得中…"
                        } else {
                            "從伺服器取得信箱清單"
                        };
                        if ui
                            .add_enabled(!is_fetching, egui::Button::new(btn_text))
                            .clicked()
                        {
                            self.fetch_mailboxes();
                        }
                        if is_fetching {
                            ui.spinner();
                        } else if self.mailbox_fetch_error.is_none() && !self.mailboxes.is_empty() {
                            ui.label(
                                egui::RichText::new(format!(
                                    "✔ 已載入 {} 個信箱",
                                    self.mailboxes.len()
                                ))
                                .color(pal.ok),
                            );
                        }
                    });
                    if let Some(err) = &self.mailbox_fetch_error {
                        ui.add_space(2.0);
                        ui.add(
                            egui::Label::new(
                                egui::RichText::new(format!("❌ {err}"))
                                    .color(pal.danger)
                                    .strong(),
                            )
                            .wrap(),
                        );
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
        ui.add_space(8.0);
        ui.small("密碼會以明文儲存在 config.toml，請使用 App Password 並保護該檔案。");
    }

    fn ui_settings_llm(&mut self, ui: &mut egui::Ui) {
        ui.heading("LLM 智慧判定設定");
        ui.add_space(4.0);
        egui::Grid::new("llm_settings_grid")
            .num_columns(2)
            .spacing([12.0, 8.0])
            .show(ui, |ui| {
                ui.label("後端模式");
                let mut current_backend = self.config.llm.backend.clone().unwrap_or_else(|| {
                    if !self.config.llm.base_url.trim().is_empty() {
                        "api".to_string()
                    } else {
                        "claude".to_string()
                    }
                });
                egui::ComboBox::from_id_salt("llm_backend_select")
                    .selected_text(match current_backend.as_str() {
                        "claude" => "Claude Code CLI (claude)",
                        "agy" => "Antigravity CLI (agy)",
                        "codex" => "OpenAI Codex CLI (codex)",
                        "command" => "自訂命令列 (command)",
                        "jev" => "TypeSafe Jev / Ollama Nimble (jev)",
                        _ => "OpenAI 相容 HTTP API (api)",
                    })
                    .show_ui(ui, |ui| {
                        ui.selectable_value(
                            &mut current_backend,
                            "claude".into(),
                            "Claude Code CLI (claude)",
                        );
                        ui.selectable_value(
                            &mut current_backend,
                            "agy".into(),
                            "Antigravity CLI (agy)",
                        );
                        ui.selectable_value(
                            &mut current_backend,
                            "codex".into(),
                            "OpenAI Codex CLI (codex)",
                        );
                        ui.selectable_value(
                            &mut current_backend,
                            "api".into(),
                            "OpenAI 相容 HTTP API (api)",
                        );
                        ui.selectable_value(
                            &mut current_backend,
                            "jev".into(),
                            "TypeSafe Jev / Ollama Nimble (jev)",
                        );
                        ui.selectable_value(
                            &mut current_backend,
                            "command".into(),
                            "自訂命令列 (command)",
                        );
                    });
                self.config.llm.backend = Some(current_backend.clone());
                ui.end_row();

                let is_api = current_backend == "api";
                let is_cmd = current_backend == "command";
                let is_jev = current_backend == "jev";

                if is_cmd {
                    field(ui, "自訂命令", &mut self.config.llm.command);
                    ui.end_row();
                }

                if is_api || is_jev {
                    field(ui, "伺服器網址", &mut self.config.llm.base_url);
                    ui.end_row();
                    ui.label("API 金鑰");
                    ui.add(egui::TextEdit::singleline(&mut self.config.llm.api_key).password(true));
                    ui.end_row();
                }

                if is_jev {
                    ui.label("Jev 評分上限");
                    ui.add(egui::DragValue::new(&mut self.config.llm.jev_max_score).range(1..=50));
                    ui.end_row();
                    ui.label("Jev 起算機率");
                    ui.add(
                        egui::DragValue::new(&mut self.config.llm.jev_min_prob)
                            .range(0.0..=0.99)
                            .speed(0.01),
                    );
                    ui.end_row();
                }

                field(ui, "模型名稱", &mut self.config.llm.model);
                ui.end_row();

                ui.label("逾時（秒）");
                ui.add(egui::DragValue::new(&mut self.config.llm.timeout_secs).range(10..=600));
                ui.end_row();
                ui.label("內文最大字數");
                ui.add(egui::DragValue::new(&mut self.config.llm.max_chars).range(500..=50000));
                ui.end_row();
            });
        ui.add_space(8.0);
        match self.config.llm.effective_backend() {
            Some(LlmBackend::Claude) => {
                ui.small("✔ 使用本機 Claude Code CLI：直接使用已登入的 Claude 憑據，免填伺服器網址與金鑰；模型名稱留空則使用 CLI 預設模型。");
            }
            Some(LlmBackend::Agy) => {
                ui.small("✔ 使用本機 Antigravity CLI (agy)：直接使用本機 agy 憑據，免填伺服器網址與金鑰；模型名稱留空則使用 CLI 預設模型。");
            }
            Some(LlmBackend::Codex) => {
                ui.small("✔ 使用本機 OpenAI Codex CLI (codex)：沙箱唯讀執行；模型名稱留空則使用 CLI 預設模型。");
            }
            Some(LlmBackend::Command) => {
                ui.small("✔ 使用自訂命令列：將透過 stdin 送入 Prompt 並解析標準輸出回傳之判定。");
            }
            Some(LlmBackend::Api) => {
                ui.small("✔ 使用 OpenAI 相容 API：支援 Ollama / LM Studio 或雲端服務；地端免認證模型 API 金鑰可留空。");
            }
            Some(LlmBackend::Jev) => {
                ui.small("✔ 使用 TypeSafe Jev API (System One)：採混合評分制，Jev 評定釣魚機率換算為 0~分數上限並與安全規則加總判定；雲端 Jev 需 API 金鑰，地端 Ollama Nimble 請將模型名稱填 nimble、網址填 http://127.0.0.1:11434，金鑰可留空。");
            }
            None => {
                ui.small("⚠ LLM 判定未啟用（若欲使用請選擇 CLI 後端或填入 API 伺服器網址）。未啟用時不會搬移任何郵件。");
            }
        }
    }

    fn ui_settings_detection(&mut self, ui: &mut egui::Ui) {
        ui.heading("偵測規則設定");
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.label("判定門檻");
            ui.add(egui::DragValue::new(&mut self.config.detection.threshold).range(1..=100));
            ui.add_space(12.0);
            ui.label("Word 外部圖片分數");
            ui.add(
                egui::DragValue::new(&mut self.config.detection.external_word_image_score)
                    .range(0..=100),
            );
        });
        ui.add_space(8.0);
        multiline(
            ui,
            "可疑寄件網域（每行一個）",
            &mut self.config.detection.suspicious_sender_domains,
        );
        ui.add_space(6.0);
        multiline(
            ui,
            "信任寄件網域（每行一個）",
            &mut self.config.detection.trusted_sender_domains,
        );
        ui.add_space(6.0);
        multiline(
            ui,
            "信任來源 IP（最上層 Received，每行一個）",
            &mut self.config.detection.trusted_relay_ips,
        );
        ui.add_space(6.0);
        multiline(
            ui,
            "可疑關鍵字（每行一個）",
            &mut self.config.detection.suspicious_keywords,
        );
    }

    fn ui_settings_schedule(&mut self, ui: &mut egui::Ui) {
        ui.heading("排程與系統匣設定");
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.label("每隔（分鐘）");
            ui.add(
                egui::DragValue::new(&mut self.config.gui.check_interval_minutes).range(1..=1440),
            );
            ui.add_space(12.0);
            ui.label(format!(
                "下次檢查：{} 秒後",
                self.next_check
                    .saturating_duration_since(Instant::now())
                    .as_secs()
            ));
        });
        ui.add_space(6.0);
        ui.checkbox(
            &mut self.config.gui.minimize_to_tray,
            "關閉視窗時縮小至系統匣／選單列",
        );
        ui.checkbox(
            &mut self.config.gui.hide_taskbar_when_minimized,
            "縮小至系統匣／選單列時隱藏工作列／Dock 項目",
        );
        ui.checkbox(
            &mut self.config.gui.start_minimized_to_tray,
            "啟動時直接縮小至系統匣／選單列（下次啟動生效）",
        );
        ui.checkbox(
            &mut self.config.gui.confirm_before_move,
            "搬移前先確認（可個別選取要隔離的郵件）",
        );
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.label("外觀主題");
            let mut changed = false;
            egui::ComboBox::from_id_salt("theme_combo")
                .selected_text(theme::theme_label(&self.config.gui.theme))
                .show_ui(ui, |ui| {
                    for (value, label) in theme::THEME_CHOICES {
                        changed |= ui
                            .selectable_value(&mut self.config.gui.theme, value.to_string(), label)
                            .changed();
                    }
                });
            if changed {
                theme::apply_theme(ui.ctx(), &self.config.gui.theme);
            }
        });
        ui.horizontal(|ui| {
            ui.label("中文字型（重啟後套用）");
            ui.text_edit_singleline(&mut self.config.gui.font_family);
        });
        ui.add_space(8.0);
        ui.small("系統匣選單提供顯示視窗、立即掃描與結束程式。密碼會以明文儲存在 config.toml，請使用 App Password 並保護該檔案。");
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
        match self.active_view {
            ActiveView::Dashboard => self.ui_dashboard(ui),
            ActiveView::Settings(tab) => self.ui_settings(ui, tab),
        }

        // 搬移確認對話框：當有待隔離項目且 show_confirm_dialog 為 true 時繪製
        if self.show_confirm_dialog && !self.pending_queue.is_empty() {
            Self::show_move_confirmation(ui.ctx(), self);
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
        .add(egui::TextEdit::multiline(&mut text).desired_rows(4))
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

/// 判斷啟動時的初始視圖與旗標（無設定或設定無效時導向設定畫面）
fn determine_initial_view(config: &Config, tray_available: bool) -> (ActiveView, bool, bool) {
    let config_invalid = imap_credentials_problem(&config.imap).is_some()
        || imap_mailbox_problem(&config.imap).is_some();
    if config_invalid {
        (ActiveView::Settings(SettingsTab::Imap), false, false)
    } else {
        let hide_window = config.gui.start_minimized_to_tray && tray_available;
        (ActiveView::Dashboard, hide_window, true)
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

/// 將路徑開頭的 `~` 展開為使用者的家目錄路徑
fn expand_tilde(path_str: &str) -> PathBuf {
    if let Some(rest) = path_str.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    PathBuf::from(path_str)
}

#[cfg(target_os = "macos")]
/// 於 macOS 系統搜尋蘋方字型（PingFang.ttc）
fn find_macos_pingfang() -> Option<PathBuf> {
    let direct = Path::new("/System/Library/Fonts/PingFang.ttc");
    if direct.is_file() {
        return Some(direct.to_path_buf());
    }
    // 現代 macOS 將 PingFang 存放於 AssetsV2 目錄中
    let assets_dir = Path::new("/System/Library/AssetsV2");
    if let Ok(entries) = fs::read_dir(assets_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            if name
                .to_string_lossy()
                .starts_with("com_apple_MobileAsset_Font")
            {
                if let Ok(sub_entries) = fs::read_dir(entry.path()) {
                    for sub in sub_entries.flatten() {
                        let pingfang = sub.path().join("AssetData").join("PingFang.ttc");
                        if pingfang.is_file() {
                            return Some(pingfang);
                        }
                    }
                }
            }
        }
    }
    None
}

fn find_font(requested: &str) -> Option<(String, Vec<u8>)> {
    let requested = requested.trim();
    let expanded = expand_tilde(requested);
    let mut candidates: Vec<(String, PathBuf)> = if expanded.is_file() {
        vec![(requested.to_owned(), expanded)]
    } else {
        Vec::new()
    };

    let home = std::env::var("HOME").unwrap_or_default();
    let home_path = Path::new(&home);

    if requested.eq_ignore_ascii_case("noto sans tc") || requested == "思源黑體" {
        candidates.push((
            "Noto Sans TC".into(),
            home_path.join("Library/Fonts/NotoSansTC-Regular.otf"),
        ));
        candidates.push((
            "Noto Sans TC".into(),
            home_path.join("Library/Fonts/NotoSansTC-VF.ttf"),
        ));
        candidates.push((
            "Noto Sans TC".into(),
            PathBuf::from("/Library/Fonts/NotoSansTC-Regular.otf"),
        ));
        candidates.push((
            "Noto Sans TC".into(),
            PathBuf::from("/Library/Fonts/NotoSansTC-VF.ttf"),
        ));
        candidates.push((
            "Noto Sans TC".into(),
            PathBuf::from(r"C:\Windows\Fonts\NotoSansTC-VF.ttf"),
        ));
        candidates.push((
            "Noto Sans TC".into(),
            PathBuf::from("/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc"),
        ));
    } else if requested.eq_ignore_ascii_case("pingfang")
        || requested.eq_ignore_ascii_case("pingfang tc")
        || requested == "蘋方"
        || requested == "苹方"
    {
        #[cfg(target_os = "macos")]
        if let Some(pf) = find_macos_pingfang() {
            candidates.push(("PingFang".into(), pf));
        }
        candidates.push((
            "PingFang".into(),
            PathBuf::from("/System/Library/Fonts/PingFang.ttc"),
        ));
    } else if requested.eq_ignore_ascii_case("microsoft jhenghei") || requested == "微軟正黑體"
    {
        candidates.push((
            "Microsoft JhengHei".into(),
            PathBuf::from(r"C:\Windows\Fonts\msjh.ttc"),
        ));
        candidates.push((
            "Microsoft JhengHei".into(),
            home_path.join("Library/Fonts/msjh.ttc"),
        ));
        candidates.push((
            "Microsoft JhengHei".into(),
            PathBuf::from("/Library/Fonts/msjh.ttc"),
        ));
    } else if requested.eq_ignore_ascii_case("stheiti")
        || requested.eq_ignore_ascii_case("heiti")
        || requested == "黑體"
        || requested == "華文黑體"
    {
        candidates.push((
            "STHeiti".into(),
            PathBuf::from("/System/Library/Fonts/STHeiti Light.ttc"),
        ));
        candidates.push((
            "STHeiti".into(),
            PathBuf::from("/System/Library/Fonts/STHeiti Medium.ttc"),
        ));
    } else if requested.eq_ignore_ascii_case("songti")
        || requested == "宋體"
        || requested == "華文宋體"
    {
        candidates.push((
            "Songti".into(),
            PathBuf::from("/System/Library/Fonts/Supplemental/Songti.ttc"),
        ));
    } else if requested.eq_ignore_ascii_case("hiragino sans gb") || requested == "冬青黑體" {
        candidates.push((
            "Hiragino Sans GB".into(),
            PathBuf::from("/System/Library/Fonts/Hiragino Sans GB.ttc"),
        ));
    } else if requested.eq_ignore_ascii_case("arial unicode")
        || requested.eq_ignore_ascii_case("arial unicode ms")
    {
        candidates.push((
            "Arial Unicode".into(),
            PathBuf::from("/Library/Fonts/Arial Unicode.ttf"),
        ));
        candidates.push((
            "Arial Unicode".into(),
            PathBuf::from("/System/Library/Fonts/Supplemental/Arial Unicode.ttf"),
        ));
        candidates.push((
            "Arial Unicode".into(),
            PathBuf::from(r"C:\Windows\Fonts\ARIALUNI.TTF"),
        ));
    } else if requested.eq_ignore_ascii_case("dfkai-sb")
        || requested.eq_ignore_ascii_case("kaiu")
        || requested == "標楷體"
    {
        candidates.push((
            "DFKai-SB".into(),
            PathBuf::from(r"C:\Windows\Fonts\kaiu.ttf"),
        ));
        candidates.push(("DFKai-SB".into(), home_path.join("Library/Fonts/kaiu.ttf")));
    }

    // 指定字型不存在時，依作業系統環境退回系統內建的繁體中文字型，避免中文顯示為方框
    #[cfg(target_os = "macos")]
    {
        candidates.push((
            "Noto Sans TC".into(),
            home_path.join("Library/Fonts/NotoSansTC-Regular.otf"),
        ));
        candidates.push((
            "Noto Sans TC".into(),
            PathBuf::from("/Library/Fonts/NotoSansTC-Regular.otf"),
        ));
        if let Some(pf) = find_macos_pingfang() {
            candidates.push(("PingFang".into(), pf));
        }
        candidates.push((
            "PingFang".into(),
            PathBuf::from("/System/Library/Fonts/PingFang.ttc"),
        ));
        candidates.push((
            "STHeiti".into(),
            PathBuf::from("/System/Library/Fonts/STHeiti Light.ttc"),
        ));
        candidates.push((
            "STHeiti".into(),
            PathBuf::from("/System/Library/Fonts/STHeiti Medium.ttc"),
        ));
        candidates.push((
            "Hiragino Sans GB".into(),
            PathBuf::from("/System/Library/Fonts/Hiragino Sans GB.ttc"),
        ));
        candidates.push((
            "Songti".into(),
            PathBuf::from("/System/Library/Fonts/Supplemental/Songti.ttc"),
        ));
        candidates.push((
            "Arial Unicode".into(),
            PathBuf::from("/Library/Fonts/Arial Unicode.ttf"),
        ));
        candidates.push((
            "Microsoft JhengHei".into(),
            home_path.join("Library/Fonts/msjh.ttc"),
        ));
        candidates.push(("DFKai-SB".into(), home_path.join("Library/Fonts/kaiu.ttf")));
    }

    #[cfg(target_os = "windows")]
    {
        candidates.push((
            "Noto Sans TC".into(),
            PathBuf::from(r"C:\Windows\Fonts\NotoSansTC-VF.ttf"),
        ));
        candidates.push((
            "Microsoft JhengHei".into(),
            PathBuf::from(r"C:\Windows\Fonts\msjh.ttc"),
        ));
        candidates.push((
            "DFKai-SB".into(),
            PathBuf::from(r"C:\Windows\Fonts\kaiu.ttf"),
        ));
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        candidates.push((
            "Noto Sans CJK".into(),
            PathBuf::from("/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc"),
        ));
        candidates.push((
            "Noto Sans CJK".into(),
            PathBuf::from("/usr/share/fonts/noto-cjk/NotoSansCJK-Regular.ttc"),
        ));
        candidates.push((
            "Noto Sans TC".into(),
            PathBuf::from("/usr/share/fonts/truetype/noto/NotoSansTC-Regular.otf"),
        ));
        candidates.push((
            "Noto Sans TC".into(),
            home_path.join(".local/share/fonts/NotoSansTC-Regular.otf"),
        ));
    }

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

/// 執行獨立的隔離搬移任務（於獨立短暫的 IMAP session 中進行）
fn execute_move_task(config: &Config, items: &[PendingMoveItem]) -> Result<MoveOutcome> {
    let mut lines = Vec::new();
    let mut moved_uids = Vec::new();
    let mut failed_uids = Vec::new();
    let mut not_found_uids = Vec::new();

    let mut session = connect(&config.imap).context("無法連線至 IMAP 伺服器")?;
    let _ = session
        .select(&config.imap.source_mailbox)
        .with_context(|| format!("無法開啟來源信箱：{}", config.imap.source_mailbox))?;

    ensure_phishing_mailbox(&mut session, &config.imap.phishing_mailbox)
        .with_context(|| format!("目標信箱「{}」無法使用", config.imap.phishing_mailbox))?;

    let mut expunge_uids = Vec::new();
    for item in items {
        // 先以 UID SEARCH 檢查該郵件是否依然存在於來源信箱
        let exists = match session.uid_search(format!("UID {}", item.uid)) {
            Ok(uids) => uids.contains(&item.uid),
            Err(_) => true, // 若搜尋指令不支援或出錯，仍嘗試搬移
        };
        if !exists {
            lines.push(format!(
                "郵件 UID {}〈{}〉已不在來源信箱中（可能已於外部手動刪除），略過。",
                item.uid, item.subject
            ));
            not_found_uids.push(item.uid);
            continue;
        }

        match move_message(&mut session, item.uid, &config.imap.phishing_mailbox) {
            Ok(()) => {
                lines.push(format!(
                    "已隔離搬移〈{}〉（評分 {}；LLM：{}）",
                    item.subject, item.score, item.reason
                ));
                moved_uids.push(item.uid);
                expunge_uids.push(item.uid.to_string());
            }
            Err(error) => {
                let err_str = format!("{error:#}");
                if err_str.to_ascii_lowercase().contains("nonexistent")
                    || err_str.to_ascii_lowercase().contains("not found")
                    || err_str.to_ascii_lowercase().contains("no such message")
                {
                    lines.push(format!(
                        "郵件 UID {}〈{}〉搬移時伺服器回報不存在（可能已手動刪除），略過。",
                        item.uid, item.subject
                    ));
                    not_found_uids.push(item.uid);
                } else {
                    lines.push(format!("搬移〈{}〉失敗：{error:#}", item.subject));
                    failed_uids.push(item.uid);
                }
            }
        }
    }

    if !expunge_uids.is_empty() {
        let uid_set = expunge_uids.join(",");
        if let Err(error) = session.uid_expunge(&uid_set) {
            lines.push(format!("UID EXPUNGE 失敗（改用 EXPUNGE）：{error:#}"));
            if let Err(error) = session.expunge() {
                lines.push(format!("清除來源信箱中已搬移郵件失敗：{error:#}"));
            }
        }
    }

    session.logout().ok();

    Ok(MoveOutcome {
        lines,
        moved_uids,
        failed_uids,
        not_found_uids,
    })
}

/// 掃描指定日期郵件：逐封送 LLM 判定；
/// 若啟用 confirm_before_move，判定為釣魚/惡意廣告者放入待隔離清單，完成後立即結束並斷開連線；
/// 若未啟用，則於本輪中直接自動搬移。
fn scan_mail(
    config: &Config,
    dates: &[NaiveDate],
    last_seen: Option<(u32, u32)>,
    progress: &mpsc::Sender<ScanEvent>,
) -> Result<ScanOutcome> {
    let mut session = connect(&config.imap)?;
    let selected = session
        .select(&config.imap.source_mailbox)
        .with_context(|| format!("無法開啟來源信箱：{}", config.imap.source_mailbox))?;
    let original_uidvalidity = selected.uid_validity.unwrap_or(0);
    let llm = llm_config(&config.llm);
    let mut lines: Vec<String> = Vec::new();
    let mut scanned = 0;
    let mut max_checked_uid: Option<u32> = None;
    let mut last_checked: Option<(NaiveDate, u32, String)> = None;
    let mut pending: Vec<(u32, String, u32, String)> = Vec::new();
    let mut sorted_dates = dates.to_vec();
    sorted_dates.sort_unstable();
    sorted_dates.dedup();

    for date in &sorted_dates {
        let mut uids: Vec<u32> = session
            .uid_search(format!("ON {}", date.format("%d-%b-%Y")))
            .with_context(|| format!("搜尋 {date} 郵件失敗"))?
            .into_iter()
            .collect();
        uids.sort_unstable();
        uids = filter_new_uids(uids, last_seen, original_uidvalidity);
        // LLM 連續失敗熔斷：本日期內連續失敗 ≥3 次後，本輪剩餘信件直接採規則評分，
        // 避免 LLM 服務當機時每封都等待逾時上限。
        let mut llm_consecutive_failures: u32 = 0;
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
            // BODY.PEEK[] 依 RFC 3501 § 6.4.5 不會觸發 \Seen；RFC822 fallback 在多數伺服器上會。
            // 只在 fallback 路徑才還原未讀，避免對未讀信件多發一次無意義的 STORE。
            let (messages, used_fallback) =
                match session.uid_fetch(uid.to_string(), "(FLAGS BODY.PEEK[])") {
                    Ok(messages) => (messages, false),
                    Err(_) => match session.uid_fetch(uid.to_string(), "(FLAGS RFC822)") {
                        Ok(messages) => (messages, true),
                        Err(error) => {
                            lines.push(format!("無法讀取郵件 UID {uid}（略過）：{error:#}"));
                            continue;
                        }
                    },
                };
            let Some(message) = messages.iter().next() else {
                lines.push(format!("郵件 UID {uid} 內容為空或已被刪除，略過。"));
                continue;
            };
            // 記錄掃描當下是否為未讀取狀態（不含 \Seen 旗標）
            let was_unread = is_message_unread(message.flags());
            let Some(bytes) = message.body() else {
                lines.push(format!("郵件 UID {uid} 內容為空或已被刪除，略過。"));
                if used_fallback && was_unread {
                    let _ = restore_unread_status(&mut session, uid);
                }
                continue;
            };
            let mail = match parse_mail(bytes) {
                Ok(mail) => mail,
                Err(error) => {
                    lines.push(format!("無法解析郵件 UID {uid} 內容（略過）：{error:#}"));
                    if used_fallback && was_unread {
                        let _ = restore_unread_status(&mut session, uid);
                    }
                    continue;
                }
            };
            let from = mail.headers.get_first_value("From").unwrap_or_default();
            let subject = mail.headers.get_first_value("Subject").unwrap_or_default();
            let (body, score_body) = extract_body_text(&mail);
            scanned += 1;
            progress
                .send(ScanEvent::Progress(progress_text(
                    index + 1,
                    total,
                    &subject,
                )))
                .ok();
            let attachments = extract_attachment_filenames(&mail);
            let targets = external_word_image_targets(&mail);
            let auth_status = check_auth_status(&mail);
            let auth_warnings = auth_status.warnings.clone();
            let auth_summary = auth_status.summary();

            // 白名單直接安全豁免檢查：若寄件來源符合 trusted_sender_domains，且安全驗證無失敗警告，直接豁免跳過
            if let Some(matched) = trusted_source(&mail, &from, &config.detection) {
                if auth_warnings.is_empty() {
                    max_checked_uid = Some(max_checked_uid.map_or(uid, |seen| seen.max(uid)));
                    last_checked = Some((*date, uid, subject.clone()));
                    lines.push(format!(
                        "略過〈{}〉（寄件來源在信任清單：{}，且通過安全驗證）",
                        subject, matched
                    ));
                    if used_fallback && was_unread {
                        let _ = restore_unread_status(&mut session, uid);
                    }
                    continue;
                } else {
                    lines.push(format!(
                        "注意：〈{}〉寄件來源雖符合信任清單 ({})，但安全驗證失敗（{}），取消白名單豁免並送檢",
                        subject,
                        matched,
                        auth_warnings.join("；")
                    ));
                }
            }

            let (score, reasons) = phishing_score(
                &from,
                &subject,
                &score_body,
                &attachments,
                &targets,
                &auth_warnings,
                &config.detection,
            );
            match &llm {
                Some(llm_config) => {
                    if llm_config.effective_backend() == Some(LlmBackend::Jev) {
                        max_checked_uid = Some(max_checked_uid.map_or(uid, |seen| seen.max(uid)));
                        last_checked = Some((*date, uid, subject.clone()));
                        if llm_consecutive_failures >= 3 {
                            lines.push(format!(
                                "略過〈{}〉（Jev 連續失敗熔斷，採規則評分 {score}）",
                                subject
                            ));
                            if score >= config.detection.threshold {
                                let fallback_reason = format!(
                                    "Jev 熔斷；規則評分達標（{score}分）：{}",
                                    reasons.join("；")
                                );
                                pending.push((uid, subject.clone(), score, fallback_reason));
                            }
                        } else {
                            match llm_judge_jev(
                                llm_config,
                                &from,
                                &subject,
                                &body,
                                &attachments,
                                &targets,
                                &auth_summary,
                                &auth_warnings,
                            ) {
                                Ok(prob) => {
                                    let jev_points = calculate_jev_points(
                                        prob,
                                        llm_config.jev_max_score,
                                        llm_config.jev_min_prob,
                                    );
                                    let final_score = score + jev_points;
                                    let mut combined_reasons = reasons.clone();
                                    combined_reasons.push(format!(
                                        "Jev 評定釣魚機率 {:.0}%（+{jev_points}分）",
                                        prob * 100.0
                                    ));
                                    if final_score >= config.detection.threshold {
                                        pending.push((
                                            uid,
                                            subject.clone(),
                                            final_score,
                                            combined_reasons.join("；"),
                                        ));
                                    } else {
                                        lines.push(format!(
                                            "略過〈{}〉（評分 {final_score}，未達門檻；Jev 機率 {:.0}%）",
                                            subject,
                                            prob * 100.0
                                        ));
                                    }
                                }
                                Err(error) => {
                                    llm_consecutive_failures += 1;
                                    lines.push(format!(
                                        "Jev 判斷失敗（{error:#}），退回規則評分判定：〈{subject}〉"
                                    ));
                                    if score >= config.detection.threshold {
                                        let fallback_reason = format!(
                                            "Jev 判定失敗，退回規則評分達標（{score}分）：{}",
                                            reasons.join("；")
                                        );
                                        pending.push((
                                            uid,
                                            subject.clone(),
                                            score,
                                            fallback_reason,
                                        ));
                                    } else {
                                        lines.push(format!(
                                            "略過〈{}〉（評分 {score}，未達門檻；Jev 判定失敗）",
                                            subject
                                        ));
                                    }
                                }
                            }
                        }
                    } else if llm_consecutive_failures >= 3 {
                        // 熔斷：本日期內已連續失敗 ≥3 次，跳過 LLM 直接採規則評分
                        max_checked_uid = Some(max_checked_uid.map_or(uid, |seen| seen.max(uid)));
                        last_checked = Some((*date, uid, subject.clone()));
                        lines.push(format!(
                            "略過〈{}〉（LLM 連續失敗熔斷，採規則評分 {score}）",
                            subject
                        ));
                        if score >= config.detection.threshold {
                            let fallback_reason = format!(
                                "LLM 熔斷；規則評分達標（{score}分）：{}",
                                reasons.join("；")
                            );
                            pending.push((uid, subject.clone(), score, fallback_reason));
                        }
                    } else {
                        match llm_judge(
                            llm_config,
                            &from,
                            &subject,
                            &body,
                            &attachments,
                            &targets,
                            &auth_summary,
                            &auth_warnings,
                        ) {
                            Ok(verdict) => {
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
                                llm_consecutive_failures += 1;
                                max_checked_uid =
                                    Some(max_checked_uid.map_or(uid, |seen| seen.max(uid)));
                                last_checked = Some((*date, uid, subject.clone()));
                                lines.push(format!(
                                    "LLM 判斷失敗（{error:#}），退回規則評分判定：〈{subject}〉"
                                ));
                                if score >= config.detection.threshold {
                                    let fallback_reason = format!(
                                        "LLM 判定失敗，退回規則評分達標（{score}分）：{}",
                                        reasons.join("；")
                                    );
                                    pending.push((uid, subject.clone(), score, fallback_reason));
                                } else {
                                    lines.push(format!(
                                        "略過〈{}〉（評分 {score}，未達門檻；LLM 判定失敗）",
                                        subject
                                    ));
                                }
                            }
                        }
                    }
                }
                None => {
                    max_checked_uid = Some(max_checked_uid.map_or(uid, |seen| seen.max(uid)));
                    last_checked = Some((*date, uid, subject.clone()));
                }
            }
            if used_fallback && was_unread {
                let _ = restore_unread_status(&mut session, uid);
            }
        }
    }
    if scanned == 0 {
        session.logout().ok();
        return Ok(ScanOutcome {
            lines: Vec::new(),
            uidvalidity: original_uidvalidity,
            max_checked_uid: None,
            last_checked: None,
            no_new_mail: true,
            pending_moves: Vec::new(),
        });
    }

    let mut moved = 0;
    let mut failed = 0;
    let mut moved_uids: Vec<String> = Vec::new();
    let mut pending_moves = Vec::new();

    if config.gui.confirm_before_move {
        for (uid, subject, score, reason) in pending {
            lines.push(format!(
                "發現疑似釣魚／惡意廣告郵件〈{}〉（評分 {}；LLM：{}），已加入待隔離清單。",
                subject, score, reason
            ));
            pending_moves.push(PendingMoveItem {
                uid,
                subject,
                score,
                reason,
                selected: true,
            });
        }
    } else if !pending.is_empty() {
        // 未啟用確認：自動立即搬移
        if let Err(error) = ensure_phishing_mailbox(&mut session, &config.imap.phishing_mailbox) {
            lines.push(format!(
                "目標信箱「{}」無法使用，本輪取消搬移：{error:#}",
                config.imap.phishing_mailbox
            ));
        } else {
            for (uid, subject, score, reason) in pending {
                match move_message(&mut session, uid, &config.imap.phishing_mailbox) {
                    Ok(()) => {
                        lines.push(format!(
                            "自動搬移〈{}〉（評分 {}；LLM：{}）",
                            subject, score, reason
                        ));
                        moved += 1;
                        moved_uids.push(uid.to_string());
                    }
                    Err(error) => {
                        lines.push(format!("搬移〈{}〉失敗：{error:#}", subject));
                        failed += 1;
                    }
                }
            }
            if !moved_uids.is_empty() {
                let uid_set = moved_uids.join(",");
                if let Err(error) = session.uid_expunge(&uid_set) {
                    lines.push(format!("UID EXPUNGE 失敗（改用 EXPUNGE）：{error:#}"));
                    let _ = session.expunge();
                }
            }
        }
    }

    session.logout().ok();

    let scanned_dates = dates_summary(dates);
    if llm.is_none() {
        lines.push(format!(
            "LLM 未設定（未指定 backend = \"claude\" / \"agy\" 等 CLI 或 API 伺服器網址）。{scanned_dates}：已掃描 {scanned} 封，未搬移。"
        ));
    } else if config.gui.confirm_before_move {
        let found = pending_moves.len();
        let mut summary = format!("{scanned_dates}：已掃描 {scanned} 封");
        if found > 0 {
            summary.push_str(&format!("，發現 {found} 封待確認隔離"));
        }
        summary.push('。');
        lines.push(summary);
    } else {
        let mut summary = format!("{scanned_dates}：已掃描 {scanned} 封，自動搬移 {moved} 封");
        if failed > 0 {
            summary.push_str(&format!("，失敗 {failed} 封"));
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
        pending_moves,
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

fn startup_scan_dates(today: NaiveDate) -> [NaiveDate; 2] {
    [today - chrono::Duration::days(1), today]
}

/// 計算掃描日期清單：自上次掃描的郵件所屬日期（或預設前一日）一路涵蓋至今日，
/// 避免隔日或連續假期未掃描/未確認時產生遺漏。最高回溯上限為 `MAX_CATCHUP_DAYS` 天。
fn scan_dates_since_last(today: NaiveDate, last_date: Option<NaiveDate>) -> Vec<NaiveDate> {
    let earliest = today - chrono::Duration::days(MAX_CATCHUP_DAYS);
    let start_date = match last_date {
        Some(d) => d.min(today - chrono::Duration::days(1)).max(earliest),
        None => today - chrono::Duration::days(1),
    };
    let mut dates = Vec::new();
    let mut cur = start_date;
    while cur <= today {
        dates.push(cur);
        cur += chrono::Duration::days(1);
    }
    dates
}

/// .eml 批次判定結果列（檔名＋判定結果或錯誤訊息）
type EmlRow = (String, std::result::Result<MailEvaluation, String>);

/// 批次判定 .eml（唯讀；整批共用 LLM 熔斷計數）
fn evaluate_eml_batch(inputs: &[PathBuf], config: &Config) -> Result<Vec<EmlRow>> {
    let paths = collect_eml_paths(inputs)?;
    if paths.is_empty() {
        bail!("指定的路徑中沒有 .eml 檔");
    }
    let llm = llm_config(&config.llm);
    let mut failures: u32 = 0;
    Ok(paths
        .iter()
        .map(|path| {
            let result = evaluate_eml_file(path, &config.detection, &llm, &mut failures)
                .map_err(|e| format!("{e:#}"));
            (path.display().to_string(), result)
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn initial_view_routes_to_settings_when_config_is_invalid() {
        let mut config = Config::default();
        // 預設 config 的 host/username/password 為空，屬於無效設定
        let (view, hide_window, scan_pending) = determine_initial_view(&config, true);
        assert_eq!(view, ActiveView::Settings(SettingsTab::Imap));
        assert!(!hide_window, "無效設定時不得縮小隱藏視窗");
        assert!(!scan_pending, "無效設定時不得排程啟動掃描");

        // 填入憑據但無信箱名稱，仍為無效
        config.imap.host = "imap.example.com".into();
        config.imap.username = "user@example.com".into();
        config.imap.password = "secret".into();
        config.imap.source_mailbox = "".into();
        let (view2, _, _) = determine_initial_view(&config, true);
        assert_eq!(view2, ActiveView::Settings(SettingsTab::Imap));
    }

    #[test]
    fn initial_view_routes_to_dashboard_when_config_is_valid() {
        let mut config = Config::default();
        config.imap.host = "imap.example.com".into();
        config.imap.username = "user@example.com".into();
        config.imap.password = "secret".into();
        config.imap.source_mailbox = "INBOX".into();
        config.imap.phishing_mailbox = "Phishing".into();
        config.gui.start_minimized_to_tray = true;

        let (view, hide_window, scan_pending) = determine_initial_view(&config, true);
        assert_eq!(view, ActiveView::Dashboard);
        assert!(hide_window);
        assert!(scan_pending);
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
    fn scan_dates_since_last_covers_same_day_and_gap() {
        let today = NaiveDate::from_ymd_opt(2026, 8, 5).expect("固定測試日期");
        // 同一日檢查：涵蓋前一日與今日（與舊行為一致）
        assert_eq!(
            scan_dates_since_last(today, Some(today)),
            vec![
                NaiveDate::from_ymd_opt(2026, 8, 4).unwrap(),
                NaiveDate::from_ymd_opt(2026, 8, 5).unwrap(),
            ]
        );
        // 連假 4 天前（8 月 1 日）：自 8 月 1 日連續涵蓋到 8 月 5 日
        let last = NaiveDate::from_ymd_opt(2026, 8, 1).unwrap();
        assert_eq!(
            scan_dates_since_last(today, Some(last)),
            vec![
                NaiveDate::from_ymd_opt(2026, 8, 1).unwrap(),
                NaiveDate::from_ymd_opt(2026, 8, 2).unwrap(),
                NaiveDate::from_ymd_opt(2026, 8, 3).unwrap(),
                NaiveDate::from_ymd_opt(2026, 8, 4).unwrap(),
                NaiveDate::from_ymd_opt(2026, 8, 5).unwrap(),
            ]
        );
        // 無上次紀錄：回退至近兩日
        assert_eq!(
            scan_dates_since_last(today, None),
            vec![
                NaiveDate::from_ymd_opt(2026, 8, 4).unwrap(),
                NaiveDate::from_ymd_opt(2026, 8, 5).unwrap(),
            ]
        );
        // 超過 60 天以上未開機：限制最多回溯 MAX_CATCHUP_DAYS 天
        let ancient = NaiveDate::from_ymd_opt(2025, 1, 1).unwrap();
        let dates = scan_dates_since_last(today, Some(ancient));
        assert_eq!(dates.len(), (MAX_CATCHUP_DAYS + 1) as usize);
        assert_eq!(
            dates.first(),
            Some(&(today - chrono::Duration::days(MAX_CATCHUP_DAYS)))
        );
        assert_eq!(dates.last(), Some(&today));
    }

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
    fn pending_queue_deduplicates_by_uid() {
        let mut queue = vec![PendingMoveItem {
            uid: 101,
            subject: "信件A".into(),
            score: 3,
            reason: "垃圾推銷".into(),
            selected: true,
        }];
        let new_items = vec![
            PendingMoveItem {
                uid: 101,
                subject: "信件A重複".into(),
                score: 3,
                reason: "垃圾推銷".into(),
                selected: true,
            },
            PendingMoveItem {
                uid: 102,
                subject: "信件B".into(),
                score: 4,
                reason: "釣魚信件".into(),
                selected: true,
            },
        ];
        for item in new_items {
            if !queue.iter().any(|existing| existing.uid == item.uid) {
                queue.push(item);
            }
        }
        assert_eq!(queue.len(), 2);
        assert_eq!(queue[0].uid, 101);
        assert_eq!(queue[1].uid, 102);
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
    #[ignore = "需連線真實 IMAP 與 LLM 進行測試"]
    fn test_scan_live_date() {
        let config_str = std::fs::read_to_string("config.toml").expect("需有 config.toml");
        let config: Config = toml::from_str(&config_str).expect("需可解析 config.toml");
        let date = chrono::NaiveDate::from_ymd_opt(2026, 8, 19).unwrap();
        let (progress_tx, progress_rx) = mpsc::channel::<ScanEvent>();

        // 背景 thread：印出掃描進度
        thread::spawn(move || {
            while let Ok(event) = progress_rx.recv() {
                if let ScanEvent::Progress(text) = event {
                    println!("  [進度] {text}");
                }
            }
        });

        let outcome =
            scan_mail(&config, &[date], None, &progress_tx).expect("scan_mail 應成功執行");
        println!("\n=== 2026-08-19 掃描日誌結果 ===");
        for log in outcome.lines {
            println!("{log}");
        }
        for item in outcome.pending_moves {
            println!("  [待隔離] 主旨：{}，原因：{}", item.subject, item.reason);
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
            pending_moves: vec![PendingMoveItem {
                uid: 999,
                subject: "DHL：包裹待領取「引號」".into(),
                score: 5,
                reason: "釣魚郵件".into(),
                selected: true,
            }],
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
    fn needs_catchup_does_not_busy_loop_when_checked_today() {
        let today = NaiveDate::from_ymd_opt(2026, 9, 10).unwrap();
        // 假設今天已經檢查過（last_check 為今天），即使最後郵件是昨天的，也不應需要立即補掃
        let last_check_today = true;
        let last_scanned_yesterday = Some(NaiveDate::from_ymd_opt(2026, 9, 9).unwrap());
        let needs_catchup =
            !last_check_today && last_scanned_yesterday.map_or(false, |d| d < today);
        assert!(!needs_catchup);
    }

    #[test]
    fn pending_queue_removal_after_successful_move() {
        let mut queue = vec![
            PendingMoveItem {
                uid: 10,
                subject: "信件10".into(),
                score: 3,
                reason: "理由10".into(),
                selected: true,
            },
            PendingMoveItem {
                uid: 20,
                subject: "信件20".into(),
                score: 4,
                reason: "理由20".into(),
                selected: true,
            },
        ];
        let moved_uids = vec![10];
        let not_found_uids: Vec<u32> = vec![];
        let removed_set: std::collections::HashSet<u32> = moved_uids
            .iter()
            .chain(not_found_uids.iter())
            .copied()
            .collect();
        queue.retain(|i| !removed_set.contains(&i.uid));
        assert_eq!(queue.len(), 1);
        assert_eq!(queue[0].uid, 20);
    }

    #[test]
    fn test_safe_write_file_round_trip() {
        let dir = temp_test_dir("safewrite");
        let target = dir.join("test_config.toml");
        let content1 = "key = \"initial_value\"\n";
        safe_write_file(&target, content1).expect("初次安全寫入應成功");
        assert_eq!(fs::read_to_string(&target).unwrap(), content1);

        // 再次覆寫
        let content2 = "key = \"updated_value\"\n[section]\nenabled = true\n";
        safe_write_file(&target, content2).expect("覆寫安全寫入應成功");
        assert_eq!(fs::read_to_string(&target).unwrap(), content2);

        // Unix：新檔預設 0600，且覆寫後保留使用者設定的權限
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
            let fresh = dir.join("fresh.toml");
            safe_write_file(&fresh, content1).unwrap();
            assert_eq!(mode(&fresh), 0o600);
            fs::set_permissions(&target, fs::Permissions::from_mode(0o640)).unwrap();
            safe_write_file(&target, content1).unwrap();
            assert_eq!(mode(&target), 0o640);
        }

        // 確保無暫存殘留檔
        let tmp_file = dir.join(".test_config.toml.tmp");
        assert!(!tmp_file.exists(), "暫存檔應於替換後不存在");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_expand_tilde() {
        let home = std::env::var("HOME").unwrap_or_default();
        if !home.is_empty() {
            let expanded = expand_tilde("~/Library/Fonts/test.ttf");
            assert_eq!(
                expanded,
                PathBuf::from(&home).join("Library/Fonts/test.ttf")
            );
        }
        let regular = expand_tilde("/Library/Fonts/test.ttf");
        assert_eq!(regular, PathBuf::from("/Library/Fonts/test.ttf"));
    }

    #[test]
    fn test_find_font_cross_platform() {
        // 預設字型 "Noto Sans TC" 應能在具備中文字型的系統上成功找到（或自動退回系統繁中字型）
        let font_opt = find_font(&default_font_family());
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        {
            assert!(
                font_opt.is_some(),
                "在桌面系統上應能找到預設字型或退回系統繁中字型"
            );
            let (name, bytes) = font_opt.unwrap();
            assert!(!name.is_empty());
            assert!(!bytes.is_empty());
        }

        // 不存在的字型應退回到系統內建繁中字型，絕不應返回 None（避免豆腐塊）
        let fallback_opt = find_font("CompletelyNonExistentFont9999");
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        {
            assert!(
                fallback_opt.is_some(),
                "不存在的字型名稱應自動退回系統繁體中文字型"
            );
        }
    }

    #[test]
    fn test_apply_configured_font_and_cjk_rendering() {
        let ctx = egui::Context::default();
        let status = apply_configured_font(&ctx, &default_font_family());
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        {
            assert!(
                status.contains("已套用字型"),
                "預期套用成功，但得到：{status}"
            );

            let mut label_width = 0.0;
            let _ = ctx.run_ui(egui::RawInput::default(), |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    let resp = ui.label("繁體中文防釣魚軟體測試");
                    label_width = resp.rect.width();
                });
            });
            assert!(
                label_width > 0.0,
                "中文字元應能正常測量與渲染，寬度需大於 0"
            );
        }
    }

    #[test]
    fn test_app_base_dir_and_paths() {
        let base = app_base_dir();
        assert!(!base.as_os_str().is_empty());
        let config = config_path();
        assert!(config.ends_with(CONFIG_FILE_NAME));
        let scan_state = scan_state_path();
        assert!(scan_state.ends_with("scan_state.toml"));
        let logs = log_dir();
        assert!(logs.ends_with("logs"));
    }

    /// 建立 .eml 測試用設定（GUI 的 Config 需要 imap／gui 區段，內容與 .eml 判定無關）
    fn eml_test_config(extra_detection: &str) -> Config {
        toml::from_str(&format!(
            "[imap]\nhost = \"\"\nport = 993\nprotocol = \"imaps\"\nusername = \"\"\npassword = \"\"\nsource_mailbox = \"INBOX\"\nphishing_mailbox = \"Phish\"\n[gui]\n[detection]\n{extra_detection}\n"
        ))
        .unwrap()
    }

    #[test]
    fn evaluate_eml_batch_is_read_only_and_reports_per_file_errors() {
        let dir = std::env::temp_dir().join(format!("ap_gui_eml_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("a.eml"),
            "From: a@example.org\r\nSubject: hi\r\n\r\nbody\r\n",
        )
        .unwrap();
        let rows = evaluate_eml_batch(std::slice::from_ref(&dir), &eml_test_config("")).unwrap();
        assert_eq!(rows.len(), 1);
        assert!(rows[0].1.is_ok());
        // 空資料夾要明確報錯而不是靜默回傳空結果
        let empty = dir.join("empty");
        fs::create_dir_all(&empty).unwrap();
        assert!(evaluate_eml_batch(&[empty], &eml_test_config("")).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_imap_credentials_problem_and_mailbox_fetch_error_formatting() {
        let mut config = ImapConfig {
            host: String::new(),
            port: 993,
            protocol: "imaps".into(),
            username: "user".into(),
            password: "pwd".into(),
            source_mailbox: "INBOX".into(),
            phishing_mailbox: "Phishing".into(),
        };

        // 伺服器為空
        assert_eq!(
            imap_credentials_problem(&config).as_deref(),
            Some("請先填寫 IMAP 伺服器。")
        );

        // 帳號為空
        config.host = "imap.example.com".into();
        config.username = "  ".into();
        assert_eq!(
            imap_credentials_problem(&config).as_deref(),
            Some("請先填寫 IMAP 帳號。")
        );

        // 密碼為空
        config.username = "user".into();
        config.password = "".into();
        assert_eq!(
            imap_credentials_problem(&config).as_deref(),
            Some("請先填寫 IMAP 密碼。")
        );

        // 完整設定
        config.password = "secret".into();
        assert_eq!(imap_credentials_problem(&config), None);

        // 驗證錯誤格式化保留原因鏈
        let dns_err: Result<Vec<String>> = Err(anyhow::anyhow!("No such host is known")
            .context("無法解析 IMAP 伺服器位址：mail.invalid"));
        let err_msg = format!("取得信箱清單失敗：{:#}", dns_err.unwrap_err());
        assert!(err_msg.contains("無法解析 IMAP 伺服器位址"));
        assert!(err_msg.contains("No such host is known"));

        let auth_err: Result<Vec<String>> = Err(anyhow::anyhow!(
            "[AUTHENTICATIONFAILED] Invalid credentials"
        )
        .context("IMAP 登入失敗"));
        let err_msg = format!("取得信箱清單失敗：{:#}", auth_err.unwrap_err());
        assert!(err_msg.contains("IMAP 登入失敗"));
        assert!(err_msg.contains("[AUTHENTICATIONFAILED]"));
    }
}
