#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::{
    fs,
    io::{Cursor, Read},
    path::Path,
    sync::Arc,
    sync::mpsc::{self, Receiver},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use chrono::{Local, NaiveDate};
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

const CONFIG_PATH: &str = "config.toml";

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
    #[serde(default)]
    hide_taskbar_when_minimized: bool,
    #[serde(default)]
    start_minimized_to_tray: bool,
    #[serde(default = "default_font_family")]
    font_family: String,
}

fn default_interval_minutes() -> u64 {
    10
}
fn default_true() -> bool {
    true
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
                hide_taskbar_when_minimized: true,
                start_minimized_to_tray: false,
                font_family: default_font_family(),
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

fn main() -> eframe::Result {
    let single_instance = SingleInstance::new("anti-phishing-gui-instance-lock").ok();
    if let Some(ref instance) = single_instance {
        if !instance.is_single() {
            return Ok(());
        }
    }

    let (config, status) = match load_config() {
        Ok(config) => (config, "已載入設定檔。".into()),
        Err(error) => (Config::default(), format!("使用預設設定：{error}")),
    };
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

struct App {
    config: Config,
    status: String,
    logs: Vec<String>,
    date_text: String,
    next_check: Instant,
    receiver: Option<Receiver<Vec<String>>>,
    tray: Option<Tray>,
    allow_exit: bool,
    startup_scan_pending: bool,
    hide_window_on_startup: bool,
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
        Self {
            next_check: Instant::now() + interval(&config),
            config,
            status: format!("{status} {font_status}"),
            logs: Vec::new(),
            date_text: Local::now().date_naive().to_string(),
            receiver: None,
            tray,
            allow_exit: false,
            startup_scan_pending: true,
            hide_window_on_startup,
        }
    }

    fn save(&mut self) {
        let result: Result<()> = (|| {
            let text = toml::to_string_pretty(&self.config)?;
            fs::write(CONFIG_PATH, text)?;
            Ok(())
        })();
        match result {
            Ok(()) => self.status = "設定已儲存。".into(),
            Err(error) => self.status = format!("儲存失敗：{error}"),
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
        self.start_scan_dates(vec![date], scheduled);
    }

    fn start_scan_dates(&mut self, dates: Vec<NaiveDate>, scheduled: bool) {
        if self.receiver.is_some() || dates.is_empty() {
            return;
        }
        let config = self.config.clone();
        let (sender, receiver) = mpsc::channel();
        self.receiver = Some(receiver);
        self.status = if dates.len() > 1 {
            "啟動掃描前一日與今日郵件中…".into()
        } else if scheduled {
            "排程掃描中…".into()
        } else {
            "手動掃描中…".into()
        };
        thread::spawn(move || {
            let _ = sender.send(
                scan_mail(&config, &dates)
                    .unwrap_or_else(|error| vec![format!("掃描失敗：{error:#}")]),
            );
        });
    }

    fn poll(&mut self, ctx: &egui::Context) {
        if self.hide_window_on_startup {
            self.hide_window_on_startup = false;
            ctx.send_viewport_cmd(ViewportCommand::Visible(false));
        }
        if let Some(receiver) = &self.receiver {
            if let Ok(results) = receiver.try_recv() {
                self.logs.extend(results.iter().cloned());
                self.status = results.last().cloned().unwrap_or_default();
                self.receiver = None;
                self.next_check = Instant::now() + interval(&self.config);
            }
        }
        if self.receiver.is_none() && self.startup_scan_pending {
            self.startup_scan_pending = false;
            let today = Local::now().date_naive();
            self.date_text = today.to_string();
            self.start_scan_dates(startup_scan_dates(today).to_vec(), false);
        } else if self.receiver.is_none() && Instant::now() >= self.next_check {
            self.date_text = Local::now().date_naive().to_string();
            self.start_scan(true);
        }
        if let Some(tray) = &self.tray {
            let show_id = tray.show.id().clone();
            let scan_id = tray.scan.id().clone();
            let quit_id = tray.quit.id().clone();
            while let Ok(event) = MenuEvent::receiver().try_recv() {
                if event.id == show_id {
                    ctx.send_viewport_cmd(ViewportCommand::Visible(true));
                    ctx.send_viewport_cmd(ViewportCommand::Focus);
                }
                if event.id == scan_id {
                    self.date_text = Local::now().date_naive().to_string();
                    self.start_scan(false);
                }
                if event.id == quit_id {
                    self.allow_exit = true;
                    ctx.send_viewport_cmd(ViewportCommand::Close);
                }
            }
        }
        ctx.request_repaint_after(Duration::from_secs(1));
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
        egui::CentralPanel::default().show(ui, |ui| {
            ui.heading("AntiPhishing 郵件防護");
            ui.label(&self.status);
            ui.separator();
            ui.heading("IMAP 信箱");
            egui::Grid::new("imap").num_columns(2).show(ui, |ui| {
                field(ui, "伺服器", &mut self.config.imap.host);
                ui.label("連接埠");
                ui.add(egui::DragValue::new(&mut self.config.imap.port).range(1..=65535));
                ui.end_row();
                ui.label("協定"); ui.horizontal(|ui| { ui.radio_value(&mut self.config.imap.protocol, "imaps".into(), "IMAPS"); ui.radio_value(&mut self.config.imap.protocol, "starttls".into(), "STARTTLS"); }); ui.end_row();
                field(ui, "帳號", &mut self.config.imap.username); ui.end_row();
                ui.label("密碼 / App Password"); ui.add(egui::TextEdit::singleline(&mut self.config.imap.password).password(true)); ui.end_row();
                field(ui, "來源信箱", &mut self.config.imap.source_mailbox); ui.end_row();
                field(ui, "釣魚信箱", &mut self.config.imap.phishing_mailbox); ui.end_row();
            });
            ui.separator(); ui.heading("偵測規則");
            ui.horizontal(|ui| { ui.label("判定門檻"); ui.add(egui::DragValue::new(&mut self.config.detection.threshold).range(1..=100)); ui.label("Word 外部圖片分數"); ui.add(egui::DragValue::new(&mut self.config.detection.external_word_image_score).range(0..=100)); });
            multiline(ui, "可疑寄件網域（每行一個）", &mut self.config.detection.suspicious_sender_domains);
            multiline(ui, "信任寄件網域（每行一個）", &mut self.config.detection.trusted_sender_domains);
            multiline(ui, "可疑關鍵字（每行一個）", &mut self.config.detection.suspicious_keywords);
            ui.separator(); ui.heading("排程與系統匣");
            ui.horizontal(|ui| { ui.label("每隔（分鐘）"); ui.add(egui::DragValue::new(&mut self.config.gui.check_interval_minutes).range(1..=1440)); ui.label(format!("下次檢查：{} 秒後", self.next_check.saturating_duration_since(Instant::now()).as_secs())); });
            ui.checkbox(&mut self.config.gui.minimize_to_tray, "關閉視窗時縮小至 Windows 系統匣");
            ui.checkbox(&mut self.config.gui.hide_taskbar_when_minimized, "縮小至系統匣時隱藏工作列項目");
            ui.checkbox(&mut self.config.gui.start_minimized_to_tray, "啟動時直接縮小至 Windows 系統匣（下次啟動生效）");
            ui.horizontal(|ui| {
                ui.label("中文字型（重啟後套用）");
                ui.text_edit_singleline(&mut self.config.gui.font_family);
            });
            ui.small("系統匣選單提供顯示視窗、立即掃描與結束程式。密碼會以明文儲存在 config.toml，請使用 App Password 並保護該檔案。");
            ui.separator();
            ui.horizontal(|ui| { if ui.button("儲存設定").clicked() { self.save(); } if ui.button("立即掃描指定日期").clicked() { self.start_scan(false); } ui.label("日期"); ui.text_edit_singleline(&mut self.date_text); });
            if !self.logs.is_empty() { ui.separator(); ui.heading("執行紀錄"); egui::ScrollArea::vertical().max_height(120.0).show(ui, |ui| for log in self.logs.iter().rev().take(20) { ui.label(log); }); }
        });
    }
}

fn field(ui: &mut egui::Ui, name: &str, value: &mut String) {
    ui.label(name);
    ui.text_edit_singleline(value);
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
fn load_config() -> Result<Config> {
    let text = fs::read_to_string(CONFIG_PATH).context("找不到 config.toml")?;
    toml::from_str(&text).context("config.toml 格式不正確")
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
    let candidates = if Path::new(requested).is_file() {
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

/// 送 LLM 判斷的 system 提示：要求嚴格 JSON 輸出，不確定一律判 false。
const LLM_SYSTEM_PROMPT: &str = "你是郵件安全判官。根據使用者提供的郵件內容，判斷該郵件是否為釣魚、詐欺或詐騙郵件。高風險訊號包括：偽裝機構（寄件網域非其所稱品牌如 DHL、FedEx、快遞、銀行的官方網域）、要求付款或繳費（關稅、手續費、驗證費）、要求提供帳號密碼、緊急施壓、可疑連結、附件追蹤、內含 QR code 或要求用手機掃描（quishing）、籠統稱呼（如「親愛的顧客」）搭配假單號或要求更新地址/電話。僅輸出嚴格 JSON，不要任何其他文字：{\"is_phishing\": true 或 false, \"reason\": \"簡短理由\"}。若證據不足或不確定，is_phishing 必須為 false。";

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
        if let Some(body) = decode_part_text(mail) {
            if !body.is_empty() {
                if mime == "text/plain" {
                    plain.push_str(&body);
                    plain.push('\n');
                } else if mime == "text/html" {
                    html.push_str(&body);
                }
            }
        }
    }
    for part in &mail.subparts {
        collect_text_parts(part, plain, html);
    }
}

/// HTML 轉純文字：移除 style/script、base64 內嵌圖（保留 img 的 alt 文字，
/// 例如「QR Code」），剝離其餘標籤並解譯常見實體字。
fn html_to_text(html: &str) -> String {
    let text = Regex::new(r"(?is)<style\b.*?</style>|<script\b.*?</script>")
        .expect("固定正規表示式")
        .replace_all(html, " ");
    // base64 內嵌圖（data: URI）是巨量噪音，先移除
    let text = Regex::new(r#"data:[^"'\s>]+"#)
        .expect("固定正規表示式")
        .replace_all(&text, " ");
    // 保留 img 的 alt 文字（如 QR Code），其餘屬性丟棄
    let text = Regex::new(r#"(?is)<img\b[^>]*?\balt="([^"]*)"[^>]*>"#)
        .expect("固定正規表示式")
        .replace_all(&text, " [$1] ");
    let text = Regex::new(r"<[^>]+>")
        .expect("固定正規表示式")
        .replace_all(&text, " ");
    let text = text
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&nbsp;", " ");
    let text = Regex::new(r"[ \t\r\f\v]+")
        .expect("固定正規表示式")
        .replace_all(&text, " ");
    Regex::new(r"\n{3,}")
        .expect("固定正規表示式")
        .replace_all(&text, "\n\n")
        .into_owned()
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

/// 解析 LLM 回傳的判定 JSON；容許 ```json 圍欄；解析失敗回 Err。
fn parse_llm_verdict(text: &str) -> Result<LlmVerdict> {
    let mut text = text.trim();
    if let Some(stripped) = text.strip_prefix("```") {
        // 剝離開頭圍欄（含選填的 json 標籤）
        let rest = stripped
            .strip_prefix("json")
            .unwrap_or(stripped)
            .trim_start();
        text = rest;
    }
    // 剝離結尾圍欄
    if let Some(index) = text.rfind("```") {
        text = text[..index].trim();
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
    // ureq 3.x 的逾時設在 Agent 上（timeout_global 涵蓋整個請求）
    let agent_config = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(config.timeout_secs)))
        .build();
    let agent = ureq::Agent::new_with_config(agent_config);
    let mut response = agent
        .post(&url)
        .send_json(payload)
        .map_err(|error| anyhow::anyhow!("LLM 請求失敗：{error}"))?;
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

/// 掃描指定日期郵件：逐封送 LLM 判定，判定為釣魚者搬移至 phishing_mailbox。
/// 回傳逐封 log 行（最後一行為總計）。LLM 未設定或判定失敗時不搬移。
fn scan_mail(config: &Config, dates: &[NaiveDate]) -> Result<Vec<String>> {
    let mut session = connect(&config.imap)?;
    session
        .select(&config.imap.source_mailbox)
        .with_context(|| format!("無法開啟來源信箱：{}", config.imap.source_mailbox))?;
    let llm = llm_config(config);
    let mut lines: Vec<String> = Vec::new();
    let mut scanned = 0;
    let mut moved = 0;
    for date in dates {
        let uids = session
            .uid_search(format!("ON {}", date.format("%d-%b-%Y")))
            .with_context(|| format!("搜尋 {date} 郵件失敗"))?;
        for uid in uids {
            let messages = session.uid_fetch(uid.to_string(), "RFC822")?;
            let Some(bytes) = messages.iter().next().and_then(|message| message.body()) else {
                continue;
            };
            let mail = parse_mail(bytes).context("無法解析郵件內容")?;
            let from = mail.headers.get_first_value("From").unwrap_or_default();
            let subject = mail.headers.get_first_value("Subject").unwrap_or_default();
            // mailparse 對 multipart 的 get_body() 回傳空，改從 subparts 提取
            let (body, score_body) = extract_body_text(&mail);
            scanned += 1;
            let targets = external_word_image_targets(&mail);
            // 現行啟發式評分僅供 log 參考，不再作為搬移依據
            let (score, _) =
                phishing_score(&from, &subject, &score_body, &targets, &config.detection);
            let Some(llm_config) = &llm else {
                continue;
            };
            match llm_judge(llm_config, &from, &subject, &body, &targets) {
                Ok(verdict) if verdict.is_phishing => {
                    move_message(&mut session, uid, &config.imap.phishing_mailbox)?;
                    moved += 1;
                    lines.push(format!(
                        "搬移〈{}〉（評分 {}；LLM：{}）",
                        subject, score, verdict.reason
                    ));
                }
                Ok(verdict) => {
                    lines.push(format!(
                        "略過〈{}〉（評分 {}；LLM：{}）",
                        subject, score, verdict.reason
                    ));
                }
                Err(error) => {
                    lines.push(format!("LLM 判斷失敗，略過〈{}〉：{error:#}", subject));
                }
            }
        }
    }
    if moved > 0 {
        session.expunge().context("刪除來源信箱中已搬移郵件失敗")?;
    }
    session.logout().ok();
    let scanned_dates = dates
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("、");
    if llm.is_none() {
        lines.push(format!(
            "LLM 未設定（config.toml 的 [llm] base_url 或 model 為空）。{scanned_dates}：已掃描 {scanned} 封，未搬移。"
        ));
    } else {
        lines.push(format!(
            "{scanned_dates}：已掃描 {scanned} 封，搬移 {moved} 封疑似釣魚郵件。"
        ));
    }
    Ok(lines)
}

fn startup_scan_dates(today: NaiveDate) -> [NaiveDate; 2] {
    [today - chrono::Duration::days(1), today]
}

fn connect(config: &ImapConfig) -> Result<Session<imap::Connection>> {
    let mode = match config.protocol.as_str() {
        "imaps" => imap::ConnectionMode::Tls,
        "starttls" => imap::ConnectionMode::StartTls,
        other => bail!("不支援的 protocol：{other}"),
    };
    let client = imap::ClientBuilder::new(config.host.as_str(), config.port)
        .mode(mode)
        .connect()
        .context("IMAP TLS 連線失敗")?;
    client
        .login(&config.username, &config.password)
        .map_err(|error| error.0.into())
}
fn move_message(session: &mut Session<imap::Connection>, uid: u32, target: &str) -> Result<()> {
    session
        .uid_copy(uid.to_string(), target)
        .with_context(|| format!("無法複製郵件到：{target}"))?;
    session.uid_store(uid.to_string(), "+FLAGS.SILENT (\\Deleted)")?;
    Ok(())
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
    let links = Regex::new(r"https?://")
        .expect("固定正規表示式")
        .find_iter(&text)
        .count();
    if links >= 2 {
        score += 2;
        reasons.push("含多個連結".into());
    }
    if Regex::new(r"https?://[^\s]*@")
        .expect("固定正規表示式")
        .is_match(&text)
    {
        score += 3;
        reasons.push("連結含 @，可能偽裝網域".into());
    }
    // QR code 內嵌圖（quishing）：整封無連結、叫用戶拿手機掃碼
    if Regex::new(r#"img[^>]*alt=["'][^"']*qr"#)
        .expect("固定正規表示式")
        .is_match(&text)
    {
        score += 4;
        reasons.push("含 QR code 圖片（quishing）".into());
    }
    // 品牌偽裝：From 顯示名稱含品牌（如 DHL），但寄件網域非該品牌官方網域
    let email_domain = Regex::new(r"@([a-z0-9.-]+\.[a-z]{2,})")
        .expect("固定正規表示式")
        .captures(&from)
        .map(|c| c[1].to_string());
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
        .filter_map(|part| part.get_body_raw().ok())
        .flat_map(|bytes| external_word_image_targets_from_docx(&bytes))
        .collect()
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
}
