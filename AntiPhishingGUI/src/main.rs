#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::{
    fs,
    io::{Cursor, Read},
    path::Path,
    sync::Arc,
    sync::mpsc::{self, Receiver, Sender},
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
    /// 每輪掃描後、搬移前顯示確認對話框（預設 true）
    #[serde(default = "default_true")]
    confirm_before_move: bool,
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
                confirm_before_move: true,
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

struct App {
    config: Config,
    status: String,
    logs: Vec<String>,
    date_text: String,
    next_check: Instant,
    receiver: Option<Receiver<Vec<String>>>,
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
            ask_receiver: None,
            reply_sender: None,
            pending_move: None,
            tray,
            allow_exit: false,
            startup_scan_pending: true,
            hide_window_on_startup,
            mailboxes: Vec::new(),
            mailbox_receiver: None,
        }
    }

    fn fetch_mailboxes(&mut self) {
        if self.mailbox_receiver.is_some() {
            return;
        }
        if self.config.imap.host.trim().is_empty()
            || self.config.imap.username.trim().is_empty()
            || self.config.imap.password.trim().is_empty()
        {
            self.status = "請先填寫 IMAP 伺服器、帳號及密碼以取得信箱清單。".into();
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
        // 搬移確認通道：worker 於掃描結束前送出待搬移清單並阻塞等待決定
        let (ask, ask_receiver) = mpsc::channel::<Vec<PendingMoveMail>>();
        let (reply_sender, reply_receiver) = mpsc::channel::<Vec<u32>>();
        self.ask_receiver = Some(ask_receiver);
        self.reply_sender = Some(reply_sender);
        self.status = if dates.len() > 1 {
            "啟動掃描前一日與今日郵件中…".into()
        } else if scheduled {
            "排程掃描中…".into()
        } else {
            "手動掃描中…".into()
        };
        thread::spawn(move || {
            let _ = sender.send(
                scan_mail(&config, &dates, &ask, &reply_receiver)
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
                self.ask_receiver = None;
                self.reply_sender = None;
                self.pending_move = None;
                self.next_check = Instant::now() + interval(&self.config);
            }
        }
        // worker 請求確認搬移：先暫存，視窗顯示時由 Dialog 呈現（eframe 不允許在 logic 繪製 UI）
        if let Some(ask) = &self.ask_receiver {
            if let Ok(list) = ask.try_recv() {
                if let Some(reply) = self.reply_sender.clone() {
                    self.status = format!(
                        "掃描完成：{} 封疑似釣魚／惡意廣告郵件，請確認是否隔離",
                        list.len()
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
        }
        // 處理信箱清單接收
        if let Some(receiver) = &self.mailbox_receiver {
            if let Ok(result) = receiver.try_recv() {
                match result {
                    Ok(mailboxes) => {
                        let count = mailboxes.len();
                        self.mailboxes = mailboxes;
                        self.status = format!("已成功取得 {count} 個信箱。");
                    }
                    Err(err) => {
                        self.status = format!("取得信箱清單失敗：{err:#}");
                    }
                }
                self.mailbox_receiver = None;
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
                    ctx.send_viewport_cmd(ViewportCommand::Minimized(false));
                    ctx.send_viewport_cmd(ViewportCommand::Focus);
                    if let Some(cmd) = ViewportCommand::center_on_screen(ctx) {
                        ctx.send_viewport_cmd(cmd);
                    }
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
                    if ui.button("立即掃描指定日期").clicked() {
                        self.start_scan(false);
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
                    for log in self.logs.iter().rev().take(20) {
                        ui.label(log);
                    }
                }
            });
        // 搬移確認對話框：使用者決定後清空，未決定則保留等下次繪製
        if let Some(mut dialog) = self.pending_move.take() {
            if !Self::show_move_confirmation(ui.ctx(), &mut dialog) {
                self.pending_move = Some(dialog);
            }
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
    // ureq 3.x 的逾時設在 Agent 上；max_redirects(0) 避免 POST 被自動重定向時拋出 redirect failed
    let agent_config = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(config.timeout_secs)))
        .max_redirects(0)
        .http_status_as_error(false)
        .build();
    let agent = ureq::Agent::new_with_config(agent_config);
    let mut response = agent
        .post(&url)
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
/// 否則向 UI 送出清單並阻塞等待決定；送出失敗（UI 已關閉）或無回覆 → 視為跳過（回傳空清單，不搬移）。
fn confirm_move(
    enabled: bool,
    pending: &[(u32, String, u32, String)],
    ask: &mpsc::Sender<Vec<PendingMoveMail>>,
    reply: &mpsc::Receiver<Vec<u32>>,
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
    if ask.send(list).is_ok() {
        reply.recv().unwrap_or_default()
    } else {
        Vec::new()
    }
}

/// 掃描指定日期郵件：逐封送 LLM 判定；判定為釣魚/惡意廣告者先暫存，
/// 該輪結束後依 `confirm_before_move` 向 UI 請求確認，核准之個別郵件才搬移至 phishing_mailbox。
/// 回傳逐封 log 行（最後一行為總計）。LLM 未設定或判定失敗時不搬移。
fn scan_mail(
    config: &Config,
    dates: &[NaiveDate],
    ask: &mpsc::Sender<Vec<PendingMoveMail>>,
    reply: &mpsc::Receiver<Vec<u32>>,
) -> Result<Vec<String>> {
    let mut session = connect(&config.imap)?;
    session
        .select(&config.imap.source_mailbox)
        .with_context(|| format!("無法開啟來源信箱：{}", config.imap.source_mailbox))?;
    let llm = llm_config(config);
    let mut lines: Vec<String> = Vec::new();
    let mut scanned = 0;
    // 疑似釣魚/惡意廣告郵件暫存（uid、主旨、評分、LLM 理由），該輪結束後確認再搬移
    let mut pending: Vec<(u32, String, u32, String)> = Vec::new();
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
                    pending.push((uid, subject.clone(), score, verdict.reason));
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
    // 該輪結束、搬移前：依設定向 UI 請求確認；核准選取的 uid 才搬移
    let approved_uids = confirm_move(config.gui.confirm_before_move, &pending, ask, reply);
    let approved_set: std::collections::HashSet<u32> = approved_uids.into_iter().collect();
    let mut moved = 0;
    for (uid, subject, score, reason) in &pending {
        if approved_set.contains(uid) {
            move_message(&mut session, *uid, &config.imap.phishing_mailbox)?;
            lines.push(format!(
                "搬移〈{}〉（評分 {}；LLM：{}）",
                subject, score, reason
            ));
            moved += 1;
        } else {
            lines.push(format!(
                "跳過搬移〈{}〉（評分 {}；LLM：{}）",
                subject, score, reason
            ));
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
        let skipped = pending.len().saturating_sub(moved);
        if skipped > 0 {
            lines.push(format!(
                "{scanned_dates}：已掃描 {scanned} 封，搬移 {moved} 封，保留 {skipped} 封疑似釣魚／惡意廣告郵件。"
            ));
        } else {
            lines.push(format!(
                "{scanned_dates}：已掃描 {scanned} 封，搬移 {moved} 封疑似釣魚／惡意廣告郵件。"
            ));
        }
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
    fn parses_spam_marketing_json_verdict() {
        let verdict =
            parse_llm_verdict(r#"{"is_phishing": true, "reason": "惡意行銷廣告與推銷商品"}"#)
                .expect("純 JSON 應可解析");
        assert!(verdict.is_phishing);
        assert_eq!(verdict.reason, "惡意行銷廣告與推銷商品");
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

        let logs = scan_mail(&config, &[date], &ask_tx, &reply_rx).expect("scan_mail 應成功執行");
        println!("\n=== 2026-08-19 掃描日誌結果 ===");
        for log in logs {
            println!("{log}");
        }
        println!("===============================\n");
    }
}
