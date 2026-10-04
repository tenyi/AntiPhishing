//! 外觀：深／淺／跟隨系統主題、語意色與卡片容器。

use eframe::egui::{
    self, Color32, CornerRadius, FontId, Margin, RichText, TextStyle, Theme, ThemePreference,
};

/// 設定檔 `[gui] theme` 的可選值與顯示文字。
pub const THEME_CHOICES: [(&str, &str); 3] =
    [("system", "跟隨系統"), ("light", "淺色"), ("dark", "深色")];

/// 依主題深淺選用的語意色。
pub struct Palette {
    /// 主要按鈕底色（搭配白字）
    pub primary: Color32,
    pub warn: Color32,
    pub danger: Color32,
    pub ok: Color32,
    pub muted: Color32,
}

pub fn palette(visuals: &egui::Visuals) -> Palette {
    if visuals.dark_mode {
        Palette {
            primary: Color32::from_rgb(37, 99, 235),
            warn: Color32::from_rgb(251, 191, 36),
            danger: Color32::from_rgb(248, 113, 113),
            ok: Color32::from_rgb(74, 222, 128),
            muted: Color32::from_gray(150),
        }
    } else {
        Palette {
            primary: Color32::from_rgb(37, 99, 235),
            warn: Color32::from_rgb(180, 83, 9),
            danger: Color32::from_rgb(185, 28, 28),
            ok: Color32::from_rgb(22, 128, 61),
            muted: Color32::from_gray(105),
        }
    }
}

pub fn theme_label(name: &str) -> &'static str {
    THEME_CHOICES
        .iter()
        .find(|(value, _)| *value == name)
        .map_or("跟隨系統", |(_, label)| label)
}

/// 套用使用者選擇的主題；未知值視為跟隨系統。
pub fn apply_theme(ctx: &egui::Context, name: &str) {
    ctx.set_theme(match name {
        "light" => ThemePreference::Light,
        "dark" => ThemePreference::Dark,
        _ => ThemePreference::System,
    });
}

/// 啟動時安裝一次：共用的間距、字級、圓角，以及兩套主題的底色。
pub fn install_style(ctx: &egui::Context) {
    ctx.all_styles_mut(|style| {
        style.spacing.item_spacing = egui::vec2(8.0, 6.0);
        style.spacing.button_padding = egui::vec2(10.0, 5.0);
        style.spacing.interact_size.y = 26.0;
        style.text_styles = [
            (TextStyle::Heading, FontId::proportional(20.0)),
            (TextStyle::Body, FontId::proportional(14.0)),
            (TextStyle::Button, FontId::proportional(14.0)),
            (TextStyle::Small, FontId::proportional(12.0)),
            (TextStyle::Monospace, FontId::monospace(13.0)),
        ]
        .into();
        let radius = CornerRadius::same(6);
        let widgets = &mut style.visuals.widgets;
        for w in [
            &mut widgets.noninteractive,
            &mut widgets.inactive,
            &mut widgets.hovered,
            &mut widgets.active,
            &mut widgets.open,
        ] {
            w.corner_radius = radius;
        }
        style.visuals.window_corner_radius = CornerRadius::same(10);
        style.visuals.menu_corner_radius = CornerRadius::same(8);
    });
    ctx.style_mut_of(Theme::Dark, |style| {
        let v = &mut style.visuals;
        v.panel_fill = Color32::from_rgb(24, 26, 31);
        v.window_fill = Color32::from_rgb(32, 35, 41);
        v.faint_bg_color = Color32::from_rgb(34, 37, 44);
        v.extreme_bg_color = Color32::from_rgb(18, 19, 23);
        v.widgets.noninteractive.bg_stroke.color = Color32::from_rgb(58, 62, 72);
    });
    ctx.style_mut_of(Theme::Light, |style| {
        let v = &mut style.visuals;
        v.panel_fill = Color32::from_rgb(243, 245, 248);
        v.window_fill = Color32::WHITE;
        v.faint_bg_color = Color32::WHITE;
        v.extreme_bg_color = Color32::from_rgb(250, 251, 252);
        v.widgets.noninteractive.bg_stroke.color = Color32::from_rgb(218, 222, 229);
    });
}

/// 帶標題的卡片，寬度撐滿可用空間。
pub fn card<R>(ui: &mut egui::Ui, title: &str, add_contents: impl FnOnce(&mut egui::Ui) -> R) -> R {
    let visuals = ui.visuals();
    egui::Frame::new()
        .fill(visuals.faint_bg_color)
        .stroke(visuals.widgets.noninteractive.bg_stroke)
        .corner_radius(10)
        .inner_margin(Margin::same(14))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            if !title.is_empty() {
                ui.label(RichText::new(title).strong().size(15.0));
                ui.add_space(2.0);
            }
            add_contents(ui)
        })
        .inner
}
