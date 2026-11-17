use serde::{Deserialize, Serialize};

use crate::*;

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct ImapConfig {
    pub host: String,
    pub port: u16,
    pub protocol: String,
    pub username: String,
    pub password: String,
    pub source_mailbox: String,
    pub phishing_mailbox: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct DetectionConfig {
    #[serde(default = "default_threshold")]
    pub threshold: u32,
    #[serde(default)]
    pub suspicious_sender_domains: Vec<String>,
    #[serde(default)]
    pub trusted_sender_domains: Vec<String>,
    /// 信任來源 IP：最上層 Received 標頭的來源 IP 完全相符即視為信任
    #[serde(default)]
    pub trusted_relay_ips: Vec<String>,
    #[serde(default = "default_keywords")]
    pub suspicious_keywords: Vec<String>,
    #[serde(default = "default_external_word_image_score")]
    pub external_word_image_score: u32,
}

pub fn default_threshold() -> u32 {
    8
}

pub fn default_external_word_image_score() -> u32 {
    6
}

pub fn default_keywords() -> Vec<String> {
    [
        "verify", "urgent", "password", "login", "帳戶", "驗證", "緊急", "密碼", "掃描", "QR",
        "關稅",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LlmBackend {
    Api,
    Claude,
    Codex,
    Agy,
    Command,
    Jev,
}

impl LlmBackend {
    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "api" | "http" | "openai" => Some(Self::Api),
            "claude" | "claude-code" | "claudecode" => Some(Self::Claude),
            "codex" | "codex-cli" => Some(Self::Codex),
            "agy" | "agy-cli" | "antigravity" => Some(Self::Agy),
            "command" | "cmd" | "custom" => Some(Self::Command),
            "jev" | "typesafe" | "systemone" | "nimble" | "clef" | "clef-flash" => Some(Self::Jev),
            _ => None,
        }
    }
}

/// LLM 判定設定，存於 config.toml 的 `[llm]`；
/// 支援 API 與命令列呼叫（claude、codex、agy、command、jev）。
#[derive(Clone, Serialize, Deserialize)]
pub struct LlmConfig {
    /// 後端類型：api、claude、codex、agy、command、jev
    #[serde(default)]
    pub backend: Option<String>,
    #[serde(default)]
    pub base_url: String,
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub api_key: String,
    /// backend = "command" 時執行的自訂命令字串
    #[serde(default)]
    pub command: String,
    /// Jev 混合評分模式下的分數換算上限（預設 10）
    #[serde(default = "default_jev_max_score")]
    pub jev_max_score: u32,
    /// Jev 起算機率（預設 0.6；低於此值不計分，起算值～1.0 線性換算為 0～jev_max_score）
    #[serde(default = "default_jev_min_prob")]
    pub jev_min_prob: f64,
    #[serde(default = "default_llm_timeout_secs")]
    pub timeout_secs: u64,
    #[serde(default = "default_llm_max_chars")]
    pub max_chars: usize,
}

pub fn default_jev_max_score() -> u32 {
    10
}

pub fn default_jev_min_prob() -> f64 {
    0.6
}

pub fn default_llm_timeout_secs() -> u64 {
    120
}

pub fn default_llm_max_chars() -> usize {
    6000
}

impl Default for LlmConfig {
    fn default() -> Self {
        Self {
            backend: None,
            base_url: String::new(),
            model: String::new(),
            api_key: String::new(),
            command: String::new(),
            jev_max_score: default_jev_max_score(),
            jev_min_prob: default_jev_min_prob(),
            timeout_secs: default_llm_timeout_secs(),
            max_chars: default_llm_max_chars(),
        }
    }
}

impl LlmConfig {
    /// 解析出實際應使用的後端類型；若未指定 backend 則依 base_url 是否非空回退為 Api
    pub fn effective_backend(&self) -> Option<LlmBackend> {
        if let Some(ref b) = self.backend {
            let trimmed = b.trim();
            if !trimmed.is_empty() {
                return LlmBackend::from_str_loose(trimmed);
            }
        }
        if !self.base_url.trim().is_empty() {
            Some(LlmBackend::Api)
        } else {
            None
        }
    }
}

/// 由 Config 取得有效的 LLM 設定；未設定（無法判定後端或缺少必要參數）回 None。
/// 不區分「沒設定」與「設定錯誤」；需要對設定錯誤報錯的呼叫端請用 `llm_config_checked`。
pub fn llm_config(llm: &LlmConfig) -> Option<LlmConfig> {
    llm_config_checked(llm).ok().flatten()
}

/// 同 `llm_config`，但明確寫了 `backend` 卻無法辨識或缺少必要參數時回 Err。
///
/// `backend` 留空＝未設定 LLM（依文件回退規則評分），回 Ok(None)；
/// 寫了 backend 卻打錯字（如 "claud"）若也靜默回退，CLI 會進入不經確認就搬移的傳統模式。
pub fn llm_config_checked(llm: &LlmConfig) -> anyhow::Result<Option<LlmConfig>> {
    let explicit = llm
        .backend
        .as_deref()
        .map(str::trim)
        .filter(|b| !b.is_empty());
    let Some(backend) = llm.effective_backend() else {
        if let Some(name) = explicit {
            anyhow::bail!(
                "[llm] backend = \"{name}\" 無法辨識（可用：api、claude、codex、agy、command、jev）"
            );
        }
        return Ok(None);
    };
    let valid = llm_config_inner(llm, backend);
    if valid.is_none()
        && let Some(name) = explicit
    {
        anyhow::bail!(
            "[llm] backend = \"{name}\" 缺少必要參數（{}）",
            required_params(backend)
        );
    }
    Ok(valid)
}

/// 各後端的必要參數說明（錯誤訊息用）
fn required_params(backend: LlmBackend) -> &'static str {
    match backend {
        LlmBackend::Api => "base_url 與 model",
        LlmBackend::Command => "command",
        LlmBackend::Jev => "雲端 Jev 需 api_key；地端 nimble/clef 需 base_url",
        LlmBackend::Claude | LlmBackend::Codex | LlmBackend::Agy => "無",
    }
}

/// 檢查後端必要參數，齊全回 Some
fn llm_config_inner(llm: &LlmConfig, backend: LlmBackend) -> Option<LlmConfig> {
    match backend {
        LlmBackend::Api => {
            if llm.base_url.trim().is_empty() || llm.model.trim().is_empty() {
                return None;
            }
        }
        LlmBackend::Command => {
            if llm.command.trim().is_empty() {
                return None;
            }
        }
        LlmBackend::Claude | LlmBackend::Codex | LlmBackend::Agy => {
            // CLI 模式已指定 backend 即為有效，model 為可選
        }
        LlmBackend::Jev => {
            if is_local_systemone_model(&llm.model) {
                // 地端 System One（Nimble / Clef / Clef-Flash）：不檢查金鑰，但必須指定 base_url（避免誤送雲端）
                if llm.base_url.trim().is_empty() {
                    return None;
                }
            } else if llm.api_key.trim().is_empty() {
                return None;
            }
        }
    }
    Some(llm.clone())
}
