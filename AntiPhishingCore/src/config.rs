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
            "jev" | "typesafe" | "systemone" => Some(Self::Jev),
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
pub fn llm_config(llm: &LlmConfig) -> Option<LlmConfig> {
    let backend = llm.effective_backend()?;
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
            if is_nimble_model(&llm.model) {
                // 地端 Nimble：不檢查金鑰，但必須指定 base_url（避免誤送雲端）
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
