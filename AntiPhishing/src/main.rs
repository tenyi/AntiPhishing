use std::{
    cell::Cell,
    fs,
    io::{self, Cursor, Read, Write},
    net::{TcpStream, ToSocketAddrs},
    path::PathBuf,
    process::{Command, Stdio},
    sync::LazyLock,
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use chrono::NaiveDate;
use clap::Parser;
use imap::Session;
use mailparse::{MailHeaderMap, parse_mail};
use quick_xml::{Reader, events::Event};
use regex::Regex;
use serde::{Deserialize, Serialize};
use zip::ZipArchive;

/// IMAP TCP 連線逾時
const IMAP_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// IMAP 讀寫逾時（避免伺服器停滯時永久卡死）
const IMAP_IO_TIMEOUT: Duration = Duration::from_secs(60);
/// 單一 .rels 檔案的解壓上限（Word 關聯檔極小，僅防壓縮炸彈）
const MAX_DOCX_RELS_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Parser, Debug)]
#[command(about = "依指定日期掃描 IMAP 信箱，以地端 LLM 判定釣魚／惡意廣告郵件並搬移至指定信箱")]
struct Args {
    /// 要掃描的日期，格式 YYYY-MM-DD；可重複指定多個（例如昨天與今天）。
    #[arg(long = "date", value_name = "DATE", required = true)]
    date: Vec<NaiveDate>,

    /// 設定檔路徑。
    #[arg(long, default_value = "config.toml")]
    config: PathBuf,

    /// 只列出判定結果，不實際搬移郵件。
    #[arg(long)]
    dry_run: bool,

    /// 搬移前不做互動確認，直接搬移全部判定郵件（LLM 模式適用）。
    #[arg(short = 'y', long)]
    yes: bool,
}

#[derive(Deserialize)]
struct Config {
    imap: ImapConfig,
    detection: DetectionConfig,
    /// 地端 LLM 判定（OpenAI 相容 API）；留空 base_url 或 model 即回退傳統評分模式。
    #[serde(default)]
    llm: LlmConfig,
}

#[derive(Deserialize)]
struct ImapConfig {
    host: String,
    port: u16,
    /// 支援 imaps（隱式 TLS）或 starttls。
    protocol: String,
    username: String,
    password: String,
    source_mailbox: String,
    phishing_mailbox: String,
}

#[derive(Deserialize)]
struct DetectionConfig {
    /// 傳統評分模式（未設定 LLM）的搬移門檻。
    threshold: u32,
    #[serde(default)]
    suspicious_sender_domains: Vec<String>,
    #[serde(default)]
    trusted_sender_domains: Vec<String>,
    #[serde(default = "default_keywords")]
    suspicious_keywords: Vec<String>,
    /// Word 附件含有外部圖片時加上的分數。
    #[serde(default = "default_external_word_image_score")]
    external_word_image_score: u32,
}

fn default_external_word_image_score() -> u32 {
    5
}

fn default_keywords() -> Vec<String> {
    [
        "verify", "urgent", "password", "login", "帳戶", "驗證", "緊急", "密碼",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum LlmBackend {
    Api,
    Claude,
    Codex,
    Agy,
    Command,
}

impl LlmBackend {
    fn from_str_loose(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "api" | "http" | "openai" => Some(Self::Api),
            "claude" | "claude-code" | "claudecode" => Some(Self::Claude),
            "codex" | "codex-cli" => Some(Self::Codex),
            "agy" | "agy-cli" | "antigravity" => Some(Self::Agy),
            "command" | "cmd" | "custom" => Some(Self::Command),
            _ => None,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct LlmConfig {
    /// 後端類型：api、claude、codex、agy、command
    #[serde(default)]
    backend: Option<String>,
    #[serde(default)]
    base_url: String,
    #[serde(default)]
    model: String,
    #[serde(default)]
    api_key: String,
    /// backend = "command" 時執行的自訂命令字串
    #[serde(default)]
    command: String,
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
            backend: None,
            base_url: String::new(),
            model: String::new(),
            api_key: String::new(),
            command: String::new(),
            timeout_secs: default_llm_timeout_secs(),
            max_chars: default_llm_max_chars(),
        }
    }
}

impl LlmConfig {
    /// 解析出實際應使用的後端類型；若未指定 backend 則依 base_url 是否非空回退為 Api
    fn effective_backend(&self) -> Option<LlmBackend> {
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
fn llm_config(config: &Config) -> Option<LlmConfig> {
    let backend = config.llm.effective_backend()?;
    match backend {
        LlmBackend::Api => {
            if config.llm.base_url.trim().is_empty() || config.llm.model.trim().is_empty() {
                return None;
            }
        }
        LlmBackend::Command => {
            if config.llm.command.trim().is_empty() {
                return None;
            }
        }
        LlmBackend::Claude | LlmBackend::Codex | LlmBackend::Agy => {
            // CLI 模式已指定 backend 即為有效，model 為可選
        }
    }
    Some(config.llm.clone())
}

/// 送 LLM 判斷的 system 提示：要求嚴格 JSON 輸出，判定釣魚/詐欺/惡意行銷廣告/垃圾推銷/仿冒品牌。
const LLM_SYSTEM_PROMPT: &str = "你是郵件安全判官。根據使用者提供的郵件內容，判斷該郵件是否為「釣魚、詐欺、詐騙郵件」或「惡意行銷廣告、垃圾推銷、仿冒知名品牌或販賣一般性物品的垃圾廣告郵件」。\
高風險與排除目標訊號包括：\
1. 惡意行銷與垃圾廣告：未經請求的推銷廣告、仿冒知名品牌促銷、販賣一般性物品或商品（如香薰瀑布、健康器材、保健品、手錶名品等）、含可疑轉址或假退訂連結（Opt Out）、寄件者與商品內容不合的垃圾郵件。\
2. 偽裝機構或品牌：寄件網域非其所稱品牌（如 DHL、FedEx、快遞、銀行、Yahoo 等知名企業）的官方網域，或郵件安全驗證（DMARC/SPF）失敗。\
3. 詐騙與個資竊取：要求付款或繳費（關稅、手續費、驗證費）、要求提供帳號密碼、緊急施壓、可疑連結、附件追蹤、內含 QR code 或要求用手機掃描（quishing）、籠統稱呼（如「親愛的顧客」）搭配假單號或要求更新地址/電話。\
4. 異常附件：一般無需附件之郵件（如新聞推播、通知信、系統警告等）卻夾帶 Office 文件（.doc/.docx/.xls/.xlsx 等）、壓縮檔或可執行檔等可疑附件；或附件包含外部追蹤連結。\
\
僅輸出嚴格 JSON，不要任何其他文字：{\"is_phishing\": true 或 false, \"reason\": \"簡短理由\"}。\
只要符合上述釣魚、詐騙或惡意推銷廣告/垃圾信特徵，is_phishing 必須為 true；若為正常商務或私人往來郵件（非垃圾廣告與釣魚），is_phishing 必須為 false。若證據不足或不確定，is_phishing 設為 false。";

/// 組裝送 LLM 的郵件內容：From/Subject/內文（截斷），並附附件清單、Word 外部圖片與安全驗證提示。
fn llm_user_prompt(
    from: &str,
    subject: &str,
    body: &str,
    max_chars: usize,
    attachments: &[String],
    docx_targets: &[String],
    auth_warnings: &[String],
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
    if !attachments.is_empty() {
        text.push('\n');
        text.push_str("附件清單：");
        text.push_str(&attachments.join("、"));
    }
    if !docx_targets.is_empty() {
        text.push('\n');
        text.push_str("附件提示：Word 文件含外部圖片連結（追蹤）：");
        text.push_str(&docx_targets.join("、"));
    }
    if !auth_warnings.is_empty() {
        text.push('\n');
        text.push_str("安全驗證提示：");
        text.push_str(&auth_warnings.join("；"));
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
static RE_HTML_SIGNATURE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)<html\b|<!doctype\s+html|<body\b|<\?xml\b|<w:worddocument\b"#)
        .expect("固定正規表示式")
});
static RE_HTML_IMG_SRC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)<img\b[^>]*?\bsrc=["'](https?://[^"'\s>]+)["']"#).expect("固定正規表示式")
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

/// LLM 對單一郵件的判定結果。
#[derive(Deserialize)]
struct LlmVerdict {
    is_phishing: bool,
    #[serde(default)]
    reason: String,
}

/// 組合命令列程式與引數清單
fn build_cli_command(config: &LlmConfig) -> Result<(String, Vec<String>)> {
    let backend = config
        .effective_backend()
        .context("未設定有效的 LLM 後端")?;
    let model = config.model.trim();

    match backend {
        LlmBackend::Claude => {
            let mut args = vec![
                "-p".to_string(),
                "--tools".to_string(),
                "".to_string(),
                "--dangerously-skip-permissions".to_string(),
                "--output-format".to_string(),
                "text".to_string(),
            ];
            if !model.is_empty() {
                args.push("--model".to_string());
                args.push(model.to_string());
            }
            Ok(("claude".to_string(), args))
        }
        LlmBackend::Codex => {
            let mut args = vec![
                "exec".to_string(),
                "--skip-git-repo-check".to_string(),
                "--ephemeral".to_string(),
                "--color".to_string(),
                "never".to_string(),
                "--dangerously-bypass-approvals-and-sandbox".to_string(),
            ];
            if !model.is_empty() {
                args.push("-m".to_string());
                args.push(model.to_string());
            }
            args.push("-".to_string());
            Ok(("codex".to_string(), args))
        }
        LlmBackend::Agy => {
            let mut args = vec![
                "--dangerously-skip-permissions".to_string(),
                "--output-format".to_string(),
                "text".to_string(),
                "--disable-slash-commands".to_string(),
            ];
            if !model.is_empty() {
                args.push("--model".to_string());
                args.push(model.to_string());
            }
            Ok(("agy".to_string(), args))
        }
        LlmBackend::Command => {
            let cmd_str = config.command.trim();
            if cmd_str.is_empty() {
                bail!("backend 設為 command，但未設定 command 命令字串");
            }
            #[cfg(windows)]
            {
                Ok((
                    "cmd".to_string(),
                    vec!["/C".to_string(), cmd_str.to_string()],
                ))
            }
            #[cfg(not(windows))]
            {
                Ok((
                    "sh".to_string(),
                    vec!["-c".to_string(), cmd_str.to_string()],
                ))
            }
        }
        LlmBackend::Api => {
            bail!("Api 後端不支援透過命令列執行");
        }
    }
}

/// 執行外部 CLI 命令，透過 stdin 送入 prompt，並讀取 stdout 回傳純文字。
/// 具備逾時防護與防管線緩衝區死鎖設計。
fn run_cli_with_stdin(
    program: &str,
    args: &[String],
    prompt: &str,
    timeout: Duration,
) -> Result<String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("無法啟動外部 CLI 命令：{program}"))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(prompt.as_bytes())
            .with_context(|| format!("無法將 Prompt 寫入 {program} 的 stdin"))?;
    }

    let mut stdout_pipe = child.stdout.take().context("無法取得子行程 stdout")?;
    let mut stderr_pipe = child.stderr.take().context("無法取得子行程 stderr")?;

    let stdout_handle = thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout_pipe.read_to_end(&mut buf);
        buf
    });
    let stderr_handle = thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stderr_pipe.read_to_end(&mut buf);
        buf
    });

    let start = Instant::now();
    let poll_interval = Duration::from_millis(50);
    let status = loop {
        if let Some(status) = child
            .try_wait()
            .with_context(|| format!("檢查 {program} 行程狀態失敗"))?
        {
            break status;
        }
        if start.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            bail!(
                "CLI 命令 ({program}) 執行逾時（超過 {} 秒），已終止該行程",
                timeout.as_secs()
            );
        }
        thread::sleep(poll_interval);
    };

    let stdout_bytes = stdout_handle.join().unwrap_or_default();
    let stderr_bytes = stderr_handle.join().unwrap_or_default();
    let stdout_text = String::from_utf8_lossy(&stdout_bytes).into_owned();
    let stderr_text = String::from_utf8_lossy(&stderr_bytes).into_owned();

    if !status.success() {
        bail!(
            "CLI 命令 ({program}) 執行失敗 (結束代碼 {:?})：\n{}",
            status.code(),
            stderr_text.trim()
        );
    }

    Ok(stdout_text)
}

/// 透過 OpenAI 相容的 /chat/completions 取得單一郵件判定。
fn llm_judge_api(
    config: &LlmConfig,
    from: &str,
    subject: &str,
    body: &str,
    attachments: &[String],
    docx_targets: &[String],
    auth_warnings: &[String],
) -> Result<LlmVerdict> {
    let payload = serde_json::json!({
        "model": config.model,
        "temperature": 0,
        "messages": [
            { "role": "system", "content": LLM_SYSTEM_PROMPT },
            { "role": "user", "content": llm_user_prompt(from, subject, body, config.max_chars, attachments, docx_targets, auth_warnings) }
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
        bail!(
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
        bail!(
            "LLM 伺服器回傳錯誤 (HTTP {})：{}",
            status.as_u16(),
            err_body
        );
    }

    let response: serde_json::Value = response
        .body_mut()
        .read_json()
        .map_err(|error| anyhow::anyhow!("LLM 回應不是 JSON：{error}"))?;
    let content = match response["choices"]
        .get(0)
        .and_then(|choice| choice["message"]["content"].as_str())
    {
        Some(s) => s,
        None => {
            bail!("LLM 回應缺少 choices[0].message.content，完整回應：{response}");
        }
    };
    parse_llm_verdict(content).with_context(|| format!("原始回應內容為：{content:?}"))
}

/// 透過外部 CLI 取得單一郵件判定。
fn llm_judge_cli(
    config: &LlmConfig,
    from: &str,
    subject: &str,
    body: &str,
    attachments: &[String],
    docx_targets: &[String],
    auth_warnings: &[String],
) -> Result<LlmVerdict> {
    let (program, args) = build_cli_command(config)?;
    let user_prompt = llm_user_prompt(
        from,
        subject,
        body,
        config.max_chars,
        attachments,
        docx_targets,
        auth_warnings,
    );
    let full_prompt = format!("{LLM_SYSTEM_PROMPT}\n\n=== 待判定郵件 ===\n{user_prompt}");
    let timeout = Duration::from_secs(config.timeout_secs);
    let output_text = run_cli_with_stdin(&program, &args, &full_prompt, timeout)?;
    parse_llm_verdict(&output_text)
        .with_context(|| format!("CLI ({program}) 原始回應為：{output_text:?}"))
}

/// 呼叫指定之 LLM 後端（API 或 CLI）取得單一郵件判定。
fn llm_judge(
    config: &LlmConfig,
    from: &str,
    subject: &str,
    body: &str,
    attachments: &[String],
    docx_targets: &[String],
    auth_warnings: &[String],
) -> Result<LlmVerdict> {
    let backend = config
        .effective_backend()
        .context("未設定有效的 LLM 後端")?;
    match backend {
        LlmBackend::Api => llm_judge_api(
            config,
            from,
            subject,
            body,
            attachments,
            docx_targets,
            auth_warnings,
        ),
        LlmBackend::Claude | LlmBackend::Codex | LlmBackend::Agy | LlmBackend::Command => {
            llm_judge_cli(
                config,
                from,
                subject,
                body,
                attachments,
                docx_targets,
                auth_warnings,
            )
        }
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    let config: Config = toml::from_str(
        &fs::read_to_string(&args.config)
            .with_context(|| format!("無法讀取設定檔：{}", args.config.display()))?,
    )
    .context("設定檔 TOML 格式不正確")?;

    let mut session = connect(&config.imap)?;
    let selected = session
        .select(&config.imap.source_mailbox)
        .with_context(|| format!("無法開啟來源信箱：{}", config.imap.source_mailbox))?;
    let original_uidvalidity = selected.uid_validity;

    let llm = llm_config(&config);
    let mut scanned = 0;
    // 待搬移清單（uid、主旨、評分、理由）：LLM 模式以 LLM 判定為準，啟發式評分僅供 log 參考；
    // 未設定 LLM 時沿用傳統門檻模式（評分 ≥ threshold）。
    let mut pending: Vec<(u32, String, u32, String)> = Vec::new();
    let mut lines: Vec<String> = Vec::new();

    // 自動納入前一日以消除伺服器 UTC 時差落差（例如臺灣 UTC+8 凌晨信件會落在伺服器前一日）
    let dates = expand_scan_dates(&args.date);

    // 進度顯示在 stderr，stdout 保留給判定結果，方便管線處理
    let progress_width = Cell::new(0usize);
    for date in &dates {
        let mut uids: Vec<u32> = session
            .uid_search(format!("ON {}", date.format("%d-%b-%Y")))
            .with_context(|| format!("搜尋 {date} 郵件失敗"))?
            .into_iter()
            .collect();
        // 由小到大排序：處理順序穩定，進度計數也與 UID 對應
        uids.sort_unstable();
        // LLM 連續失敗熔斷：本日期內連續失敗 ≥3 次後，本輪剩餘信件直接採規則評分，
        // 避免 LLM 服務當機時每封都等待逾時上限。
        let mut llm_consecutive_failures: u32 = 0;
        show_progress(
            &progress_width,
            format!("搜尋 {date}：找到 {} 封待檢查", uids.len()),
        );
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
                lines.push(format!("郵件 UID {uid} 內容為空，略過。"));
                continue;
            };
            // 記錄掃描當下是否為未讀取狀態（不含 \Seen 旗標）
            let was_unread = is_message_unread(message.flags());
            let Some(bytes) = message.body() else {
                lines.push(format!("郵件 UID {uid} 內文為空，略過。"));
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
            // mailparse 對 multipart 的 get_body() 回傳空，改從 subparts 提取
            let (body, score_body) = extract_body_text(&mail);
            scanned += 1;
            show_progress(&progress_width, progress_text(index + 1, total, &subject));
            let attachments = extract_attachment_filenames(&mail);
            let targets = external_word_image_targets(&mail);
            let auth_warnings = check_auth_failures(&mail);
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
                    if llm_consecutive_failures >= 3 {
                        // 熔斷：本日期內已連續失敗 ≥3 次，跳過 LLM 直接採規則評分
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
                            &auth_warnings,
                        ) {
                            Ok(verdict) if verdict.is_phishing => {
                                pending.push((uid, subject.clone(), score, verdict.reason));
                            }
                            Ok(verdict) => {
                                lines.push(format!(
                                    "略過〈{}〉（評分 {score}；LLM：{}）",
                                    subject, verdict.reason
                                ));
                            }
                            Err(error) => {
                                llm_consecutive_failures += 1;
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
                    if score >= config.detection.threshold {
                        pending.push((uid, subject.clone(), score, reasons.join("；")));
                    }
                }
            }
            if used_fallback && was_unread {
                let _ = restore_unread_status(&mut session, uid);
            }
        }
    }
    clear_progress(&progress_width);

    let mut moved = 0;
    let mut failed = 0;
    if args.dry_run {
        for (uid, subject, score, reason) in &pending {
            lines.push(format!(
                "會搬移〈{subject}〉（UID {uid}，評分 {score}；{reason}）"
            ));
        }
    } else {
        let approved_uids: Vec<u32> = if llm.is_some() && !args.yes {
            confirm_move_interactive(&pending)
        } else {
            pending.iter().map(|(uid, ..)| *uid).collect()
        };
        let mut approved: std::collections::HashSet<u32> = approved_uids.iter().copied().collect();
        if !approved.is_empty() {
            // 搬移前重新 SELECT 刷新狀態並比對 UIDVALIDITY，避免信箱重建後搬錯信。
            // 若因等待確認過久導致連線中斷或逾時（如 Connection Lost），嘗試重新連線後再次確認。
            let mut reconnected = false;
            let select_res = match session.select(&config.imap.source_mailbox) {
                Ok(refreshed) => Ok(refreshed),
                Err(first_err) => {
                    lines.push(format!(
                        "來源信箱連線中斷或逾時（{first_err:#}），嘗試重新建立連線…"
                    ));
                    session.logout().ok();
                    match connect(&config.imap) {
                        Ok(new_session) => {
                            session = new_session;
                            reconnected = true;
                            session
                                .select(&config.imap.source_mailbox)
                                .map_err(|e| anyhow::anyhow!(e))
                        }
                        Err(reconnect_err) => Err(anyhow::anyhow!(
                            "重新連線失敗：{reconnect_err:#}（原連線錯誤：{first_err:#}）"
                        )),
                    }
                }
            };
            match select_res {
                Ok(refreshed) if refreshed.uid_validity == original_uidvalidity => {
                    if reconnected {
                        lines.push("重新建立連線成功，繼續搬移作業。".into());
                    }
                }
                Ok(_) => {
                    lines.push("來源信箱 UIDVALIDITY 已變更，為避免誤搬本輪取消搬移。".into());
                    approved.clear();
                }
                Err(error) => {
                    lines.push(format!("無法重新確認來源信箱狀態，本輪取消搬移：{error:#}"));
                    approved.clear();
                }
            }
            if let Err(error) = ensure_phishing_mailbox(&mut session, &config.imap.phishing_mailbox)
            {
                // 目標信箱不存在又建不出來：逐封標記失敗但保留全部日誌，不再中斷
                lines.push(format!(
                    "目標信箱「{}」無法使用，本輪取消搬移：{error:#}",
                    config.imap.phishing_mailbox
                ));
                approved.clear();
            }
        }
        let mut moved_uids: Vec<String> = Vec::new();
        for (uid, subject, score, reason) in &pending {
            if !approved.contains(uid) {
                if approved_uids.contains(uid) {
                    lines.push(format!(
                        "因本輪取消搬移未處理〈{subject}〉（評分 {score}；{reason}）"
                    ));
                } else {
                    lines.push(format!("跳過搬移〈{subject}〉（評分 {score}；{reason}）"));
                }
                continue;
            }
            match move_message(&mut session, *uid, &config.imap.phishing_mailbox) {
                Ok(()) => {
                    lines.push(format!("搬移〈{subject}〉（評分 {score}；{reason}）"));
                    moved += 1;
                    moved_uids.push(uid.to_string());
                }
                Err(error) => {
                    // 單封失敗只記錄並繼續，不丟棄其餘結果
                    lines.push(format!("搬移〈{subject}〉失敗：{error:#}"));
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
    }
    session.logout().ok();

    for line in &lines {
        println!("{line}");
    }
    let scanned_dates = dates_summary(&args.date);
    if args.dry_run {
        println!(
            "{scanned_dates}：dry-run 完成，共掃描 {scanned} 封，{} 封符合搬移條件。",
            pending.len()
        );
    } else if llm.is_some() {
        let skipped = pending.len().saturating_sub(moved + failed);
        let mut summary = format!("{scanned_dates}：已掃描 {scanned} 封，搬移 {moved} 封");
        if failed > 0 {
            summary.push_str(&format!("，搬移失敗 {failed} 封"));
        }
        if skipped > 0 {
            summary.push_str(&format!("，保留 {skipped} 封疑似釣魚／惡意廣告郵件"));
        }
        summary.push('。');
        println!("{summary}");
    } else {
        println!("{scanned_dates}：已掃描 {scanned} 封，搬移 {moved} 封（傳統評分模式）。");
        println!(
            "提示：在 config.toml 的 [llm] 設定 backend（如 \"claude\"、\"agy\"）或 API base_url 與 model 即可啟用 LLM 判定。"
        );
    }
    Ok(())
}

/// 建立 IMAP 連線：手動 TCP+TLS 以確保連線與讀寫皆有逾時，
/// 避免伺服器停滯時整批掃描永久卡死。
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

/// 判斷郵件旗標清單中是否為未讀（不含 \Seen 旗標）。
fn is_message_unread(flags: &[imap::types::Flag]) -> bool {
    !flags.iter().any(|f| matches!(f, imap::types::Flag::Seen))
}

/// 若郵件在掃描前為未讀，於處理後還原未讀狀態（移除 \Seen 旗標）。
fn restore_unread_status(session: &mut Session<imap::Connection>, uid: u32) -> Result<()> {
    session
        .uid_store(uid.to_string(), "-FLAGS.SILENT (\\Seen)")
        .with_context(|| format!("還原郵件 UID {uid} 未讀狀態失敗"))?;
    Ok(())
}

fn move_message(session: &mut Session<imap::Connection>, uid: u32, target: &str) -> Result<()> {
    session
        .uid_copy(uid.to_string(), target)
        .with_context(|| format!("無法複製郵件到：{target}"))?;
    session.uid_store(uid.to_string(), "+FLAGS.SILENT (\\Deleted)")?;
    Ok(())
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

/// 於 stderr 原地更新單行進度：以空白覆蓋殘影，不依賴 ANSI 控制碼。
fn show_progress(width: &Cell<usize>, text: String) {
    let previous = width.get();
    let current = text.chars().count();
    let pad = previous.saturating_sub(current);
    eprint!("\r{text}{}", " ".repeat(pad));
    io::stderr().flush().ok();
    width.set(current.max(previous));
}

/// 清除進度行並換行，讓後續輸出從新的一行開始。
fn clear_progress(width: &Cell<usize>) {
    show_progress(width, String::new());
    eprintln!();
}

/// 掃描進度文字；無主旨（或全空白）時以「(無主旨)」後備，主旨截斷以免進度行過長。
fn progress_text(current: usize, total: usize, subject: &str) -> String {
    let subject = subject.trim();
    let subject = if subject.is_empty() {
        "(無主旨)"
    } else {
        subject
    };
    let subject: String = subject.chars().take(40).collect();
    format!("檢查第 {current}/{total} 封〈{subject}〉")
}

/// 互動式確認：列出待搬移清單，選擇全部搬移／全部跳過／逐封決定。
/// 讀取失敗或輸入結束（EOF）視為全部跳過，避免非互動環境誤搬。
fn confirm_move_interactive(pending: &[(u32, String, u32, String)]) -> Vec<u32> {
    println!("以下 {} 封郵件判定為釣魚／惡意廣告：", pending.len());
    for (index, (uid, subject, score, reason)) in pending.iter().enumerate() {
        println!("  [{index}] UID {uid}　評分 {score}　〈{subject}〉");
        println!("      理由：{reason}");
    }
    print!("搬移方式：[a]全部搬移 [s]全部跳過 [c]逐封決定？");
    io::stdout().flush().ok();
    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_err() {
        return Vec::new();
    }
    match input.trim().to_ascii_lowercase().as_str() {
        "a" => pending.iter().map(|(uid, ..)| *uid).collect(),
        "c" => {
            let mut approved = Vec::new();
            for (uid, subject, score, reason) in pending {
                print!("搬移 UID {uid}〈{subject}〉（評分 {score}；{reason}）？[y/N]");
                io::stdout().flush().ok();
                input.clear();
                if io::stdin().read_line(&mut input).is_err() {
                    break;
                }
                if input.trim().eq_ignore_ascii_case("y") {
                    approved.push(*uid);
                }
            }
            approved
        }
        _ => Vec::new(),
    }
}

/// 擴充掃描日期：每個指定日期自動包含前一日（安全視窗），以消除 IMAP 伺服器 UTC 時差落差，並按日期由舊到新排序且去重。
fn expand_scan_dates(dates: &[NaiveDate]) -> Vec<NaiveDate> {
    let mut expanded: Vec<NaiveDate> = dates
        .iter()
        .flat_map(|&d| [d - chrono::Duration::days(1), d])
        .collect();
    expanded.sort_unstable();
    expanded.dedup();
    expanded
}

fn dates_summary(dates: &[NaiveDate]) -> String {
    dates
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("、")
}

/// 常見快遞與電商品牌及其官方網域（小寫）：用於偵測 From 顯示名稱偽裝。
const BRAND_OFFICIAL_DOMAINS: [(&str, &[&str]); 8] = [
    ("dhl", &["dhl.com"]),
    ("fedex", &["fedex.com"]),
    ("ups", &["ups.com"]),
    ("momo", &["momoshop.com.tw", "momo.com.tw"]),
    ("pchome", &["pchome.com.tw", "pcstore.com.tw"]),
    ("shopee", &["shopee.tw", "shopee.com"]),
    ("蝦皮", &["shopee.tw", "shopee.com"]),
    (
        "yahoo",
        &[
            "yahoo.com",
            "yahoo.com.tw",
            "yahoo.co.jp",
            "yahoo.com.hk",
            "yahoo.co.uk",
            "yahoo.com.au",
            "yahoo.com.sg",
        ],
    ),
];

/// 檢查郵件驗證標頭（DMARC / SPF 驗證失敗）
///
/// 規則：
/// - `Authentication-Results` / `ARC-Authentication-Results`：只信任 `i=1`（最外層
///   受信邊界）。inner hop 的 ARC 結果略過，避免 forwarding / mailing list 殘留誤判。
///   沒有 `i=` 視為受信邊界（多數現代 MTA 預設）。
/// - `Received-SPF`：hop-local 結果，不做 i= 過濾。
/// - `spf=softfail` 不視為偽造（常見於 forwarding / 授權第三方 / mailing list）。
///   若 DKIM 通過且 DMARC pass，仍屬合法郵件。
fn check_auth_failures(mail: &mailparse::ParsedMail<'_>) -> Vec<String> {
    let mut warnings = Vec::new();
    let check_headers = [
        "Authentication-Results",
        "ARC-Authentication-Results",
        "Received-SPF",
    ];
    for name in check_headers {
        for val in mail.headers.get_all_values(name) {
            if matches!(
                name,
                "Authentication-Results" | "ARC-Authentication-Results"
            ) {
                let instance = parse_auth_results_instance(&val);
                if !matches!(instance, Some(1) | None) {
                    continue;
                }
            }
            let lower = val.to_lowercase();
            if (lower.contains("dmarc=fail") || lower.contains("dmarc=reject"))
                && !warnings.iter().any(|w: &String| w.contains("DMARC"))
            {
                warnings.push("DMARC 驗證失敗（寄件者網域遭偽造）".into());
            }
            let spf_failed =
                lower.contains("spf=fail") || (name == "Received-SPF" && lower.starts_with("fail"));
            if spf_failed && !warnings.iter().any(|w: &String| w.contains("SPF")) {
                warnings.push("SPF 驗證失敗（發信伺服器未獲授權）".into());
            }
        }
    }
    warnings
}

/// 從 Authentication-Results 標頭值中解析 `i=<n>` instance number。
fn parse_auth_results_instance(value: &str) -> Option<u32> {
    for token in value.split(';') {
        let token = token.trim();
        if let Some(rest) = token.strip_prefix("i=") {
            return rest.trim().parse::<u32>().ok();
        }
    }
    None
}

/// 收集所有附件檔名清單（供評分與 LLM 提示參考）
fn extract_attachment_filenames(mail: &mailparse::ParsedMail<'_>) -> Vec<String> {
    let mut names = Vec::new();
    for part in mail.parts() {
        let cd = part.get_content_disposition();
        let is_attachment = matches!(cd.disposition, mailparse::DispositionType::Attachment)
            || cd.params.contains_key("filename")
            || part.ctype.params.contains_key("name");
        if is_attachment {
            if let Some(name) = cd
                .params
                .get("filename")
                .or_else(|| part.ctype.params.get("name"))
            {
                let clean = name.replace(['\r', '\n'], " ").trim().to_string();
                if !clean.is_empty() && !names.contains(&clean) {
                    names.push(clean);
                }
            }
        }
    }
    names
}

fn phishing_score(
    from: &str,
    subject: &str,
    body: &str,
    attachments: &[String],
    external_word_image_targets: &[String],
    auth_warnings: &[String],
    config: &DetectionConfig,
) -> (u32, Vec<String>) {
    let text = format!("{subject}\n{body}").to_lowercase();
    let from = from.to_lowercase();
    let mut score: u32 = 0;
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
    let link_count = RE_ANY_LINK.find_iter(&text).count();
    if link_count >= 2 {
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
    // 品牌偽裝：From 顯示名稱含品牌（如 DHL、momo、蝦皮、Yahoo），但寄件網域非該品牌官方網域
    let email_domain = RE_EMAIL_DOMAIN.captures(&from).map(|c| c[1].to_string());
    let display_name = from.split('<').next().unwrap_or(from.as_str()).trim();
    if let Some(domain) = email_domain {
        for (brand, officials) in BRAND_OFFICIAL_DOMAINS {
            if display_name.contains(brand)
                // 嚴格比對：官方網域本身或「.官方網域」結尾，避免 evil-dhl.com 偽裝
                && !officials.iter().any(|official| {
                    domain == *official
                        || domain.ends_with(&format!(".{official}"))
                })
            {
                score += 3;
                reasons.push(format!(
                    "品牌偽裝：顯示名稱含 {brand} 但網域非 {}",
                    officials.join("/")
                ));
                break;
            }
        }
    }
    // 附件風險評估：夾帶 Office 文件（常見社交工程載體）
    let has_office_attachment = attachments.iter().any(|att| {
        let lower = att.to_lowercase();
        lower.ends_with(".doc")
            || lower.ends_with(".docx")
            || lower.ends_with(".docm")
            || lower.ends_with(".xls")
            || lower.ends_with(".xlsx")
            || lower.ends_with(".xlsm")
            || lower.ends_with(".ppt")
            || lower.ends_with(".pptx")
    });
    if has_office_attachment {
        score += 2;
        reasons.push("夾帶 Office 文件附件".into());
    }
    if !external_word_image_targets.is_empty() {
        score += config.external_word_image_score;
        reasons.push("Word 附件含外部圖片連結".into());
    }
    // 郵件安全驗證失敗（DMARC/SPF fail）
    if !auth_warnings.is_empty() {
        score += 4;
        reasons.push(auth_warnings.join("；"));
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

/// 從 Word 附件（含 OOXML 與 HTML 格式）找出外部圖片；全程只讀取附件位元組，不開啟文件或連線。
fn external_word_image_targets(mail: &mailparse::ParsedMail<'_>) -> Vec<String> {
    mail.parts()
        .filter(|part| is_word_part(part))
        .filter_map(|part| part.get_body_raw().ok())
        .flat_map(|bytes| external_word_image_targets_from_word(&bytes))
        .collect()
}

/// 對 Word（docx/docm/doc/rtf）附件判定，依 MIME 或副檔名篩選。
fn is_word_part(part: &mailparse::ParsedMail<'_>) -> bool {
    let mime = part.ctype.mimetype.to_ascii_lowercase();
    if mime.contains("wordprocessingml.document")
        || mime.contains("msword")
        || mime.contains("application/vnd.ms-word")
    {
        return true;
    }
    part.get_content_disposition()
        .params
        .get("filename")
        .or_else(|| part.ctype.params.get("name"))
        .map(|name| {
            let lower = name.to_lowercase();
            lower.ends_with(".docx")
                || lower.ends_with(".docm")
                || lower.ends_with(".doc")
                || lower.ends_with(".rtf")
        })
        .unwrap_or(false)
}

#[allow(dead_code)]
fn is_docx_part(part: &mailparse::ParsedMail<'_>) -> bool {
    is_word_part(part)
}

fn external_word_image_targets_from_word(bytes: &[u8]) -> Vec<String> {
    // 1. 若為 ZIP 壓縮格式（OOXML docx/docm），解析 word/_rels/*.rels 中的外部圖片關聯
    if let Ok(mut archive) = ZipArchive::new(Cursor::new(bytes)) {
        let mut targets = Vec::new();
        for index in 0..archive.len() {
            let Ok(mut entry) = archive.by_index(index) else {
                continue;
            };
            let name = entry.name().to_owned();
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
        return targets;
    }

    // 2. 若非 ZIP 格式，檢查是否為 HTML 格式偽裝的 Word 文件（常見於釣魚社交工程演練與追蹤像素）
    // 限制檢驗長度（如前 512KB），防禦超大檔案；僅離線文字比對提取 URL，絕不連網
    let check_bytes = if bytes.len() > 512 * 1024 {
        &bytes[..512 * 1024]
    } else {
        bytes
    };
    let text = String::from_utf8_lossy(check_bytes);
    if RE_HTML_SIGNATURE.is_match(&text) {
        let mut targets = Vec::new();
        for cap in RE_HTML_IMG_SRC.captures_iter(&text) {
            if let Some(m) = cap.get(1) {
                let url = m.as_str().trim().to_string();
                if !url.is_empty() && !targets.contains(&url) {
                    targets.push(url);
                }
            }
        }
        return targets;
    }

    Vec::new()
}

#[allow(dead_code)]
fn external_word_image_targets_from_docx(bytes: &[u8]) -> Vec<String> {
    external_word_image_targets_from_word(bytes)
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

    fn config() -> DetectionConfig {
        DetectionConfig {
            threshold: 4,
            suspicious_sender_domains: vec!["evil.test".into()],
            trusted_sender_domains: vec!["company.test".into()],
            suspicious_keywords: vec!["verify".into(), "password".into()],
            external_word_image_score: 5,
        }
    }

    fn bare_config() -> DetectionConfig {
        DetectionConfig {
            threshold: 5,
            suspicious_sender_domains: Vec::new(),
            trusted_sender_domains: Vec::new(),
            suspicious_keywords: Vec::new(),
            external_word_image_score: 5,
        }
    }

    #[test]
    fn detects_combined_phishing_signals() {
        let (score, _) = phishing_score(
            "fake@evil.test",
            "Verify your password",
            "https://x.test/a https://x.test/b",
            &[],
            &[],
            &[],
            &config(),
        );
        assert!(score >= 4);
    }

    #[test]
    fn trusted_sender_reduces_score() {
        let (score, _) = phishing_score(
            "notice@company.test",
            "Verify",
            "",
            &[],
            &[],
            &[],
            &config(),
        );
        assert_eq!(score, 0);
    }

    #[test]
    fn detects_external_word_image_relationship() {
        let xml = r#"<Relationships><Relationship Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="https://track.example/pixel.png" TargetMode="External" /></Relationships>"#;
        let targets = external_image_targets_from_relationships(xml);
        assert_eq!(targets, ["https://track.example/pixel.png"]);
    }

    #[test]
    fn external_word_image_reaches_default_threshold() {
        let targets = vec!["https://track.example/pixel.png".into()];
        let (score, _) = phishing_score(
            "sender@example.test",
            "Meeting",
            "",
            &[],
            &targets,
            &[],
            &config(),
        );
        assert_eq!(score, 5);
    }

    #[test]
    fn scores_qr_inline_image_as_quishing() {
        let (score, reasons) = phishing_score(
            "a@b.com",
            "主旨",
            "<img src=\"x.png\" alt=\"QR Code\">",
            &[],
            &[],
            &[],
            &bare_config(),
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
            &[],
            &[],
            &bare_config(),
        );
        assert!(score >= 3);
        assert!(reasons.iter().any(|r| r.contains("品牌偽裝")));

        let (score_momo, reasons_momo) = phishing_score(
            "MOMO會員權益 <service02@service02.6htao.com>",
            "發票中獎",
            "",
            &[],
            &[],
            &[],
            &bare_config(),
        );
        assert!(score_momo >= 3);
        assert!(reasons_momo.iter().any(|r| r.contains("品牌偽裝")));

        let (score_yahoo, reasons_yahoo) = phishing_score(
            "Yahoo 新聞 <news@social-attack.example>",
            "新聞快訊",
            "",
            &[],
            &[],
            &[],
            &bare_config(),
        );
        assert!(score_yahoo >= 3);
        assert!(reasons_yahoo.iter().any(|r| r.contains("品牌偽裝")));
    }

    #[test]
    fn does_not_score_brand_spoofing_for_official_domain() {
        let (_, reasons) = phishing_score(
            "DHL Express <noreply@dhl.com>",
            "包裹",
            "",
            &[],
            &[],
            &[],
            &bare_config(),
        );
        assert!(!reasons.iter().any(|r| r.contains("品牌偽裝")));

        let (_, reasons_momo) = phishing_score(
            "momo購物網 <service@momoshop.com.tw>",
            "發票開立",
            "",
            &[],
            &[],
            &[],
            &bare_config(),
        );
        assert!(!reasons_momo.iter().any(|r| r.contains("品牌偽裝")));

        let (_, reasons_yahoo) = phishing_score(
            "Yahoo 新聞 <news@yahoo.com.tw>",
            "新聞快訊",
            "",
            &[],
            &[],
            &[],
            &bare_config(),
        );
        assert!(!reasons_yahoo.iter().any(|r| r.contains("品牌偽裝")));
    }

    // 回歸（F1）：lookalike 網域（evil-dhl.com 等）在嚴格比對下必須觸發品牌偽裝。
    // 修正前 loose `ends_with(official)` 會把它誤判為 DHL 官方，導致攻擊者漏抓。
    #[test]
    fn scores_brand_spoofing_for_lookalike_domain() {
        let (_, reasons) = phishing_score(
            "DHL Express <noreply@evil-dhl.com>",
            "包裹",
            "",
            &[],
            &[],
            &[],
            &bare_config(),
        );
        assert!(
            reasons.iter().any(|r| r.contains("品牌偽裝")),
            "evil-dhl.com 應被判定為品牌偽裝（DHL lookalike），實際 reasons = {reasons:?}"
        );

        let (_, reasons_attack) = phishing_score(
            "DHL <noreply@attackerdhl.com>",
            "包裹",
            "",
            &[],
            &[],
            &[],
            &bare_config(),
        );
        assert!(
            reasons_attack.iter().any(|r| r.contains("品牌偽裝")),
            "attackerdhl.com 應被判定為品牌偽裝，實際 reasons = {reasons_attack:?}"
        );
    }

    // 回歸（F2）：ARC 內層 hop（i=2）的 DMARC fail 不應警告，避免 forwarding 殘留誤判。
    #[test]
    fn check_auth_failures_ignores_inner_hop_dmarc() {
        let raw = concat!(
            "From: friend@example.com\r\n",
            "Subject: hi\r\n",
            "ARC-Authentication-Results: i=2; dmarc=fail\r\n",
            "ARC-Authentication-Results: i=1; dmarc=pass\r\n",
            "Received-SPF: pass\r\n\r\n",
            "body\r\n"
        );
        let mail = parse_mail(raw.as_bytes()).expect("應可解析郵件");
        let warnings = check_auth_failures(&mail);
        assert!(
            warnings.is_empty(),
            "i=1 pass + i=2 fail 不應觸發警告，實際為 {warnings:?}"
        );
    }

    // 回歸（F2）：spf=softfail 不視為偽造（forwarding / mailing list 常見）。
    #[test]
    fn check_auth_failures_skips_spf_softfail() {
        let raw = concat!(
            "From: newsletter@example.com\r\n",
            "Subject: news\r\n",
            "Authentication-Results: i=1; spf=softfail smtp.mailfrom=example.com\r\n",
            "Received-SPF: softfail\r\n\r\n",
            "body\r\n"
        );
        let mail = parse_mail(raw.as_bytes()).expect("應可解析郵件");
        let warnings = check_auth_failures(&mail);
        assert!(
            !warnings.iter().any(|w| w.contains("SPF")),
            "spf=softfail 不應觸發 SPF 警告，實際為 {warnings:?}"
        );
    }

    // 回歸（F2）：i=1（最外層受信邊界）的 dmarc=fail 仍應觸發警告。
    #[test]
    fn check_auth_failures_trusts_boundary_i_one_dmarc_fail() {
        let raw = concat!(
            "From: spoof@evil.com\r\n",
            "Subject: urgent\r\n",
            "Authentication-Results: i=1; dmarc=fail action=quarantine\r\n\r\n",
            "body\r\n"
        );
        let mail = parse_mail(raw.as_bytes()).expect("應可解析郵件");
        let warnings = check_auth_failures(&mail);
        assert!(warnings.iter().any(|w| w.contains("DMARC")));
    }

    // 回歸（F3）：RFC 2047 編碼的中文附件檔名應在擷取時已被解碼，
    // 後續 Office / Word 副檔名比對才能命中。
    #[test]
    fn extracts_attachment_filename_decoded_from_rfc2047() {
        let raw = concat!(
            "From: x@example.com\r\n",
            "Subject: doc\r\n",
            "Content-Type: multipart/mixed; boundary=BOUND\r\n",
            "\r\n",
            "--BOUND\r\n",
            "Content-Type: application/octet-stream;\r\n",
            " name=\"=?UTF-8?B?5paH5rWL6K6u56uZ5paH5qGjLn?=\"\r\n",
            "Content-Disposition: attachment;\r\n",
            " filename=\"=?UTF-8?B?5paH5rWL6K6u56uZ5paH5qGjLmRvY3g=?=\"\r\n",
            "\r\n",
            "fake docx body\r\n",
            "--BOUND--\r\n"
        );
        let mail = parse_mail(raw.as_bytes()).expect("應可解析郵件");
        let names = extract_attachment_filenames(&mail);
        assert!(
            names.iter().any(|n| n.ends_with(".docx")),
            "RFC 2047 編碼的 .docx 附件檔名未正確解碼為中文，names = {names:?}"
        );
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

    // 對 Word 附件做解析：依副檔名（.doc/.docx/.docm/.rtf）或 MIME 判別
    #[test]
    fn word_attachments_are_selected_for_parsing() {
        let raw = concat!(
            "Content-Type: multipart/mixed; boundary=b\r\n\r\n",
            "--b\r\nContent-Disposition: attachment; filename=\"report.docx\"\r\n",
            "Content-Type: application/octet-stream\r\n\r\nzzz\r\n",
            "--b\r\nContent-Disposition: attachment; filename=\"notes.txt\"\r\n",
            "Content-Type: text/plain\r\n\r\nhello\r\n",
            "--b\r\nContent-Disposition: attachment; filename=\"news.doc\"\r\n",
            "Content-Type: application/octet-stream\r\n\r\nzzz\r\n",
            "--b\r\nContent-Disposition: attachment\r\n",
            "Content-Type: application/vnd.openxmlformats-officedocument.wordprocessingml.document\r\n\r\nzzz\r\n",
            "--b--\r\n"
        );
        let mail = parse_mail(raw.as_bytes()).expect("應可解析 multipart");
        let attachments = &mail.subparts;
        assert_eq!(attachments.len(), 4);
        assert!(is_word_part(&attachments[0]), ".docx 副檔名應命中");
        assert!(!is_word_part(&attachments[1]), ".txt 不應命中");
        assert!(is_word_part(&attachments[2]), ".doc 副檔名應命中");
        assert!(is_word_part(&attachments[3]), "Word MIME 應命中");
        // 非 zip 且非 html 內容不應 panic 且回傳空
        assert!(external_word_image_targets_from_word(b"not a zip or html").is_empty());
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
    fn parses_fenced_json_verdict() {
        let text = "```json\n{\"is_phishing\": false, \"reason\": \"正常\"}\n```";
        let verdict = parse_llm_verdict(text).expect("圍欄 JSON 應可解析");
        assert!(!verdict.is_phishing);
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
    fn rejects_invalid_verdict() {
        assert!(parse_llm_verdict("這不是 JSON").is_err());
        assert!(parse_llm_verdict("").is_err());
    }

    #[test]
    fn llm_prompt_truncates_body_and_includes_docx_hint() {
        let body = "a".repeat(5000);
        let targets = vec!["https://track.example/pixel.png".into()];
        let prompt = llm_user_prompt("a@b.com", "主旨", &body, 100, &[], &targets, &[]);
        // 內文被截斷至 100 字元
        assert!(prompt.contains(&"a".repeat(100)));
        assert!(!prompt.contains(&"a".repeat(101)));
        // 附帶 Word 外部圖片提示
        assert!(prompt.contains("外部圖片連結（追蹤）"));
        assert!(prompt.contains("https://track.example/pixel.png"));
    }

    #[test]
    fn llm_prompt_omits_docx_hint_when_empty() {
        let prompt = llm_user_prompt("a@b.com", "主旨", "內文", 100, &[], &[], &[]);
        assert!(!prompt.contains("附件提示"));
        assert!(!prompt.contains("附件清單"));
        assert!(!prompt.contains("安全驗證提示"));
    }

    #[test]
    fn llm_prompt_includes_attachment_and_auth_warnings() {
        let prompt = llm_user_prompt(
            "news@yahoo.com",
            "新聞主旨",
            "新聞內文",
            100,
            &["新聞.doc".into()],
            &["https://track.example/p.png".into()],
            &["DMARC 驗證失敗".into()],
        );
        assert!(prompt.contains("附件清單：新聞.doc"));
        assert!(
            prompt
                .contains("附件提示：Word 文件含外部圖片連結（追蹤）：https://track.example/p.png")
        );
        assert!(prompt.contains("安全驗證提示：DMARC 驗證失敗"));
    }

    #[test]
    fn detects_html_doc_external_image_relationship() {
        let html_doc = r#"
        <html>
        <head><title>News</title></head>
        <body>
        <p>新聞報導</p>
        <img src="https://attack.example/tracking.png" width="1" height="1" />
        </body>
        </html>
        "#;
        let targets = external_word_image_targets_from_word(html_doc.as_bytes());
        assert_eq!(targets, ["https://attack.example/tracking.png"]);
    }

    #[test]
    fn scores_dmarc_and_office_attachment_phishing_signals() {
        let (score, reasons) = phishing_score(
            "news@yahoo.com",
            "尼泊爾西藏洪災",
            "內文報導",
            &["災情報導.doc".into()],
            &["https://attack.example/track.png".into()],
            &["DMARC 驗證失敗（寄件者網域遭偽造）".into()],
            &config(),
        );
        // Office 附件 +2，Word 外部圖片 +5，DMARC 失敗 +4 => 11
        assert!(score >= 11);
        assert!(reasons.iter().any(|r| r.contains("Office")));
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("Word 附件含外部圖片連結"))
        );
        assert!(reasons.iter().any(|r| r.contains("DMARC")));
    }

    #[test]
    fn check_auth_failures_detects_dmarc_and_spf_fail() {
        let raw = concat!(
            "From: spoofed@yahoo.com\r\n",
            "Subject: test\r\n",
            "ARC-Authentication-Results: i=1; spf=neutral; dmarc=fail action=pct.reject\r\n",
            "Received-SPF: fail (mail.example: domain of spoofed@yahoo.com does not designate 1.2.3.4 as permitted sender)\r\n\r\n",
            "body\r\n"
        );
        let mail = parse_mail(raw.as_bytes()).expect("應可解析郵件");
        let warnings = check_auth_failures(&mail);
        assert_eq!(warnings.len(), 2);
        assert!(warnings.iter().any(|w| w.contains("DMARC")));
        assert!(warnings.iter().any(|w| w.contains("SPF")));
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

    #[test]
    fn progress_text_truncates_long_subject() {
        let long = "字".repeat(60);
        let text = progress_text(1, 2, &long);
        assert!(text.chars().count() < 60);
        assert!(text.starts_with("檢查第 1/2 封〈"));
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
    fn expand_scan_dates_expands_previous_day_and_dedups() {
        let d1 = NaiveDate::from_ymd_opt(2026, 8, 31).unwrap();
        let d0 = NaiveDate::from_ymd_opt(2026, 8, 30).unwrap();
        let expanded = expand_scan_dates(&[d1]);
        assert_eq!(expanded, vec![d0, d1]);

        let d_prev = NaiveDate::from_ymd_opt(2026, 8, 29).unwrap();
        let expanded_multi = expand_scan_dates(&[d0, d1]);
        assert_eq!(expanded_multi, vec![d_prev, d0, d1]);
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

    #[test]
    fn detects_message_read_and_unread_flags() {
        use imap::types::Flag;
        assert!(is_message_unread(&[]));
        assert!(is_message_unread(&[Flag::Flagged, Flag::Draft]));
        assert!(!is_message_unread(&[Flag::Seen]));
        assert!(!is_message_unread(&[Flag::Seen, Flag::Flagged]));
    }

    #[test]
    fn llm_config_backward_compatibility_defaults_to_api() {
        let config: Config = toml::from_str(
            r#"
            [imap]
            host = "imap.example.com"
            port = 993
            protocol = "imaps"
            username = "u"
            password = "p"
            source_mailbox = "INBOX"
            phishing_mailbox = "Spam"
            [detection]
            threshold = 5
            [llm]
            base_url = "http://localhost:11434/v1"
            model = "llama3.1"
            "#,
        )
        .unwrap();
        let effective = llm_config(&config).expect("舊版設定應自動推斷為有效 LLM");
        assert_eq!(effective.effective_backend(), Some(LlmBackend::Api));
    }

    #[test]
    fn llm_config_cli_backends_parse_and_build_commands() {
        let config_claude: LlmConfig = toml::from_str(
            r#"
            backend = "claude"
            model = "claude-3-7-sonnet"
            "#,
        )
        .unwrap();
        assert_eq!(config_claude.effective_backend(), Some(LlmBackend::Claude));
        let (prog, args) = build_cli_command(&config_claude).unwrap();
        assert_eq!(prog, "claude");
        assert!(args.contains(&"-p".to_string()));
        assert!(args.contains(&"--tools".to_string()));
        assert!(args.contains(&"--dangerously-skip-permissions".to_string()));
        assert!(args.contains(&"--model".to_string()));
        assert!(args.contains(&"claude-3-7-sonnet".to_string()));

        let config_codex: LlmConfig = toml::from_str(
            r#"
            backend = "codex"
            "#,
        )
        .unwrap();
        assert_eq!(config_codex.effective_backend(), Some(LlmBackend::Codex));
        let (prog, args) = build_cli_command(&config_codex).unwrap();
        assert_eq!(prog, "codex");
        assert!(args.contains(&"exec".to_string()));
        assert!(args.contains(&"--dangerously-bypass-approvals-and-sandbox".to_string()));
        assert!(args.contains(&"-".to_string()));

        let config_agy: LlmConfig = toml::from_str(
            r#"
            backend = "agy"
            "#,
        )
        .unwrap();
        assert_eq!(config_agy.effective_backend(), Some(LlmBackend::Agy));
        let (prog, args) = build_cli_command(&config_agy).unwrap();
        assert_eq!(prog, "agy");
        assert!(args.contains(&"--dangerously-skip-permissions".to_string()));
        assert!(args.contains(&"--output-format".to_string()));
        assert!(args.contains(&"--disable-slash-commands".to_string()));

        let config_cmd: LlmConfig = toml::from_str(
            r#"
            backend = "command"
            command = "ollama run llama3.1"
            "#,
        )
        .unwrap();
        assert_eq!(config_cmd.effective_backend(), Some(LlmBackend::Command));
        let (prog, args) = build_cli_command(&config_cmd).unwrap();
        #[cfg(windows)]
        {
            assert_eq!(prog, "cmd");
            assert_eq!(args, vec!["/C", "ollama run llama3.1"]);
        }
        #[cfg(not(windows))]
        {
            assert_eq!(prog, "sh");
            assert_eq!(args, vec!["-c", "ollama run llama3.1"]);
        }
    }
}
