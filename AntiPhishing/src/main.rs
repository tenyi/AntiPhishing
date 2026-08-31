use std::{
    cell::Cell,
    fs,
    io::{self, Cursor, Read, Write},
    net::{TcpStream, ToSocketAddrs},
    path::PathBuf,
    sync::LazyLock,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use chrono::NaiveDate;
use clap::Parser;
use imap::Session;
use mailparse::{MailHeaderMap, parse_mail};
use quick_xml::{Reader, events::Event};
use regex::Regex;
use serde::Deserialize;
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

#[derive(Clone, Deserialize)]
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

/// LLM 對單一郵件的判定結果。
#[derive(Deserialize)]
struct LlmVerdict {
    is_phishing: bool,
    #[serde(default)]
    reason: String,
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
    let mut aborted_by_llm_error = false;
    // 待搬移清單（uid、主旨、評分、理由）：LLM 模式以 LLM 判定為準，啟發式評分僅供 log 參考；
    // 未設定 LLM 時沿用傳統門檻模式（評分 ≥ threshold）。
    let mut pending: Vec<(u32, String, u32, String)> = Vec::new();
    let mut lines: Vec<String> = Vec::new();

    // 確保日期由舊到新排序且不重複，保證 UID 嚴格遞增處理
    let mut dates = args.date.clone();
    dates.sort_unstable();
    dates.dedup();

    // 進度顯示在 stderr，stdout 保留給判定結果，方便管線處理
    let progress_width = Cell::new(0usize);
    'dates: for date in &dates {
        let mut uids: Vec<u32> = session
            .uid_search(format!("ON {}", date.format("%d-%b-%Y")))
            .with_context(|| format!("搜尋 {date} 郵件失敗"))?
            .into_iter()
            .collect();
        // 由小到大排序：處理順序穩定，進度計數也與 UID 對應
        uids.sort_unstable();
        show_progress(
            &progress_width,
            format!("搜尋 {date}：找到 {} 封待檢查", uids.len()),
        );
        let total = uids.len();
        for (index, uid) in uids.into_iter().enumerate() {
            let messages = match session.uid_fetch(uid.to_string(), "RFC822") {
                Ok(messages) => messages,
                Err(error) => {
                    lines.push(format!("無法讀取郵件 UID {uid}（略過）：{error:#}"));
                    continue;
                }
            };
            let Some(message) = messages.iter().next() else {
                lines.push(format!("郵件 UID {uid} 內容為空，略過。"));
                continue;
            };
            let Some(bytes) = message.body() else {
                lines.push(format!("郵件 UID {uid} 內文為空，略過。"));
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
            show_progress(&progress_width, progress_text(index + 1, total, &subject));
            let targets = external_word_image_targets(&mail);
            let (score, reasons) =
                phishing_score(&from, &subject, &score_body, &targets, &config.detection);
            match &llm {
                Some(llm_config) => {
                    match llm_judge(llm_config, &from, &subject, &body, &targets) {
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
                    if score >= config.detection.threshold {
                        pending.push((uid, subject.clone(), score, reasons.join("；")));
                    }
                }
            }
        }
    }
    clear_progress(&progress_width);

    if aborted_by_llm_error && llm.is_some() {
        session.logout().ok();
        for line in &lines {
            println!("{line}");
        }
        println!(
            "{}：已掃描 {scanned} 封後因 LLM 判定失敗中止，未搬移。",
            dates_summary(&dates)
        );
        return Ok(());
    }

    let mut moved = 0;
    let mut failed = 0;
    if args.dry_run {
        for (uid, subject, score, reason) in &pending {
            lines.push(format!(
                "會搬移〈{subject}〉（UID {uid}，評分 {score}；{reason}）"
            ));
        }
    } else {
        // 決定要搬移的 uid：LLM 模式預設互動確認（--yes 直接全搬）；傳統模式維持自動搬移
        let mut approved: std::collections::HashSet<u32> = if llm.is_some() && !args.yes {
            confirm_move_interactive(&pending).into_iter().collect()
        } else {
            pending.iter().map(|(uid, ..)| *uid).collect()
        };
        if !approved.is_empty() {
            // 搬移前重新 SELECT 刷新狀態並比對 UIDVALIDITY，避免信箱重建後搬錯信
            match session.select(&config.imap.source_mailbox) {
                Ok(refreshed) if refreshed.uid_validity == original_uidvalidity => {}
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
                lines.push(format!("跳過搬移〈{subject}〉（評分 {score}；{reason}）"));
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
        println!("提示：在 config.toml 的 [llm] 設定 base_url 與 model 即可啟用 LLM 判定。");
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

fn dates_summary(dates: &[NaiveDate]) -> String {
    dates
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("、")
}

/// 常見快遞與電商品牌及其官方網域（小寫）：用於偵測 From 顯示名稱偽裝。
const BRAND_OFFICIAL_DOMAINS: [(&str, &[&str]); 7] = [
    ("dhl", &["dhl.com"]),
    ("fedex", &["fedex.com"]),
    ("ups", &["ups.com"]),
    ("momo", &["momoshop.com.tw", "momo.com.tw"]),
    ("pchome", &["pchome.com.tw", "pcstore.com.tw"]),
    ("shopee", &["shopee.tw", "shopee.com"]),
    ("蝦皮", &["shopee.tw", "shopee.com"]),
];

fn phishing_score(
    from: &str,
    subject: &str,
    body: &str,
    external_word_image_targets: &[String],
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
    // 品牌偽裝：From 顯示名稱含品牌（如 DHL、momo、蝦皮），但寄件網域非該品牌官方網域
    let email_domain = RE_EMAIL_DOMAIN.captures(&from).map(|c| c[1].to_string());
    let display_name = from.split('<').next().unwrap_or(from.as_str()).trim();
    if let Some(domain) = email_domain {
        for (brand, officials) in BRAND_OFFICIAL_DOMAINS {
            if display_name.contains(brand)
                && !officials.iter().any(|official| domain.ends_with(official))
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
    if !external_word_image_targets.is_empty() {
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

/// 從 DOCX 內 Word relationship XML 找出外部圖片；全程只讀取附件位元組，不開啟文件或連線。
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
            &config(),
        );
        assert!(score >= 4);
    }

    #[test]
    fn trusted_sender_reduces_score() {
        let (score, _) = phishing_score("notice@company.test", "Verify", "", &[], &config());
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
        let (score, _) = phishing_score("sender@example.test", "Meeting", "", &targets, &config());
        assert_eq!(score, 5);
    }

    #[test]
    fn scores_qr_inline_image_as_quishing() {
        let (score, reasons) = phishing_score(
            "a@b.com",
            "主旨",
            "<img src=\"x.png\" alt=\"QR Code\">",
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
            &bare_config(),
        );
        assert!(score >= 3);
        assert!(reasons.iter().any(|r| r.contains("品牌偽裝")));

        let (score_momo, reasons_momo) = phishing_score(
            "MOMO會員權益 <service02@service02.6htao.com>",
            "發票中獎",
            "",
            &[],
            &bare_config(),
        );
        assert!(score_momo >= 3);
        assert!(reasons_momo.iter().any(|r| r.contains("品牌偽裝")));
    }

    #[test]
    fn does_not_score_brand_spoofing_for_official_domain() {
        let (_, reasons) = phishing_score(
            "DHL Express <noreply@dhl.com>",
            "包裹",
            "",
            &[],
            &bare_config(),
        );
        assert!(!reasons.iter().any(|r| r.contains("品牌偽裝")));

        let (_, reasons_momo) = phishing_score(
            "momo購物網 <service@momoshop.com.tw>",
            "發票開立",
            "",
            &[],
            &bare_config(),
        );
        assert!(!reasons_momo.iter().any(|r| r.contains("品牌偽裝")));
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
