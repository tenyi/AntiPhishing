use std::{
    io::{Cursor, Read},
    sync::LazyLock,
};

use mailparse::MailHeaderMap;
use quick_xml::{Reader, events::Event};
use regex::Regex;
use zip::ZipArchive;

use crate::*;

/// 單一 .rels 檔案的解壓上限（Word 關聯檔極小，僅防壓縮炸彈）
pub const MAX_DOCX_RELS_BYTES: u64 = 8 * 1024 * 1024;

/// 解碼單一 part 的文字。mailparse 在 charset 未指定時預設 us-ascii，
/// 會把 UTF-8 高字節解成亂碼，故該情況改以 UTF-8 解碼（from_utf8_lossy）。
pub fn decode_part_text(mail: &mailparse::ParsedMail<'_>) -> Option<String> {
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
pub fn collect_text_parts(mail: &mailparse::ParsedMail<'_>, plain: &mut String, html: &mut String) {
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

pub static RE_STYLE_SCRIPT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?is)<style\b.*?</style>|<script\b.*?</script>").expect("固定正規表示式")
});

pub static RE_DATA_URI: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"data:[^"'\s>]+"#).expect("固定正規表示式"));

pub static RE_IMG_ALT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)<img\b[^>]*?\balt="([^"]*)"[^>]*>"#).expect("固定正規表示式")
});

pub static RE_HTML_TAG: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"<[^>]+>").expect("固定正規表示式"));

pub static RE_INLINE_WS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[ \t\r\f\v]+").expect("固定正規表示式"));

pub static RE_MULTIPLE_NEWLINES: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\n{3,}").expect("固定正規表示式"));

pub static RE_ANY_LINK: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"https?://").expect("固定正規表示式"));

/// 連結主機名稱段含 @（如 https://paypal.com@evil.example/），路徑與參數中的 @ 不算。
/// 主機段排除引號與角括號，避免 `<a href="https://a.com">user@a.com` 跨過標籤誤判。
pub static RE_LINK_WITH_AT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"https?://[^\s/?#"'<>]*@"#).expect("固定正規表示式"));

/// 評分前移除的「非連結網址」：DOCTYPE 宣告與 xmlns 命名空間屬性（如 w3.org、
/// schemas.microsoft.com），這些幾乎出現在每封 HTML 信中，不應計入「含多個連結」。
pub static RE_NON_LINK_URL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)<!doctype[^>]*>|\bxmlns(?::[\w-]+)?\s*=\s*(?:"[^"]*"|'[^']*')"#)
        .expect("固定正規表示式")
});

pub static RE_QR_IMAGE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"img[^>]*alt=["'][^"']*qr"#).expect("固定正規表示式"));

pub static RE_THINKING_TAGS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?is)<think(?:ing)?\b.*?</think(?:ing)?>").expect("固定正規表示式")
});

pub static RE_HTML_SIGNATURE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)<html\b|<!doctype\s+html|<body\b|<\?xml\b|<w:worddocument\b"#)
        .expect("固定正規表示式")
});

pub static RE_HTML_IMG_SRC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)<img\b[^>]*?\bsrc=["'](https?://[^"'\s>]+)["']"#).expect("固定正規表示式")
});

/// HTML 轉純文字：移除 style/script、base64 內嵌圖（保留 img 的 alt 文字，
/// 例如「QR Code」），剝離其餘標籤並解譯常見實體字。
pub fn html_to_text(html: &str) -> String {
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

/// 組裝送 LLM 的內文：text/html（轉純文字）在前、text/plain 在後。
///
/// 收件軟體實際顯示的是 HTML 版本；若 plain 在前，攻擊者可塞一大段正常 text/plain
/// 把 HTML 中的惡意內容擠出 `max_chars` 截斷範圍，讓 LLM 看不到。故 HTML 一律優先。
pub fn extract_body_text(mail: &mailparse::ParsedMail<'_>) -> (String, String) {
    let mut plain = String::new();
    let mut html = String::new();
    collect_text_parts(mail, &mut plain, &mut html);
    // 評分用原始 HTML（保留 <img alt> 等標籤特徵；噪音於 phishing_score 內清除）
    let score_body = format!("{html}\n{plain}");
    let llm_body = if html.is_empty() {
        plain
    } else {
        format!("{}\n{plain}", html_to_text(&html))
    };
    (llm_body, score_body)
}

/// 常見快遞與電商品牌及其官方網域（小寫）：用於偵測 From 顯示名稱偽裝。
/// 常見快遞與電商品牌及其官方網域（小寫）：用於偵測 From 顯示名稱偽裝。
pub const BRAND_OFFICIAL_DOMAINS: [(&str, &[&str]); 8] = [
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

/// 郵件安全驗證解析狀態（SPF / DKIM / DMARC / TLS）
#[derive(Debug, Default, Clone)]
pub struct EmailAuthStatus {
    pub spf: Option<String>,
    pub dkim: Option<String>,
    pub dmarc: Option<String>,
    pub tls: Option<String>,
    pub warnings: Vec<String>,
}

impl EmailAuthStatus {
    /// 組合給 LLM / Jev 的安全驗證狀態摘要字串
    pub fn summary(&self) -> String {
        let mut parts = Vec::new();
        if let Some(ref spf) = self.spf {
            parts.push(format!("SPF: {spf}"));
        }
        if let Some(ref dkim) = self.dkim {
            parts.push(format!("DKIM: {dkim}"));
        }
        if let Some(ref dmarc) = self.dmarc {
            parts.push(format!("DMARC: {dmarc}"));
        }
        if let Some(ref tls) = self.tls {
            parts.push(format!("TLS 傳輸加密: {tls}"));
        }
        parts.join("；")
    }

    /// 是否有受信 MTA 明確判定 DMARC 通過（From 網域對齊驗證）。
    /// 信任網域豁免必須以此為前提：「沒有失敗」不等於「通過」，
    /// 沒有任何驗證標頭或 dmarc=none 的偽造信也會沒有警示。
    pub fn dmarc_pass(&self) -> bool {
        self.dmarc.as_deref() == Some("pass")
    }
}

/// 取出驗證結果標頭的 authserv-id（收信伺服器識別），已轉小寫的標頭值。
///
/// 格式：`[i=N;] authserv-id [版本]; method=result ...`。第一個非 `i=` 片段若含 `=`，
/// 表示省略了 authserv-id（如 `i=1; dmarc=fail`），回傳 None。
pub fn auth_results_server_id(lower: &str) -> Option<&str> {
    let token = lower
        .split(';')
        .map(str::trim)
        .find(|t| !t.starts_with("i="))?;
    if token.is_empty() || token.contains('=') {
        return None;
    }
    token.split_whitespace().next()
}

/// 檢查並解析郵件驗證標頭（SPF / DKIM / DMARC / TLS）與偽造警示
///
/// 規則：
/// - 依標頭在郵件中的實際順序（由上而下）處理。MTA 會把結果加在最上方，因此每個欄位
///   以第一個（最外層、受信 MTA）結果為準，下層可能由寄件者偽造的標頭無法覆蓋。
/// - `Authentication-Results` / `ARC-Authentication-Results`：只信任 `i=1`（最外層
///   受信邊界）；沒有 `i=` 視為受信邊界（多數現代 MTA 預設）。
/// - `Received-SPF`：僅提供 SPF 結果，不解析 DKIM / DMARC。
/// - 第一個受信驗證標頭決定「我方收信伺服器」的 authserv-id；之後的標頭只有在
///   authserv-id 相同時才補齊缺少的欄位（同一台 MTA 常分寫 A-R 與 ARC-A-R）。
///   第一個標頭沒有 authserv-id 時不合併任何下層標頭，避免採用寄件者自帶的偽造結果。
/// - `dmarc=reject` 視同 `fail`；`spf=softfail` 不視為偽造（常見於 forwarding / mailing list）。
pub fn check_auth_status(mail: &mailparse::ParsedMail<'_>) -> EmailAuthStatus {
    let mut status = EmailAuthStatus::default();
    // 第一個受信驗證標頭的 authserv-id：None＝尚未遇到；Some(None)＝首個標頭未寫 id
    let mut anchor_id: Option<Option<String>> = None;
    for header in &mail.headers {
        let key = header.get_key();
        let lower = header.get_value().to_lowercase();
        if key.eq_ignore_ascii_case("Received-SPF") {
            if status.spf.is_none() {
                let value = lower.trim_start();
                status.spf = ["pass", "fail", "softfail", "neutral", "none"]
                    .into_iter()
                    .find(|r| value.starts_with(r))
                    .map(str::to_string);
            }
            continue;
        }
        if !(key.eq_ignore_ascii_case("Authentication-Results")
            || key.eq_ignore_ascii_case("ARC-Authentication-Results"))
        {
            continue;
        }
        if !matches!(parse_auth_results_instance(&lower), Some(1) | None) {
            continue;
        }
        let server_id = auth_results_server_id(&lower).map(str::to_string);
        match &anchor_id {
            // 首個受信標頭：記下收信伺服器 id
            None => anchor_id = Some(server_id),
            // 下層標頭：僅同一台收信伺服器（id 相同且非空）寫的才可補齊欄位
            Some(Some(anchor)) if server_id.as_deref() == Some(anchor.as_str()) => {}
            Some(_) => continue,
        }
        if status.dmarc.is_none() {
            status.dmarc = find_auth_result(&lower, "dmarc", &["pass", "fail", "reject", "none"])
                .map(|r| if r == "reject" { "fail" } else { r }.to_string());
        }
        if status.dkim.is_none() {
            status.dkim = find_auth_result(&lower, "dkim", &["pass", "fail", "neutral", "none"])
                .map(str::to_string);
        }
        if status.spf.is_none() {
            status.spf = find_auth_result(
                &lower,
                "spf",
                &["pass", "fail", "softfail", "neutral", "none"],
            )
            .map(str::to_string);
        }
    }

    // 依據最外層權威驗證狀態產生警告（避免轉發 hop 或信件下層殘留標頭造成警告與狀態矛盾）
    if status.dmarc.as_deref() == Some("fail") {
        status
            .warnings
            .push("DMARC 驗證失敗（寄件者網域遭偽造）".into());
    }
    if status.spf.as_deref() == Some("fail") {
        status
            .warnings
            .push("SPF 驗證失敗（發信伺服器未獲授權）".into());
    }

    // 解析傳輸加密（Received 標頭）
    for val in mail.headers.get_all_values("Received") {
        let lower = val.to_lowercase();
        if lower.contains("using tlsv1.3") || lower.contains("tlsv1.3") {
            status.tls = Some("TLSv1.3".to_string());
            break;
        } else if lower.contains("using tlsv1.2") || lower.contains("tlsv1.2") {
            status.tls = Some("TLSv1.2".to_string());
            break;
        } else if lower.contains("using tls") || lower.contains("with esmtps") {
            status.tls = Some("TLS (SMTPS)".to_string());
            break;
        }
    }

    status
}

/// 在（已轉小寫的）驗證標頭值中找出 `method=結果`，依 `results` 順序回傳第一個命中的結果
pub fn find_auth_result(
    lower: &str,
    method: &str,
    results: &[&'static str],
) -> Option<&'static str> {
    results
        .iter()
        .copied()
        .find(|r| lower.contains(&format!("{method}={r}")))
}

/// 兼容既有直接取得警示之處
#[allow(dead_code)]
pub fn check_auth_failures(mail: &mailparse::ParsedMail<'_>) -> Vec<String> {
    check_auth_status(mail).warnings
}

/// 從 Authentication-Results 標頭值中解析 `i=<n>` instance number。
pub fn parse_auth_results_instance(value: &str) -> Option<u32> {
    for token in value.split(';') {
        let token = token.trim();
        if let Some(rest) = token.strip_prefix("i=") {
            return rest.trim().parse::<u32>().ok();
        }
    }
    None
}

/// 解析 From 標頭，回傳（顯示名稱, 小寫寄件網域）。
///
/// 以 RFC 5322 位址解析取得實際寄件地址，避免顯示名稱內夾帶 `@網域` 誤導判定；
/// 僅接受單一寄件地址。無顯示名稱時以寄件地址代替，供品牌偽裝比對。
pub fn parse_sender(from: &str) -> Option<(String, String)> {
    let info = mailparse::addrparse(from).ok()?.extract_single_info()?;
    let domain = info.addr.rsplit_once('@')?.1.trim().to_lowercase();
    if domain.is_empty() {
        return None;
    }
    Some((info.display_name.unwrap_or(info.addr), domain))
}

/// 判斷郵件網域是否符合清單項目（必須全等，或是其合法的子網域）
pub fn domain_matches(email_domain: &str, listed_domain: &str) -> bool {
    let t = listed_domain.trim().trim_start_matches('@').to_lowercase();
    if t.is_empty() {
        return false;
    }
    email_domain == t || email_domain.ends_with(&format!(".{t}"))
}

/// 判斷寄件者顯示名稱是否命中品牌名稱（`brand` 為小寫）
///
/// 規則：英數品牌（如 dhl, ups, momo）前方不可緊接英數字，避免 groups / backups 誤判為 ups；
/// 後方若緊接小寫字母，僅在品牌本身為全大寫時成立（如 UPSnotify 命中、Upstream 不命中），
/// 數字與大寫字母視為邊界（如 PChome24h、DHLExpress）。中文品牌（如「蝦皮」）直接子字串比對。
pub fn matches_brand_name(display_name: &str, brand: &str) -> bool {
    if !brand.chars().all(|c| c.is_ascii_alphanumeric()) {
        return display_name.to_lowercase().contains(brand);
    }
    // to_ascii_lowercase 不改變位元組長度，索引可直接對應原字串
    let lower = display_name.to_ascii_lowercase();
    lower.match_indices(brand).any(|(idx, _)| {
        let end = idx + brand.len();
        let before_ok = !lower[..idx]
            .chars()
            .next_back()
            .is_some_and(|c| c.is_ascii_alphanumeric());
        let after_ok = match display_name[end..].chars().next() {
            Some(c) if c.is_ascii_lowercase() => !display_name[idx..end]
                .chars()
                .any(|c| c.is_ascii_lowercase()),
            _ => true,
        };
        before_ok && after_ok
    })
}

/// 檢查寄件者是否命中信任清單（不區分大小寫）
///
/// 規則：只比對實際電子郵件地址的網域，必須與信任網域完全相同，或是其合法的子網域（如 soc.hinet.net 比對 hinet.net），
/// 避免 evil-hinet.net 或顯示名稱內含關鍵字造成白名單安全豁免被繞過。
pub fn is_trusted_sender(from: &str, trusted_domains: &[String]) -> Option<String> {
    let (_, domain) = parse_sender(from)?;
    trusted_domains
        .iter()
        .find(|d| domain_matches(&domain, d))
        .map(|d| d.trim().to_string())
}

/// 取最上層 Received 標頭的來源 IP（此行由我方收信伺服器加上，寄件端無法竄改）
///
/// 常見格式為 `from <HELO> (<反解名稱> [實際IP])`：from 後第一個詞是寄件端 HELO
/// 自報值（可寫成 `[信任IP]` 偽造），伺服器實際看到的連線位址在括號註解內。規則：
/// - from 段落有括號註解時，只採用括號內的 IP（優先方括號，其次括號內最後一個詞，
///   相容 Exchange 的 `from HOST (IP)`）；Exim 的 `helo=` 值為自報，一律剔除。
/// - 沒有任何括號註解時，才採用 from 後的第一個詞（或其方括號），且必須是合法 IP
///   （部分閘道寫成 `from 203.69.82.82`）。
pub fn top_received_ip(mail: &mailparse::ParsedMail<'_>) -> Option<std::net::IpAddr> {
    let val = mail.headers.get_first_value("Received")?;
    // 標頭可能折行，先將所有空白正規化為單一空格
    let norm = val.split_whitespace().collect::<Vec<_>>().join(" ");
    let lower = norm.to_ascii_lowercase();
    let rest = lower.strip_prefix("from ")?;
    // 只看 from 段落（" by " 之後是收信伺服器自己的資訊）
    let from_part = rest.split(" by ").next().unwrap_or(rest);
    // 解析單一位址字串：去掉方括號與 IPv6 前綴（如 [IPv6:2001:db8::1]）
    let parse_ip = |s: &str| -> Option<std::net::IpAddr> {
        s.trim_matches(|c| c == '[' || c == ']')
            .trim_start_matches("ipv6:")
            .parse()
            .ok()
    };
    // 第一個詞是 HELO，括號註解從第一個 '(' 開始；HELO 不含空白，故以空白後的 '(' 為準
    let (helo, comment) = match from_part.split_once(" (") {
        Some((helo, comment)) => (helo, Some(comment)),
        None => (from_part, None),
    };
    let Some(comment) = comment else {
        return parse_ip(helo.split_whitespace().next()?);
    };
    // 剔除 Exim 的 helo=xxx（寄件端自報值）後，再找括號內的方括號 IP
    let cleaned: String = comment
        .split_whitespace()
        .filter(|word| !word.starts_with("helo="))
        .collect::<Vec<_>>()
        .join(" ");
    if let Some(start) = cleaned.find('[') {
        let inner = &cleaned[start + 1..];
        let end = inner.find(']')?;
        return parse_ip(&inner[..end]);
    }
    // 括號內無方括號：取第一段括號內最後一個詞（Exchange：from HOST (2603:10b6::1)）
    let first_group = cleaned.split(')').next()?;
    parse_ip(first_group.split_whitespace().last()?)
}

/// 信任清單判定結果
#[derive(Debug, PartialEq, Eq)]
pub enum TrustDecision {
    /// 不在信任清單
    NotListed,
    /// 豁免（說明供 log 顯示）
    Exempt(String),
    /// 命中信任清單但驗證不足，取消豁免（命中項目, 原因）
    Rejected(String, String),
}

/// 綜合信任清單與安全驗證結果，決定是否豁免（CLI、GUI、.eml 模式共用同一規則）。
///
/// - 信任網域：From 網域可被任意偽造，必須由受信 MTA 判定 DMARC=pass 才豁免；
///   沒有驗證標頭、dmarc=none 或有失敗警示都取消豁免。收信伺服器不寫 DMARC 結果時，
///   信任網域豁免等同停用（改為照常送檢，屬安全側）。
/// - 信任來源 IP：IP 取自我方收信伺服器所見的連線位址，無驗證失敗警示即豁免。
pub fn trust_decision(
    mail: &mailparse::ParsedMail<'_>,
    from: &str,
    detection: &DetectionConfig,
    auth: &EmailAuthStatus,
) -> TrustDecision {
    let mut rejected = None;
    if let Some(domain) = is_trusted_sender(from, &detection.trusted_sender_domains) {
        if !auth.warnings.is_empty() {
            rejected = Some((
                domain,
                format!("安全驗證失敗（{}）", auth.warnings.join("；")),
            ));
        } else if !auth.dmarc_pass() {
            let dmarc = auth.dmarc.as_deref().unwrap_or("無結果");
            rejected = Some((
                domain,
                format!("DMARC 未通過（{dmarc}），無法確認寄件網域未遭偽造"),
            ));
        } else {
            return TrustDecision::Exempt(format!("寄件網域 {domain}，DMARC 通過"));
        }
    }
    if let Some(ip) = top_received_ip(mail)
        && detection
            .trusted_relay_ips
            .iter()
            .any(|s| s.trim().parse::<std::net::IpAddr>().ok() == Some(ip))
    {
        if auth.warnings.is_empty() {
            return TrustDecision::Exempt(format!("來源 IP {ip}"));
        }
        if rejected.is_none() {
            rejected = Some((
                format!("來源 IP {ip}"),
                format!("安全驗證失敗（{}）", auth.warnings.join("；")),
            ));
        }
    }
    match rejected {
        Some((matched, reason)) => TrustDecision::Rejected(matched, reason),
        None => TrustDecision::NotListed,
    }
}

/// 檢查信件是否來自信任來源：先比對寄件網域，再比對最上層 Received 來源 IP
///
/// 回傳命中說明（供 log 顯示）；IP 只做完全比對，設定值無法解析為 IP 者忽略。
pub fn trusted_source(
    mail: &mailparse::ParsedMail<'_>,
    from: &str,
    detection: &DetectionConfig,
) -> Option<String> {
    if let Some(domain) = is_trusted_sender(from, &detection.trusted_sender_domains) {
        return Some(domain);
    }
    let ip = top_received_ip(mail)?;
    detection
        .trusted_relay_ips
        .iter()
        .any(|s| s.trim().parse::<std::net::IpAddr>().ok() == Some(ip))
        .then(|| format!("來源 IP {ip}"))
}

/// 收集所有附件檔名清單（供評分與 LLM 提示參考）
pub fn extract_attachment_filenames(mail: &mailparse::ParsedMail<'_>) -> Vec<String> {
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

pub fn phishing_score(
    from: &str,
    subject: &str,
    body: &str,
    attachments: &[String],
    targets: &[String],
    auth_warnings: &[String],
    config: &DetectionConfig,
) -> (u32, Vec<String>) {
    // 先清掉評分噪音：style/script、base64 內嵌圖（data: URI）、DOCTYPE 與 xmlns 網址。
    // `raw` 保留標籤供連結、@ 混淆與 QR alt 比對；`text` 剝掉標籤只供關鍵字比對，
    // 避免關鍵字（如 qr）命中 base64 內容或標籤屬性造成誤判。
    let cleaned = RE_STYLE_SCRIPT.replace_all(body, " ");
    let cleaned = RE_DATA_URI.replace_all(&cleaned, " ");
    let cleaned = RE_NON_LINK_URL.replace_all(&cleaned, " ");
    let raw = format!("{subject}\n{cleaned}").to_lowercase();
    let text = format!("{subject}\n{}", html_to_text(&cleaned)).to_lowercase();
    let sender = parse_sender(from);
    let email_domain = sender.as_ref().map(|(_, domain)| domain.as_str());
    let mut score = 0;
    let mut reasons = Vec::new();
    if email_domain.is_some_and(|domain| {
        config
            .suspicious_sender_domains
            .iter()
            .any(|d| domain_matches(domain, d))
    }) {
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
    let links = RE_ANY_LINK.find_iter(&raw).count();
    if links >= 2 {
        score += 2;
        reasons.push("含多個連結".into());
    }
    if RE_LINK_WITH_AT.is_match(&raw) {
        score += 3;
        reasons.push("連結含 @，可能偽裝網域".into());
    }
    // QR code 內嵌圖（quishing）：整封無連結、叫用戶拿手機掃碼
    if RE_QR_IMAGE.is_match(&raw) {
        score += 4;
        reasons.push("含 QR code 圖片（quishing）".into());
    }
    // 品牌偽裝：From 顯示名稱含品牌（如 DHL、momo、蝦皮、Yahoo），但寄件網域非該品牌官方網域
    if let Some((display_name, domain)) = &sender {
        for (brand, officials) in BRAND_OFFICIAL_DOMAINS {
            if matches_brand_name(display_name, brand)
                // 嚴格比對：官方網域本身或「.官方網域」結尾，避免 evil-dhl.com 偽裝
                && !officials.iter().any(|official| domain_matches(domain, official))
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
    if !targets.is_empty() {
        score += config.external_word_image_score;
        reasons.push("Word 附件含外部圖片連結".into());
    }
    // 郵件安全驗證失敗（DMARC/SPF fail）
    if !auth_warnings.is_empty() {
        score += 4;
        reasons.push(auth_warnings.join("；"));
    }
    // 信任網域減分：驗證失敗（DMARC/SPF fail）時 From 網域可能遭偽造，不予減分
    if let Some(domain) = email_domain
        && auth_warnings.is_empty()
    {
        if config
            .trusted_sender_domains
            .iter()
            .any(|d| domain_matches(domain, d))
        {
            score = score.saturating_sub(3);
            reasons.push("寄件網域在信任清單".into());
        }
    }
    (score, reasons)
}

pub fn external_word_image_targets(mail: &mailparse::ParsedMail<'_>) -> Vec<String> {
    mail.parts()
        .filter(|part| is_word_part(part))
        .filter_map(|part| part.get_body_raw().ok())
        .flat_map(|bytes| external_word_image_targets_from_word(&bytes))
        .collect()
}

/// 對 Word（docx/docm/doc/rtf）附件判定，依 MIME 或副檔名篩選。
pub fn is_word_part(part: &mailparse::ParsedMail<'_>) -> bool {
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

pub fn external_word_image_targets_from_word(bytes: &[u8]) -> Vec<String> {
    // 1. 若為 ZIP 壓縮格式（OOXML docx/docm），解析 word/_rels/*.rels 中的外部圖片關聯
    if let Ok(mut archive) = ZipArchive::new(Cursor::new(bytes)) {
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
            // 標頭宣告的大小可被竄改，實際解壓也以 take 設上限（多讀 1 byte 用來判斷是否超限）
            let mut xml = String::new();
            let read = (&mut entry)
                .take(MAX_DOCX_RELS_BYTES + 1)
                .read_to_string(&mut xml);
            if xml.len() as u64 > MAX_DOCX_RELS_BYTES {
                continue;
            }
            if read.is_ok() {
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

pub fn external_image_targets_from_relationships(xml: &str) -> Vec<String> {
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
