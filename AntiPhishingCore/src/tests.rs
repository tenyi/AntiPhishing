use crate::*;
use mailparse::{MailHeaderMap, parse_mail};
use serde::Deserialize;
use std::fs;

/// 只含 `[llm]` 段的測試用設定（其他段落由 serde 忽略）。
#[derive(Deserialize)]
struct TestConfig {
    #[serde(default)]
    llm: LlmConfig,
}

/// 建立 .eml 測試用偵測設定
fn eml_test_config(extra_detection: &str) -> DetectionConfig {
    toml::from_str(extra_detection).unwrap()
}

fn test_detection_config() -> DetectionConfig {
    DetectionConfig {
        threshold: 8,
        suspicious_sender_domains: Vec::new(),
        trusted_sender_domains: Vec::new(),
        trusted_relay_ips: Vec::new(),
        suspicious_keywords: Vec::new(),
        external_word_image_score: 6,
    }
}

fn config() -> DetectionConfig {
    DetectionConfig {
        threshold: 4,
        suspicious_sender_domains: vec!["evil.test".into()],
        trusted_sender_domains: vec!["company.test".into()],
        trusted_relay_ips: Vec::new(),
        suspicious_keywords: vec!["verify".into(), "password".into()],
        external_word_image_score: 6,
    }
}

fn bare_config() -> DetectionConfig {
    DetectionConfig {
        threshold: 8,
        suspicious_sender_domains: Vec::new(),
        trusted_sender_domains: Vec::new(),
        trusted_relay_ips: Vec::new(),
        suspicious_keywords: Vec::new(),
        external_word_image_score: 6,
    }
}

#[test]
fn detects_external_word_image_relationship() {
    let xml = r#"<Relationships><Relationship Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="https://track.example/pixel.png" TargetMode="External" /></Relationships>"#;
    assert_eq!(
        external_image_targets_from_relationships(xml),
        ["https://track.example/pixel.png"]
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
    let verdict = parse_llm_verdict(r#"{"is_phishing": true, "reason": "惡意行銷廣告與推銷商品"}"#)
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
    if let Ok(bytes) = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../AntiPhishingGUI/Spam.eml"
    )) {
        let mail = parse_mail(&bytes).expect("Spam.eml 應可解析");
        let from = mail.headers.get_first_value("From").unwrap_or_default();
        let subject = mail.headers.get_first_value("Subject").unwrap_or_default();
        let (llm_body, _) = extract_body_text(&mail);
        assert!(from.contains("fote-hotel.biz") || from.contains("Waterfal"));
        assert!(subject.contains("裝飾") || subject.contains("健康"));
        assert!(llm_body.contains("Spirual") || llm_body.contains("香薰"));
        let prompt = llm_user_prompt(&from, &subject, &llm_body, 6000, &[], &[], "", &[]);
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
    let prompt = llm_user_prompt("a@b.com", "主旨", &body, 100, &[], &targets, "", &[]);
    // 內文被截斷至 100 字元
    assert!(prompt.contains(&"a".repeat(100)));
    assert!(!prompt.contains(&"a".repeat(101)));
    // 附帶 Word 外部圖片提示
    assert!(prompt.contains("外部圖片連結（追蹤）"));
    assert!(prompt.contains("https://track.example/pixel.png"));
}

#[test]
fn llm_prompt_omits_docx_hint_when_empty() {
    let prompt = llm_user_prompt("a@b.com", "主旨", "內文", 100, &[], &[], "", &[]);
    assert!(!prompt.contains("附件提示"));
    assert!(!prompt.contains("附件清單"));
    assert!(!prompt.contains("安全驗證警示"));
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
        "SPF: pass；DKIM: pass；DMARC: pass；TLS 傳輸加密: TLSv1.3",
        &["DMARC 驗證失敗".into()],
    );
    assert!(prompt.contains("附件清單：新聞.doc"));
    assert!(
        prompt.contains("附件提示：Word 文件含外部圖片連結（追蹤）：https://track.example/p.png")
    );
    assert!(
        prompt.contains("安全驗證狀態：SPF: pass；DKIM: pass；DMARC: pass；TLS 傳輸加密: TLSv1.3")
    );
    assert!(prompt.contains("安全驗證警示：DMARC 驗證失敗"));
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
        &test_detection_config(),
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
        "Received-SPF: fail (mail.example: domain of spoofed@yahoo.com does not designate 1.2.3.4 as permitted sender)\r\n",
        "ARC-Authentication-Results: i=1; spf=neutral; dmarc=fail action=pct.reject\r\n\r\n",
        "body\r\n"
    );
    let mail = parse_mail(raw.as_bytes()).expect("應可解析郵件");
    let warnings = check_auth_failures(&mail);
    assert_eq!(warnings.len(), 2);
    assert!(warnings.iter().any(|w| w.contains("DMARC")));
    assert!(warnings.iter().any(|w| w.contains("SPF")));
}

#[test]
fn detection_config_defaults() {
    let toml_str = r#"
        suspicious_sender_domains = []
    "#;
    let cfg: DetectionConfig = toml::from_str(toml_str).unwrap();
    assert_eq!(cfg.threshold, 8);
    assert_eq!(cfg.external_word_image_score, 6);
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
fn scores_qr_inline_image_as_quishing() {
    let (score, reasons) = phishing_score(
        "a@b.com",
        "主旨",
        "<img src=\"x.png\" alt=\"QR Code\">",
        &[],
        &[],
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
        &[],
        &[],
        &test_detection_config(),
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
        &test_detection_config(),
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
        &test_detection_config(),
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
        &test_detection_config(),
    );
    assert!(!reasons.iter().any(|r| r.contains("品牌偽裝")));

    let (_, reasons_momo) = phishing_score(
        "momo購物網 <service@momoshop.com.tw>",
        "發票開立",
        "",
        &[],
        &[],
        &[],
        &test_detection_config(),
    );
    assert!(!reasons_momo.iter().any(|r| r.contains("品牌偽裝")));

    let (_, reasons_yahoo) = phishing_score(
        "Yahoo 新聞 <news@yahoo.com.tw>",
        "新聞快訊",
        "",
        &[],
        &[],
        &[],
        &test_detection_config(),
    );
    assert!(!reasons_yahoo.iter().any(|r| r.contains("品牌偽裝")));
}

// 回歸（F1）：lookalike 網域在嚴格比對下必須觸發品牌偽裝。
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
        &test_detection_config(),
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
        &test_detection_config(),
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

// 回歸（F3）：RFC 2047 編碼的中文附件檔名應在擷取時已被 mailparse 解碼。
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
fn parses_momospam_eml_and_verifies_detection() {
    let eml_bytes = fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../AntiPhishingGUI/momoSpam.eml"
    ))
    .expect("應可讀取 momoSpam.eml");
    let mail = mailparse::parse_mail(&eml_bytes).expect("應可解析郵件");
    let from = mail.headers.get_first_value("From").unwrap_or_default();
    let subject = mail.headers.get_first_value("Subject").unwrap_or_default();
    let (body, score_body) = extract_body_text(&mail);
    let attachments = extract_attachment_filenames(&mail);
    let targets = external_word_image_targets(&mail);
    let auth_status = check_auth_status(&mail);
    let auth_warnings = &auth_status.warnings;
    let auth_summary = auth_status.summary();
    let detection_cfg = test_detection_config();
    let (score, reasons) = phishing_score(
        &from,
        &subject,
        &score_body,
        &attachments,
        &targets,
        auth_warnings,
        &detection_cfg,
    );
    let prompt = llm_user_prompt(
        &from,
        &subject,
        &body,
        4000,
        &attachments,
        &targets,
        &auth_summary,
        auth_warnings,
    );

    println!("=== momoSpam.eml 解析結果 ===");
    println!("From: {from}");
    println!("Subject: {subject}");
    println!("Score: {score}");
    println!("Reasons: {reasons:?}");
    println!("Prompt:\n{prompt}");

    assert!(from.contains("6htao.com"));
    assert!(subject.contains("momo購物網"));
    assert!(score >= 5);
    assert!(reasons.iter().any(|r| r.contains("品牌偽裝")));
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
    let config: TestConfig = toml::from_str(
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
        [gui]
        [llm]
        base_url = "http://localhost:11434/v1"
        model = "llama3.1"
        "#,
    )
    .unwrap();
    let effective = llm_config(&config.llm).expect("舊版設定應自動推斷為有效 LLM");
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

#[test]
fn llm_config_jev_backend_parsing() {
    for alias in &["jev", "typesafe", "systemone"] {
        let config_text = format!(
            r#"
            backend = "{alias}"
            api_key = "test-key"
            "#
        );
        let config: LlmConfig = toml::from_str(&config_text).unwrap();
        assert_eq!(config.effective_backend(), Some(LlmBackend::Jev));
    }

    let toml_without_key = r#"
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
        [gui]
        [llm]
        backend = "jev"
        "#;
    let config_no_key: TestConfig = toml::from_str(toml_without_key).unwrap();
    assert!(
        llm_config(&config_no_key.llm).is_none(),
        "Jev 後端若無 api_key 應為無效"
    );

    let toml_with_key = r#"
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
        [gui]
        [llm]
        backend = "jev"
        api_key = "sk-typesafe-123"
        jev_max_score = 6
        "#;
    let config_with_key: TestConfig = toml::from_str(toml_with_key).unwrap();
    let effective = llm_config(&config_with_key.llm).expect("具備 api_key 應為有效 Jev 設定");
    assert_eq!(effective.effective_backend(), Some(LlmBackend::Jev));
    assert_eq!(effective.jev_max_score, 6);
}

#[test]
fn parse_jev_probability_noul_and_score() {
    let json_noul = serde_json::json!({
        "model": "jev-1.13.0",
        "answers": {
            "is_phishing": {
                "type": "noul",
                "noul": 0.88
            }
        }
    });
    let prob = parse_jev_probability(&json_noul).expect("應解析 noul 機率");
    assert!((prob - 0.88).abs() < 1e-6);

    let json_clamped = serde_json::json!({
        "answers": {
            "is_phishing": {
                "type": "noul",
                "noul": 1.25
            }
        }
    });
    let clamped = parse_jev_probability(&json_clamped).expect("超過 1.0 應被 clamp");
    assert_eq!(clamped, 1.0);

    let json_score = serde_json::json!({
        "answers": {
            "is_phishing": {
                "type": "score",
                "score": 0.72
            }
        }
    });
    // score 為層級加權索引而非機率，不可當作備援
    assert!(parse_jev_probability(&json_score).is_err());
}

#[test]
fn jev_endpoint_normalization() {
    let expect = "http://127.0.0.1:11434/v1/systemone";
    for base in &[
        "http://127.0.0.1:11434",
        "http://127.0.0.1:11434/",
        "http://127.0.0.1:11434/v1",
        "http://127.0.0.1:11434/v1/",
        "http://127.0.0.1:11434/v1/systemone",
    ] {
        assert_eq!(jev_endpoint(base), expect, "base_url = {base}");
    }
    assert_eq!(jev_endpoint(""), "https://api.typesafe.ai/v1/systemone");
    assert_eq!(
        jev_endpoint("https://api.typesafe.ai/"),
        "https://api.typesafe.ai/v1/systemone"
    );
}

#[test]
fn nimble_model_detection_and_config() {
    assert!(is_nimble_model("nimble"));
    assert!(is_nimble_model(" Nimble:latest "));
    assert!(!is_nimble_model(""));
    assert!(!is_nimble_model("jev-latest"));

    let make = |llm: &str| -> TestConfig {
        toml::from_str(&format!(
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
            [gui]
            [llm]
            backend = "jev"
            {llm}
            "#
        ))
        .unwrap()
    };
    // Nimble + base_url：免金鑰即有效
    assert!(
        llm_config(
            &make(
                r#"model = "nimble"
            base_url = "http://127.0.0.1:11434""#
            )
            .llm
        )
        .is_some()
    );
    // Nimble 缺 base_url：無效（不得退回雲端）
    assert!(llm_config(&make(r#"model = "nimble""#).llm).is_none());
    // model 留空（Jev）仍須金鑰
    assert!(llm_config(&make(r#"base_url = "http://127.0.0.1:11434""#).llm).is_none());
}

#[test]
fn parse_jev_probability_nimble_response() {
    let resp = serde_json::json!({
        "model": "nimble",
        "answers": { "is_phishing": { "type": "noul", "noul": 0.997 } },
        "usage": { "prompt_tokens": 10 }
    });
    assert!((parse_jev_probability(&resp).unwrap() - 0.997).abs() < 1e-9);
    assert!(parse_jev_probability(&serde_json::json!({"answers": {}})).is_err());
}

#[test]
fn jev_question_differs_by_model() {
    // Nimble：排除條件在 instructions，且不送 criteria
    let nimble = jev_question("nimble");
    assert!(nimble.get("criteria").is_none());
    assert!(
        nimble["instructions"]
            .as_str()
            .unwrap()
            .contains("垃圾信隔離明細")
    );
    // 雲端 Jev（含 model 留空）：維持原本帶 criteria 的寫法
    for model in ["", "jev-latest"] {
        let jev = jev_question(model);
        assert!(jev.get("criteria").is_some(), "model = {model:?}");
        assert_eq!(jev["type"], "noul");
    }
}

#[test]
fn top_received_ip_only_trusts_server_observed_address() {
    let ip = |raw: &str| top_received_ip(&mailparse::parse_mail(raw.as_bytes()).unwrap());
    // 上級單位閘道格式：from 後直接是 IP
    assert_eq!(
        ip("Received: from 203.69.82.82\r\nReceived: By OpenMail Mailer\r\n\r\nb"),
        Some("203.69.82.82".parse().unwrap())
    );
    // 有方括號時以伺服器實際看到的連線 IP 為準，HELO 自報的 IP 不可信
    assert_eq!(
        ip(
            "Received: from 192.168.10.254 (evil.example [198.51.100.9])\r\n by mx.local; Thu\r\n\r\nb"
        ),
        Some("198.51.100.9".parse().unwrap())
    );
    // 只看最上層：下層的 Received 可由寄件端偽造
    assert_eq!(
        ip("Received: from mx.local ([10.0.0.1]) by a\r\nReceived: from 192.168.10.254\r\n\r\nb"),
        Some("10.0.0.1".parse().unwrap())
    );
    // by 段落是收信端自身資訊，不得當作來源
    assert_eq!(
        ip("Received: from host.example by 192.168.10.254\r\n\r\nb"),
        None
    );
    assert_eq!(ip("Subject: x\r\n\r\nb"), None);
}

#[test]
fn trusted_relay_ip_exempts_mail_unless_auth_fails() {
    let config = eml_test_config("trusted_relay_ips = [\"192.168.10.254\"]");
    let mut failures = 0;
    let ok = "Received: from 192.168.10.254\r\nFrom: a@inside.test\r\nSubject: s\r\n\r\nverify password http://a http://b\r\n";
    let ev = evaluate_mail(ok.as_bytes(), &config, &None, &mut failures).unwrap();
    assert_eq!(ev.basis, "信任寄件者豁免");
    // 不在清單內的 IP 照常評分
    let other = ok.replace("192.168.10.254", "192.168.10.253");
    let ev = evaluate_mail(other.as_bytes(), &config, &None, &mut failures).unwrap();
    assert_ne!(ev.basis, "信任寄件者豁免");
    // 驗證失敗時不豁免，與信任網域規則一致
    let bad = format!("Authentication-Results: i=1; spf=fail; dmarc=fail\r\n{ok}");
    let ev = evaluate_mail(bad.as_bytes(), &config, &None, &mut failures).unwrap();
    assert_ne!(ev.basis, "信任寄件者豁免");
}

#[test]
fn link_with_at_only_flags_userinfo_obfuscation() {
    // 真正的混淆手法：@ 在主機名稱段，瀏覽器實際連到 evil.example
    assert!(RE_LINK_WITH_AT.is_match("https://paypal.com@evil.example/login"));
    assert!(RE_LINK_WITH_AT.is_match("http://user:pw@evil.example"));
    // 垃圾信閘道明細的連結：@ 只出現在路徑或參數中，不是偽裝網域
    assert!(
        !RE_LINK_WITH_AT
            .is_match("https://mxs.mailcloud.com.tw/mg-cgi/mail_read?MAILBOX=@.spam&MSG=X")
    );
    assert!(!RE_LINK_WITH_AT.is_match("https://a.example/u/a@b.example"));
    assert!(!RE_LINK_WITH_AT.is_match("https://a.example#x@y"));
}

#[test]
fn jev_min_prob_is_configurable() {
    // 起算機率 0：0~100% 全程線性給分
    assert_eq!(calculate_jev_points(0.0, 10, 0.0), 0);
    assert_eq!(calculate_jev_points(0.5, 10, 0.0), 5);
    assert_eq!(calculate_jev_points(1.0, 10, 0.0), 10);
    // 起算機率 0.4：0.58 計 (0.58-0.4)/0.6*10 = 3 分，0.39 不計分
    assert_eq!(calculate_jev_points(0.58, 10, 0.4), 3);
    assert_eq!(calculate_jev_points(0.39, 10, 0.4), 0);
    // 異常值被限制，不得除以 0 或產生超過上限的分數
    assert_eq!(calculate_jev_points(1.0, 10, 1.0), 10);
    assert_eq!(calculate_jev_points(1.0, 10, -1.0), 10);
    // 設定檔未填時預設 0.6，與舊行為一致
    assert_eq!(default_jev_min_prob(), 0.6);
}

#[test]
fn jev_composite_scoring_calculation() {
    let max_score = 5u32;

    // < 0.6 不計分
    assert_eq!(calculate_jev_points(0.15, max_score, 0.6), 0);
    assert_eq!(calculate_jev_points(0.55, max_score, 0.6), 0);
    assert_eq!(calculate_jev_points(0.599, max_score, 0.6), 0);

    // 0.6 ~ 1.0 依比例線性換算：((prob - 0.6) / 0.4) * 5
    // 0.60: 0.0 * 5 = 0
    assert_eq!(calculate_jev_points(0.60, max_score, 0.6), 0);
    // 0.70: 0.25 * 5 = 1.25 -> 1
    assert_eq!(calculate_jev_points(0.70, max_score, 0.6), 1);
    // 0.80: 0.50 * 5 = 2.50 -> 3
    assert_eq!(calculate_jev_points(0.80, max_score, 0.6), 3);
    // 0.88: 0.70 * 5 = 3.50 -> 4
    assert_eq!(calculate_jev_points(0.88, max_score, 0.6), 4);
    // 0.90: 0.75 * 5 = 3.75 -> 4
    assert_eq!(calculate_jev_points(0.90, max_score, 0.6), 4);
    // 1.00: 1.00 * 5 = 5.00 -> 5
    assert_eq!(calculate_jev_points(1.00, max_score, 0.6), 5);

    // 基礎規則評分 2 分 + Jev (0.88 -> 4分) = 6 分 (超過 threshold 5)
    let base_score = 2u32;
    let points = calculate_jev_points(0.88, max_score, 0.6);
    let final_score = base_score + points;
    assert_eq!(final_score, 6);
    assert!(final_score >= 5);

    // 低機率 0.55 -> 0分，最終得分 2 分 (未達 threshold 5)
    let low_points = calculate_jev_points(0.55, max_score, 0.6);
    assert_eq!(low_points, 0);
    let low_final = base_score + low_points;
    assert_eq!(low_final, 2);
    assert!(low_final < 5);

    // 驗證預設 jev_max_score = 10 的換算與門檻 8
    let max_score_10 = default_jev_max_score();
    assert_eq!(max_score_10, 10);
    assert_eq!(calculate_jev_points(0.55, max_score_10, 0.6), 0);
    assert_eq!(calculate_jev_points(0.80, max_score_10, 0.6), 5);
    assert_eq!(calculate_jev_points(0.88, max_score_10, 0.6), 7);
    assert_eq!(calculate_jev_points(1.00, max_score_10, 0.6), 10);

    // 基礎規則評分 2 分 + Jev (0.88 -> 7分) = 9 分 (超過預設門檻 8)
    let points_10 = calculate_jev_points(0.88, max_score_10, 0.6);
    let final_score_10 = base_score + points_10;
    assert_eq!(final_score_10, 9);
    assert!(final_score_10 >= default_threshold());

    // 低機率 0.55 -> 0分，最終得分 2 分 (未達預設門檻 8)
    let low_final_10 = base_score + calculate_jev_points(0.55, max_score_10, 0.6);
    assert_eq!(low_final_10, 2);
    assert!(low_final_10 < default_threshold());
}

#[test]
fn test_is_trusted_sender_matching() {
    let trusted = vec![
        "soc.hinet.net".to_string(),
        "internal.corp".to_string(),
        "hinet.net".to_string(),
    ];
    // 完全匹配
    assert_eq!(
        is_trusted_sender("Hinet SOC 病毒回報 <soc-report@soc.hinet.net>", &trusted),
        Some("soc.hinet.net".to_string())
    );
    // 大小寫不敏感與子網域匹配
    assert_eq!(
        is_trusted_sender("Service <notice@HiNet.Net>", &["hinet.net".to_string()]),
        Some("hinet.net".to_string())
    );
    assert_eq!(
        is_trusted_sender("Alert <notify@sub.hinet.net>", &["hinet.net".to_string()]),
        Some("hinet.net".to_string())
    );
    // 設定帶有 @ 前綴之信任網域
    assert_eq!(
        is_trusted_sender("Service <admin@corp.com>", &["@corp.com".to_string()]),
        Some("@corp.com".to_string())
    );
    // 外部不相干網域
    assert_eq!(
        is_trusted_sender("Attacker <evil@phishing.com>", &trusted),
        None
    );
    // 攻擊場景 1：包含信任網域字串之相似網域（不得命中！）
    assert_eq!(
        is_trusted_sender("Attacker <evil@evil-hinet.net>", &trusted),
        None
    );
    assert_eq!(
        is_trusted_sender("Attacker <evil@hinet.net.attacker.com>", &trusted),
        None
    );
    // 攻擊場景 2：顯示名稱內含信任網域名稱（不得命中！）
    assert_eq!(
        is_trusted_sender("\"hinet.net\" <attacker@phishing-server.com>", &trusted),
        None
    );
    assert_eq!(
        is_trusted_sender("Hinet Support (hinet.net) <fake@badguy.org>", &trusted),
        None
    );
}

#[test]
fn test_brand_spoofing_word_boundary() {
    let config = test_detection_config();

    // 正常郵件：Google Groups（包含 ups 子字串），發信網域 google.com 不應被誤判為 UPS 品牌偽裝
    let (score_groups, reasons_groups) = phishing_score(
        "Google Groups <groups-noreply@google.com>",
        "Weekly Digest",
        "Here is your update",
        &[],
        &[],
        &[],
        &config,
    );
    assert!(
        !reasons_groups.iter().any(|r| r.contains("品牌偽裝")),
        "Google Groups 不應被誤判為 UPS 品牌偽裝，得分理由：{reasons_groups:?}"
    );
    assert_eq!(score_groups, 0);

    // 真正偽造 UPS：顯示名稱獨立出現 UPS，但網域為 attacker.com -> 應觸發品牌偽裝
    let (score_ups, reasons_ups) = phishing_score(
        "UPS Express Tracking <tracking@attacker.com>",
        "Your package is arriving",
        "Click here to track",
        &[],
        &[],
        &[],
        &config,
    );
    assert!(
        reasons_ups
            .iter()
            .any(|r| r.contains("品牌偽裝：顯示名稱含 ups")),
        "UPS 顯示名稱偽裝應被偵測，實際得分理由：{reasons_ups:?}"
    );
    assert!(score_ups >= 3);
}

#[test]
fn test_auth_status_forged_lower_headers_cannot_override() {
    // 受信 MTA 在最上方寫入 spf=fail / ARC dmarc=fail；下方偽造的 Received-SPF 與 A-R pass 不得覆蓋
    let raw = concat!(
        "Authentication-Results: mx.mycompany.com; spf=fail smtp.mailfrom=x@evil.com\r\n",
        "ARC-Authentication-Results: i=1; mx.mycompany.com; dmarc=fail\r\n",
        "Received-SPF: Pass (forged)\r\n",
        "Authentication-Results: forged.example; dmarc=pass\r\n",
        "From: x@evil.com\r\n\r\n",
        "body\r\n"
    );
    let mail = mailparse::parse_mail(raw.as_bytes()).unwrap();
    let status = check_auth_status(&mail);
    assert_eq!(status.spf.as_deref(), Some("fail"));
    assert_eq!(status.dmarc.as_deref(), Some("fail"));
    assert_eq!(status.warnings.len(), 2);
}

#[test]
fn test_auth_status_dmarc_reject_maps_to_fail() {
    let raw = "Authentication-Results: mx.example.com; dmarc=reject\r\n\r\nbody\r\n";
    let mail = mailparse::parse_mail(raw.as_bytes()).unwrap();
    let status = check_auth_status(&mail);
    assert_eq!(status.dmarc.as_deref(), Some("fail"));
    assert!(status.summary().contains("DMARC: fail"));
}

#[test]
fn test_trusted_sender_display_name_address_not_trusted() {
    let trusted = vec!["hinet.net".to_string()];
    assert_eq!(
        is_trusted_sender("\"admin@hinet.net\" <x@evil.com>", &trusted),
        None
    );
    assert_eq!(
        is_trusted_sender("admin@hinet.net <x@evil.com>", &trusted),
        None
    );
}

#[test]
fn test_brand_name_boundary_variants() {
    assert!(matches_brand_name("PChome24h購物", "pchome"));
    assert!(matches_brand_name("DHLExpress", "dhl"));
    assert!(matches_brand_name("UPSnotify", "ups"));
    assert!(matches_brand_name("蝦皮購物", "蝦皮"));
    assert!(!matches_brand_name("Upstream News", "ups"));
    assert!(!matches_brand_name("Offsite Backups", "ups"));
}

#[test]
fn test_suspicious_domain_matches_address_only() {
    let mut config = test_detection_config();
    config.suspicious_sender_domains = vec!["phish.com".into(), "bad.co".into()];
    let (_, reasons) = phishing_score(
        "\"Report about phish.com\" <sec@corp.com>",
        "hi",
        "hello",
        &[],
        &[],
        &[],
        &config,
    );
    assert!(!reasons.iter().any(|r| r.contains("可疑清單")));
    let (_, reasons) = phishing_score("x <a@bad.com>", "hi", "hello", &[], &[], &[], &config);
    assert!(!reasons.iter().any(|r| r.contains("可疑清單")));
    let (_, reasons) = phishing_score(
        "x <a@mail.phish.com>",
        "hi",
        "hello",
        &[],
        &[],
        &[],
        &config,
    );
    assert!(reasons.iter().any(|r| r.contains("可疑清單")));
}

#[test]
fn test_check_auth_status_outer_pass_not_polluted_by_inner_fail() {
    // 第一層（最外層 MTA）判定 dmarc=pass，第二層（轉寄節點）殘留 dmarc=fail
    let raw = concat!(
        "From: friend@example.com\r\n",
        "Authentication-Results: mx.mycompany.com; dkim=pass; spf=pass; dmarc=pass\r\n",
        "Authentication-Results: forwarder.com; dmarc=fail\r\n\r\n",
        "Hello, this is a forwarded email.\r\n"
    );
    let mail = mailparse::parse_mail(raw.as_bytes()).unwrap();
    let status = check_auth_status(&mail);
    assert_eq!(status.dmarc.as_deref(), Some("pass"));
    assert!(
        status.warnings.is_empty(),
        "外層 pass 時不應被後續轉發節點的 fail 污染產生警告，實際 warnings: {:?}",
        status.warnings
    );
}

#[test]
fn test_check_auth_status_pass_and_tls_summary() {
    let raw = concat!(
        "From: Service <service@example.com>\r\n",
        "Authentication-Results: mx.example.com; dkim=pass header.i=@example.com; spf=pass smtp.mailfrom=service@example.com; dmarc=pass\r\n",
        "Received: from mail.example.com by mx.example.com with ESMTPS (using TLSv1.3)\r\n",
        "\r\n",
        "This is a legitimate system notification.\r\n"
    );
    let mail = mailparse::parse_mail(raw.as_bytes()).unwrap();
    let status = check_auth_status(&mail);
    assert_eq!(status.spf.as_deref(), Some("pass"));
    assert_eq!(status.dkim.as_deref(), Some("pass"));
    assert_eq!(status.dmarc.as_deref(), Some("pass"));
    assert_eq!(status.tls.as_deref(), Some("TLSv1.3"));
    assert!(status.warnings.is_empty());
    let summary = status.summary();
    assert!(summary.contains("SPF: pass"));
    assert!(summary.contains("DKIM: pass"));
    assert!(summary.contains("DMARC: pass"));
    assert!(summary.contains("TLS 傳輸加密: TLSv1.3"));
}

#[test]
fn normalize_eml_bytes_strips_bom_and_mbox_line() {
    assert_eq!(
        normalize_eml_bytes(b"\xEF\xBB\xBFSubject: a"),
        b"Subject: a"
    );
    assert_eq!(
        normalize_eml_bytes(b"From me@x.com Mon Jan 1\nSubject: a"),
        b"Subject: a"
    );
    // From: 標頭不可被誤刪
    assert_eq!(normalize_eml_bytes(b"From: a@x.com\n"), b"From: a@x.com\n");
}

#[test]
fn collect_eml_paths_filters_sorts_and_rejects_missing() {
    let dir = std::env::temp_dir().join(format!("ap_eml_test_{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("b.eml"), "x").unwrap();
    fs::write(dir.join("a.EML"), "x").unwrap();
    fs::write(dir.join("c.txt"), "x").unwrap();
    let paths = collect_eml_paths(std::slice::from_ref(&dir)).unwrap();
    let names: Vec<_> = paths
        .iter()
        .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, ["a.EML", "b.eml"]);
    assert!(collect_eml_paths(&[dir.join("missing.eml")]).is_err());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn evaluate_mail_reports_auth_and_rule_score_without_llm() {
    let config = eml_test_config("");
    let mut failures = 0;
    let benign = "From: a@example.org\r\nSubject: hello\r\n\r\nsee you tomorrow\r\n";
    let ev = evaluate_mail(benign.as_bytes(), &config, &None, &mut failures).unwrap();
    // 沒有驗證標頭時摘要為空（輸出端顯示「無驗證標頭」，不可誤當作 pass）
    assert!(ev.auth_summary.is_empty());
    assert!(!ev.flagged);

    let forged = concat!(
        "ARC-Authentication-Results: i=1; dmarc=fail\r\n",
        "From: DHL Express <x@evil.example>\r\n",
        "Subject: urgent verify password\r\n\r\n",
        "login now http://a.example/x http://b.example/y\r\n"
    );
    let ev = evaluate_mail(forged.as_bytes(), &config, &None, &mut failures).unwrap();
    assert!(!ev.auth_warnings.is_empty());
    assert!(ev.rule_score > 0);
    assert_eq!(ev.basis, "傳統規則");
}

#[test]
fn evaluate_mail_exempts_trusted_sender_but_not_when_auth_fails() {
    let config = eml_test_config("trusted_sender_domains = [\"example.com\"]");
    let mut failures = 0;
    let ok = "Authentication-Results: i=1; spf=pass; dmarc=pass\r\nFrom: a@example.com\r\nSubject: s\r\n\r\nb\r\n";
    let ev = evaluate_mail(ok.as_bytes(), &config, &None, &mut failures).unwrap();
    assert_eq!(ev.basis, "信任寄件者豁免");
    assert!(!ev.flagged);

    let forged =
        "Authentication-Results: i=1; dmarc=fail\r\nFrom: a@example.com\r\nSubject: s\r\n\r\nb\r\n";
    let ev = evaluate_mail(forged.as_bytes(), &config, &None, &mut failures).unwrap();
    // 驗證失敗取消豁免，必須照一般流程評分
    assert_ne!(ev.basis, "信任寄件者豁免");
}

#[test]
fn evaluate_mail_breaker_skips_llm_after_three_failures() {
    let config = eml_test_config("");
    let llm = Some(toml::from_str::<LlmConfig>("backend = \"command\"\ncommand = \"x\"").unwrap());
    let mut failures = 3;
    let mail = "From: a@example.org\r\nSubject: hi\r\n\r\nbody\r\n";
    let ev = evaluate_mail(mail.as_bytes(), &config, &llm, &mut failures).unwrap();
    // 熔斷時不得呼叫 LLM（否則會執行 command），直接採規則分
    assert_eq!(ev.basis, "規則（LLM 熔斷）");
    assert_eq!(failures, 3);
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
fn external_word_image_scores_configured_value() {
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
    assert_eq!(score, 6);
}
