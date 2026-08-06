use std::{
    fs,
    io::{Cursor, Read},
    path::PathBuf,
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

#[derive(Parser, Debug)]
#[command(about = "依指定日期掃描 IMAP 信箱，將疑似釣魚郵件移至指定信箱")]
struct Args {
    /// 要掃描的日期，格式 YYYY-MM-DD。
    #[arg(long)]
    date: NaiveDate,

    /// 設定檔路徑。
    #[arg(long, default_value = "config.toml")]
    config: PathBuf,

    /// 只列出判定結果，不實際搬移郵件。
    #[arg(long)]
    dry_run: bool,
}

#[derive(Deserialize)]
struct Config {
    imap: ImapConfig,
    detection: DetectionConfig,
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
    /// 總分達到此值才移動；建議先以 --dry-run 校正。
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

fn main() -> Result<()> {
    let args = Args::parse();
    let config: Config = toml::from_str(
        &fs::read_to_string(&args.config)
            .with_context(|| format!("無法讀取設定檔：{}", args.config.display()))?,
    )
    .context("設定檔 TOML 格式不正確")?;

    let mut session = connect(&config.imap)?;
    session
        .select(&config.imap.source_mailbox)
        .with_context(|| format!("無法開啟來源信箱：{}", config.imap.source_mailbox))?;

    let query = format!("ON {}", args.date.format("%d-%b-%Y"));
    let uids = session.uid_search(query).context("搜尋指定日期郵件失敗")?;
    let mut matched = 0;
    let mut moved = 0;

    for uid in uids {
        let messages = session.uid_fetch(uid.to_string(), "RFC822")?;
        let Some(message) = messages.iter().next() else {
            continue;
        };
        let Some(bytes) = message.body() else {
            continue;
        };
        let mail = parse_mail(bytes).context("無法解析郵件內容")?;
        let subject = mail.headers.get_first_value("Subject").unwrap_or_default();
        let from = mail.headers.get_first_value("From").unwrap_or_default();
        let body = mail.get_body().unwrap_or_default();
        let external_image_targets = external_word_image_targets(&mail);
        let (score, reasons) = phishing_score(
            &from,
            &subject,
            &body,
            &external_image_targets,
            &config.detection,
        );

        if score >= config.detection.threshold {
            matched += 1;
            println!(
                "[疑似釣魚] UID {uid}, {from}, 主旨：{subject}，分數：{score}（{}）",
                reasons.join("；")
            );
            if !args.dry_run {
                move_message(&mut session, uid, &config.imap.phishing_mailbox)?;
                moved += 1;
            }
        }
    }
    if !args.dry_run && moved > 0 {
        session.expunge().context("刪除來源信箱中已搬移郵件失敗")?;
    }
    session.logout().ok();
    println!(
        "完成：{} {} 封郵件。",
        if args.dry_run {
            "會搬移"
        } else {
            "已搬移"
        },
        if args.dry_run { matched } else { moved }
    );
    Ok(())
}

fn connect(config: &ImapConfig) -> Result<Session<imap::Connection>> {
    let mode = match config.protocol.as_str() {
        "imaps" => imap::ConnectionMode::Tls,
        "starttls" => imap::ConnectionMode::StartTls,
        other => bail!("不支援的 protocol：{other}；請使用 imaps 或 starttls"),
    };
    let client = imap::ClientBuilder::new(config.host.as_str(), config.port)
        .mode(mode)
        .connect()
        .context("IMAP TLS 連線失敗")?;
    client
        .login(&config.username, &config.password)
        .map_err(|e| e.0.into())
}

fn move_message(session: &mut Session<imap::Connection>, uid: u32, target: &str) -> Result<()> {
    session
        .uid_copy(uid.to_string(), target)
        .with_context(|| format!("無法複製郵件到：{target}"))?;
    session.uid_store(uid.to_string(), "+FLAGS.SILENT (\\Deleted)")?;
    Ok(())
}

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
    let link_count = Regex::new(r"https?://")
        .expect("固定正規表示式")
        .find_iter(&text)
        .count();
    if link_count >= 2 {
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
    if !external_word_image_targets.is_empty() {
        score += config.external_word_image_score;
        reasons.push(format!(
            "Word 附件含 {} 個外部圖片連結，開啟可能回傳追蹤資訊",
            external_word_image_targets.len()
        ));
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
        let name = entry.name().to_owned();
        if !name.starts_with("word/") || !name.ends_with(".rels") {
            continue;
        }
        let mut xml = String::new();
        if entry.read_to_string(&mut xml).is_err() {
            continue;
        }
        targets.extend(external_image_targets_from_relationships(&xml));
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
}
