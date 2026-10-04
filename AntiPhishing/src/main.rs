use std::{
    cell::Cell,
    fs,
    io::{self, Write},
    path::PathBuf,
};

use antiphishing_core::*;
use anyhow::{Context, Result, bail};
use chrono::NaiveDate;
use clap::Parser;
use mailparse::{MailHeaderMap, parse_mail};
use serde::Deserialize;

#[derive(Parser, Debug)]
#[command(about = "依指定日期掃描 IMAP 信箱，以地端 LLM 判定釣魚／惡意廣告郵件並搬移至指定信箱")]
struct Args {
    /// 要掃描的日期，格式 YYYY-MM-DD；可重複指定多個（例如昨天與今天）。
    #[arg(long = "date", value_name = "DATE", required_unless_present = "eml")]
    date: Vec<NaiveDate>,

    /// 讀取本機 .eml 檔（或資料夾內的 *.eml）判定是否為釣魚／垃圾信；可重複指定。
    /// 唯讀：不連 IMAP、不搬移，不可與 --date／--dry-run／-y 併用。
    #[arg(long = "eml", value_name = "PATH", conflicts_with_all = ["date", "dry_run", "yes"])]
    eml: Vec<PathBuf>,

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
    /// .eml 模式不連 IMAP，可省略；IMAP 模式由 connect 檢查主機位址是否為空。
    #[serde(default)]
    imap: ImapConfig,
    detection: DetectionConfig,
    /// 地端 LLM 判定（OpenAI 相容 API）；留空 base_url 或 model 即回退傳統評分模式。
    #[serde(default)]
    llm: LlmConfig,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let config: Config = toml::from_str(
        &fs::read_to_string(&args.config)
            .with_context(|| format!("無法讀取設定檔：{}", args.config.display()))?,
    )
    .context("設定檔 TOML 格式不正確")?;

    // .eml 模式：只讀本機檔案判定，不連 IMAP、不搬移
    if !args.eml.is_empty() {
        return run_eml_mode(&args.eml, &config);
    }

    let mut session = connect(&config.imap)?;
    let selected = session
        .select(&config.imap.source_mailbox)
        .with_context(|| format!("無法開啟來源信箱：{}", config.imap.source_mailbox))?;
    let original_uidvalidity = selected.uid_validity;

    let llm = llm_config(&config.llm);
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
            let auth_status = check_auth_status(&mail);
            let auth_warnings = auth_status.warnings.clone();
            let auth_summary = auth_status.summary();

            // 白名單直接安全豁免檢查：若寄件來源符合 trusted_sender_domains，且安全驗證無失敗警告，直接豁免跳過
            if let Some(matched) = trusted_source(&mail, &from, &config.detection) {
                if auth_warnings.is_empty() {
                    lines.push(format!(
                        "略過〈{}〉（寄件來源在信任清單：{}，且通過安全驗證）",
                        subject, matched
                    ));
                    if used_fallback && was_unread {
                        let _ = restore_unread_status(&mut session, uid);
                    }
                    continue;
                } else {
                    lines.push(format!(
                        "注意：〈{}〉寄件來源雖符合信任清單 ({})，但安全驗證失敗（{}），取消白名單豁免並送檢",
                        subject,
                        matched,
                        auth_warnings.join("；")
                    ));
                }
            }

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
                    if llm_config.effective_backend() == Some(LlmBackend::Jev) {
                        if llm_consecutive_failures >= 3 {
                            lines.push(format!(
                                "略過〈{}〉（Jev 連續失敗熔斷，採規則評分 {score}）",
                                subject
                            ));
                            if score >= config.detection.threshold {
                                let fallback_reason = format!(
                                    "Jev 熔斷；規則評分達標（{score}分）：{}",
                                    reasons.join("；")
                                );
                                pending.push((uid, subject.clone(), score, fallback_reason));
                            }
                        } else {
                            match llm_judge_jev(
                                llm_config,
                                &from,
                                &subject,
                                &body,
                                &attachments,
                                &targets,
                                &auth_summary,
                                &auth_warnings,
                            ) {
                                Ok(prob) => {
                                    let jev_points = calculate_jev_points(
                                        prob,
                                        llm_config.jev_max_score,
                                        llm_config.jev_min_prob,
                                    );
                                    let final_score = score + jev_points;
                                    let mut combined_reasons = reasons.clone();
                                    combined_reasons.push(format!(
                                        "Jev 評定釣魚機率 {:.0}%（+{jev_points}分）",
                                        prob * 100.0
                                    ));
                                    if final_score >= config.detection.threshold {
                                        pending.push((
                                            uid,
                                            subject.clone(),
                                            final_score,
                                            combined_reasons.join("；"),
                                        ));
                                    } else {
                                        lines.push(format!(
                                            "略過〈{}〉（評分 {final_score}，未達門檻；Jev 機率 {:.0}%）",
                                            subject,
                                            prob * 100.0
                                        ));
                                    }
                                }
                                Err(error) => {
                                    llm_consecutive_failures += 1;
                                    lines.push(format!(
                                        "Jev 判斷失敗（{error:#}），退回規則評分判定：〈{subject}〉"
                                    ));
                                    if score >= config.detection.threshold {
                                        let fallback_reason = format!(
                                            "Jev 判定失敗，退回規則評分達標（{score}分）：{}",
                                            reasons.join("；")
                                        );
                                        pending.push((
                                            uid,
                                            subject.clone(),
                                            score,
                                            fallback_reason,
                                        ));
                                    } else {
                                        lines.push(format!(
                                            "略過〈{}〉（評分 {score}，未達門檻；Jev 判定失敗）",
                                            subject
                                        ));
                                    }
                                }
                            }
                        }
                    } else if llm_consecutive_failures >= 3 {
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
                            &auth_summary,
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

/// .eml 模式主流程：逐檔判定並輸出，單檔失敗只印錯誤不中斷
fn run_eml_mode(inputs: &[PathBuf], config: &Config) -> Result<()> {
    let paths = collect_eml_paths(inputs)?;
    if paths.is_empty() {
        bail!("指定的路徑中沒有 .eml 檔");
    }
    let llm = llm_config(&config.llm);
    let mut failures: u32 = 0;
    let (mut ok, mut flagged, mut errors) = (0, 0, 0);
    println!("注意：驗證結果取自檔案內最上層標頭，未經重新驗證。");
    for (index, path) in paths.iter().enumerate() {
        let name = format!("[{}/{}] {}", index + 1, paths.len(), path.display());
        match evaluate_eml_file(path, &config.detection, &llm, &mut failures) {
            Ok(ev) => {
                ok += 1;
                if ev.flagged {
                    flagged += 1;
                }
                println!(
                    "{}",
                    format_evaluation(&name, &ev, config.detection.threshold)
                );
            }
            Err(error) => {
                errors += 1;
                println!("── {name}\n讀取或判定失敗：{error:#}");
            }
        }
    }
    println!(
        "共 {} 封，判定 {flagged} 封，失敗 {errors} 封。",
        ok + errors
    );
    if ok == 0 {
        bail!("所有 .eml 皆無法判定");
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn eml_args_are_exclusive_with_date_dry_run_and_yes() {
        assert!(Args::try_parse_from(["ap", "--eml", "a.eml"]).is_ok());
        assert!(Args::try_parse_from(["ap", "--date", "2026-01-01"]).is_ok());
        assert!(Args::try_parse_from(["ap"]).is_err());
        assert!(Args::try_parse_from(["ap", "--eml", "a.eml", "--date", "2026-01-01"]).is_err());
        assert!(Args::try_parse_from(["ap", "--eml", "a.eml", "--dry-run"]).is_err());
        assert!(Args::try_parse_from(["ap", "--eml", "a.eml", "-y"]).is_err());
    }
}
