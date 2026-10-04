use std::{fs, path::PathBuf};

use anyhow::{Context, Result, bail};
use chrono::NaiveDate;
use mailparse::{MailHeaderMap, parse_mail};

use crate::*;

/// .eml 單檔大小上限（防止誤給超大檔）
pub const MAX_EML_BYTES: u64 = 64 * 1024 * 1024;

/// 單封郵件的判定結果（.eml 模式，唯讀）
pub struct MailEvaluation {
    pub from: String,
    pub subject: String,
    pub auth_summary: String,
    pub auth_warnings: Vec<String>,
    pub rule_score: u32,
    pub rule_reasons: Vec<String>,
    /// LLM／Jev 判定說明（未設定、熔斷或失敗時為對應說明）
    pub llm_text: String,
    pub final_score: u32,
    pub flagged: bool,
    /// 判定依據（混合評分／LLM／規則／信任寄件者豁免）
    pub basis: &'static str,
}

/// 去掉 UTF-8 BOM 與 mbox 格式開頭的 `From ` 行（不是 `From:` 標頭）
pub fn normalize_eml_bytes(raw: &[u8]) -> &[u8] {
    let raw = raw.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(raw);
    if raw.starts_with(b"From ")
        && let Some(pos) = raw.iter().position(|&b| b == b'\n')
    {
        return &raw[pos + 1..];
    }
    raw
}

/// 展開 .eml 路徑：檔案直接收，資料夾只取第一層 *.eml（依檔名排序，不遞迴）
pub fn collect_eml_paths(inputs: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for input in inputs {
        if input.is_dir() {
            let mut found: Vec<PathBuf> = fs::read_dir(input)
                .with_context(|| format!("無法讀取資料夾：{}", input.display()))?
                .filter_map(|entry| entry.ok().map(|e| e.path()))
                .filter(|p| {
                    p.is_file()
                        && p.extension()
                            .is_some_and(|ext| ext.eq_ignore_ascii_case("eml"))
                })
                .collect();
            found.sort();
            paths.extend(found);
        } else if input.is_file() {
            paths.push(input.clone());
        } else {
            bail!("找不到檔案或資料夾：{}", input.display());
        }
    }
    Ok(paths)
}

/// 判定單封 .eml 內容（唯讀，不碰 IMAP）。
/// `failures` 為 LLM 連續失敗計數，≥3 時熔斷改採規則評分（整批共用，與 IMAP 模式一致）。
pub fn evaluate_mail(
    bytes: &[u8],
    config: &DetectionConfig,
    llm: &Option<LlmConfig>,
    failures: &mut u32,
) -> Result<MailEvaluation> {
    let mail = parse_mail(normalize_eml_bytes(bytes)).context("無法解析郵件內容")?;
    let from = mail.headers.get_first_value("From").unwrap_or_default();
    let subject = mail.headers.get_first_value("Subject").unwrap_or_default();
    let (body, score_body) = extract_body_text(&mail);
    let attachments = extract_attachment_filenames(&mail);
    let targets = external_word_image_targets(&mail);
    let auth_status = check_auth_status(&mail);
    let auth_warnings = auth_status.warnings.clone();
    let auth_summary = auth_status.summary();
    let threshold = config.threshold;

    let mut ev = MailEvaluation {
        from: from.clone(),
        subject: subject.clone(),
        auth_summary: auth_summary.clone(),
        auth_warnings: auth_warnings.clone(),
        rule_score: 0,
        rule_reasons: Vec::new(),
        llm_text: String::new(),
        final_score: 0,
        flagged: false,
        basis: "傳統規則",
    };

    // 信任寄件者且驗證無失敗：與 IMAP 模式相同直接豁免（仍列出結果以便看出原因）
    if let Some(matched) = trusted_source(&mail, &from, config)
        && auth_warnings.is_empty()
    {
        ev.llm_text = format!("未送檢（寄件來源在信任清單：{matched}）");
        ev.basis = "信任寄件者豁免";
        return Ok(ev);
    }

    let (score, reasons) = phishing_score(
        &from,
        &subject,
        &score_body,
        &attachments,
        &targets,
        &auth_warnings,
        config,
    );
    ev.rule_score = score;
    ev.rule_reasons = reasons;
    ev.final_score = score;
    ev.flagged = score >= threshold;

    let Some(llm_config) = llm else {
        ev.llm_text = "未設定 LLM".into();
        return Ok(ev);
    };
    if *failures >= 3 {
        ev.llm_text = "LLM 連續失敗熔斷，採規則評分".into();
        ev.basis = "規則（LLM 熔斷）";
        return Ok(ev);
    }
    if llm_config.effective_backend() == Some(LlmBackend::Jev) {
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
                let points =
                    calculate_jev_points(prob, llm_config.jev_max_score, llm_config.jev_min_prob);
                ev.llm_text = format!("Jev 釣魚機率 {:.1}%（+{points} 分）", prob * 100.0);
                ev.final_score = score + points;
                ev.flagged = ev.final_score >= threshold;
                ev.basis = "混合評分（規則＋Jev）";
            }
            Err(error) => {
                *failures += 1;
                ev.llm_text = format!("Jev 判定失敗：{error:#}");
                ev.basis = "規則（Jev 失敗）";
            }
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
            Ok(verdict) => {
                ev.llm_text = format!(
                    "LLM 判定{}：{}",
                    if verdict.is_phishing { "是" } else { "否" },
                    verdict.reason
                );
                ev.flagged = verdict.is_phishing;
                ev.basis = "LLM";
            }
            Err(error) => {
                *failures += 1;
                ev.llm_text = format!("LLM 判定失敗：{error:#}");
                ev.basis = "規則（LLM 失敗）";
            }
        }
    }
    Ok(ev)
}

/// 讀檔並判定單一 .eml（含大小檢查）
pub fn evaluate_eml_file(
    path: &std::path::Path,
    config: &DetectionConfig,
    llm: &Option<LlmConfig>,
    failures: &mut u32,
) -> Result<MailEvaluation> {
    let size = fs::metadata(path)?.len();
    if size > MAX_EML_BYTES {
        bail!("檔案過大（{size} bytes），略過");
    }
    evaluate_mail(&fs::read(path)?, config, llm, failures)
}

/// 輸出單封判定結果（純文字）
pub fn format_evaluation(name: &str, ev: &MailEvaluation, threshold: u32) -> String {
    let auth = if ev.auth_summary.is_empty() {
        "無驗證標頭".to_string()
    } else {
        ev.auth_summary.clone()
    };
    let warn = if ev.auth_warnings.is_empty() {
        String::new()
    } else {
        format!("（警示：{}）", ev.auth_warnings.join("；"))
    };
    let reasons = if ev.rule_reasons.is_empty() {
        "無".to_string()
    } else {
        ev.rule_reasons.join("；")
    };
    let verdict = if ev.flagged {
        "疑似釣魚／垃圾信"
    } else {
        "正常"
    };
    format!(
        "── {name}\n寄件者：{}\n主旨：{}\n驗證：{auth}{warn}\n規則分：{}（{reasons}）\nLLM：{}\n總分：{} / 門檻 {threshold} → 判定：{verdict}（依據：{}）",
        ev.from, ev.subject, ev.rule_score, ev.llm_text, ev.final_score, ev.basis
    )
}

pub fn dates_summary(dates: &[NaiveDate]) -> String {
    dates
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("、")
}
