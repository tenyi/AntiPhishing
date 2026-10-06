use std::{
    io::{Read, Write},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::*;

/// 送 LLM 判斷的 system 提示：要求嚴格 JSON 輸出，判定釣魚/詐欺/惡意行銷廣告/垃圾推銷/仿冒品牌。
pub const LLM_SYSTEM_PROMPT: &str = "你是郵件安全判官。根據使用者提供的郵件內容，判斷該郵件是否為「釣魚、詐欺、詐騙郵件」或「惡意行銷廣告、垃圾推銷、仿冒知名品牌或販賣一般性物品的垃圾廣告郵件」。\
高風險與排除目標訊號包括：\
1. 惡意行銷與垃圾廣告：未經請求的推銷廣告、仿冒知名品牌促銷、販賣一般性物品或商品（如香薰瀑布、健康器材、保健品、手錶名品等）、含可疑轉址或假退訂連結（Opt Out）、寄件者與商品內容不合的垃圾郵件。\
2. 偽裝機構或品牌：寄件網域非其所稱品牌（如 DHL、FedEx、快遞、銀行、Yahoo 等知名企業）的官方網域，或郵件安全驗證（DMARC/SPF）失敗。\
3. 詐騙與個資竊取：要求付款或繳費（關稅、手續費、驗證費）、要求提供帳號密碼、緊急施壓、可疑連結、附件追蹤、內含 QR code 或要求用手機掃描（quishing）、籠統稱呼（如「親愛的顧客」）搭配假單號或要求更新地址/電話。\
4. 異常附件：一般無需附件之郵件（如新聞推播、通知信、系統警告等）卻夾帶 Office 文件（.doc/.docx/.xls/.xlsx 等）、壓縮檔或可執行檔等可疑附件；或附件包含外部追蹤連結。\
5. 資安通報與隔離報告排除：若郵件主旨或內文為企業資安通報、垃圾信隔離明細、防毒/SOC分析回報（如 Hinet SOC、防垃圾信通知等），且其安全驗證（SPF/DKIM/DMARC）通過或無偽造警示，即使內文引用被攔截之惡意網址或樣本，亦屬於正常資安服務通知，不得判定為釣魚郵件（is_phishing 必須為 false）。\
\
僅輸出嚴格 JSON，不要任何其他文字：{\"is_phishing\": true 或 false, \"reason\": \"簡短理由\"}。\
只要符合上述釣魚、詐騙或惡意推銷廣告/垃圾信特徵，is_phishing 必須為 true；若為正常商務或私人往來郵件（非垃圾廣告與釣魚），is_phishing 必須為 false。若證據不足或不確定，is_phishing 設為 false。";

/// 組裝送 LLM 的郵件內容：From/Subject/內文（截斷），並附附件清單、Word 外部圖片與安全驗證提示。
pub fn llm_user_prompt(
    from: &str,
    subject: &str,
    body: &str,
    max_chars: usize,
    attachments: &[String],
    docx_targets: &[String],
    auth_summary: &str,
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
    if !auth_summary.is_empty() {
        text.push('\n');
        text.push_str("安全驗證狀態：");
        text.push_str(auth_summary);
    }
    if !auth_warnings.is_empty() {
        text.push('\n');
        text.push_str("安全驗證警示：");
        text.push_str(&auth_warnings.join("；"));
    }
    text
}

/// LLM 對單一郵件的判定結果。
#[derive(Deserialize)]
pub struct LlmVerdict {
    pub is_phishing: bool,
    #[serde(default)]
    pub reason: String,
}

/// 解析 LLM 回傳的判定 JSON；容許多段 <think>/<thinking> 思考標籤、```json 圍欄與前後文字；解析失敗回 Err。
pub fn parse_llm_verdict(text: &str) -> Result<LlmVerdict> {
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

/// 組合命令列程式與引數清單
pub fn build_cli_command(config: &LlmConfig) -> Result<(String, Vec<String>)> {
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
        LlmBackend::Jev => {
            bail!("Jev 後端不支援透過命令列執行");
        }
    }
}

/// 執行外部 CLI 命令，透過 stdin 送入 prompt，並讀取 stdout 回傳純文字。
/// 具備逾時防護與防管線緩衝區死鎖設計。
pub fn run_cli_with_stdin(
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
pub fn llm_judge_api(
    config: &LlmConfig,
    from: &str,
    subject: &str,
    body: &str,
    attachments: &[String],
    docx_targets: &[String],
    auth_summary: &str,
    auth_warnings: &[String],
) -> Result<LlmVerdict> {
    let payload = serde_json::json!({
        "model": config.model,
        "temperature": 0,
        "messages": [
            { "role": "system", "content": LLM_SYSTEM_PROMPT },
            { "role": "user", "content": llm_user_prompt(from, subject, body, config.max_chars, attachments, docx_targets, auth_summary, auth_warnings) }
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
pub fn llm_judge_cli(
    config: &LlmConfig,
    from: &str,
    subject: &str,
    body: &str,
    attachments: &[String],
    docx_targets: &[String],
    auth_summary: &str,
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
        auth_summary,
        auth_warnings,
    );
    let full_prompt = format!("{LLM_SYSTEM_PROMPT}\n\n=== 待判定郵件 ===\n{user_prompt}");
    let timeout = Duration::from_secs(config.timeout_secs);
    let output_text = run_cli_with_stdin(&program, &args, &full_prompt, timeout)?;
    parse_llm_verdict(&output_text)
        .with_context(|| format!("CLI ({program}) 原始回應為：{output_text:?}"))
}

/// 解析 Jev 回傳的 JSON，擷取 is_phishing 的機率值 (0.0 ~ 1.0)。
pub fn parse_jev_probability(val: &serde_json::Value) -> Result<f64> {
    let answer = val
        .get("answers")
        .and_then(|a| a.get("is_phishing"))
        .context("Jev 回應缺少 answers.is_phishing")?;

    if let Some(noul) = answer.get("noul").and_then(|n| n.as_f64()) {
        return Ok(noul.clamp(0.0, 1.0));
    }
    bail!("Jev 回應 answers.is_phishing 缺少有效的 noul 機率數值：{val}")
}

/// 判斷 model 是否為地端 System One 模型（nimble、clef、clef-flash 等，不分大小寫）。
pub fn is_local_systemone_model(model: &str) -> bool {
    let m = model.trim().to_ascii_lowercase();
    m.starts_with("nimble") || m.starts_with("clef")
}

/// 判斷 model 是否為地端 Nimble（nimble 或 nimble:latest 等，不分大小寫）。
pub fn is_nimble_model(model: &str) -> bool {
    model.trim().to_ascii_lowercase().starts_with("nimble")
}

/// 判斷 model 是否為地端 Clef / Clef-Flash（不分大小寫）。
pub fn is_clef_model(model: &str) -> bool {
    model.trim().to_ascii_lowercase().starts_with("clef")
}

/// 組出 System One 端點：base_url 寫 host、.../v1 或 .../v1/systemone 皆可；空值用官方雲端。
pub fn jev_endpoint(base_url: &str) -> String {
    let mut base = base_url.trim().trim_end_matches('/');
    if base.is_empty() {
        base = "https://api.typesafe.ai";
    }
    // 依序去掉結尾的 /v1/systemone 與 /v1，避免重複拼接
    base = base.strip_suffix("/v1/systemone").unwrap_or(base);
    base = base.trim_end_matches('/');
    base = base.strip_suffix("/v1").unwrap_or(base);
    format!("{base}/v1/systemone")
}

/// 地端 System One（Nimble / Clef / Clef-Flash）專用問句（實測）：此類模型不太參考 criteria，
/// 排除條件必須寫進 instructions，否則郵件稽核系統產生的「垃圾信隔離明細」會被誤判為釣魚；偽裝成通知的釣魚仍須判為是。
pub const NIMBLE_PHISHING_INSTRUCTIONS: &str = "判斷「這封郵件本身」是否為寄給收件者的釣魚、詐騙或惡意推銷信。釣魚信的典型特徵：以系統管理員、IT、郵件服務或帳號安全的名義，宣稱收件者信箱「發生錯誤」「容量已滿」「將被停用」「需要驗證」，並催促點擊按鈕或連結（如「立即驗證」），而寄件網域與收件者所屬單位或該服務無關（例如政府、學校或陌生網站的網域）。此類信件即使 SPF/DKIM/DMARC 通過（通過只代表寄件網域沒被偽造，不代表內容可信），仍是釣魚，答案為是。例外：若這封信是郵件稽核／閘道系統自動產生的垃圾信隔離明細或攔截通報（內文只是列出被攔截的信件、過濾原因與處理選項，如「SPF 驗證失敗」「RBL」只是描述被攔截的那些信），且其中連結的網域與寄件者網域一致，它本身是正常的系統通知，答案為否；但若這類通知要求輸入帳號密碼、連結網域與寄件者不符或寄件網域可疑，則仍是釣魚。";

/// 組出 is_phishing 問句：地端 System One（Nimble / Clef / Clef-Flash）用 instructions 內含排除條件的版本，雲端 Jev 維持原寫法。
pub fn jev_question(model: &str) -> serde_json::Value {
    if is_local_systemone_model(model) {
        serde_json::json!({
            "type": "noul",
            "instructions": NIMBLE_PHISHING_INSTRUCTIONS
        })
    } else {
        serde_json::json!({
            "type": "noul",
            "instructions": "判斷此郵件是否為釣魚、詐欺、詐騙郵件，或未經請求的惡意行銷廣告、垃圾推銷、仿冒知名品牌之垃圾廣告郵件？",
            "criteria": {
                "true": "符合釣魚、詐欺、要求帳密/款項、偽裝機構品牌、異常附件追蹤或惡意促銷垃圾信",
                "false": "正常商務或私人溝通往來郵件；或安全驗證通過且來源正常的資安通報、垃圾信隔離明細、防毒/SOC回報郵件"
            }
        })
    }
}

/// 依 Jev 釣魚機率換算為分數：
/// - 低於 min_prob（預設 0.6）不計分 (0分)
/// - min_prob ~ 1.0 依比例線性換算為 0 ~ max_score
/// - min_prob 限制在 0.0 ~ 0.99，避免除以 0；設為 0 即 0~100% 全程給分
pub fn calculate_jev_points(prob: f64, max_score: u32, min_prob: f64) -> u32 {
    let min_prob = min_prob.clamp(0.0, 0.99);
    if prob < min_prob {
        0
    } else {
        let ratio = ((prob - min_prob) / (1.0 - min_prob)).clamp(0.0, 1.0);
        (ratio * max_score as f64).round() as u32
    }
}

/// 透過 TypeSafe System One API (Jev) 取得單一郵件釣魚機率（0.0 ~ 1.0）。
pub fn llm_judge_jev(
    config: &LlmConfig,
    from: &str,
    subject: &str,
    body: &str,
    attachments: &[String],
    docx_targets: &[String],
    auth_summary: &str,
    auth_warnings: &[String],
) -> Result<f64> {
    let model = if config.model.trim().is_empty() {
        "jev-latest"
    } else {
        config.model.trim()
    };
    let url = jev_endpoint(&config.base_url);

    let user_content = llm_user_prompt(
        from,
        subject,
        body,
        config.max_chars,
        attachments,
        docx_targets,
        auth_summary,
        auth_warnings,
    );

    let payload = serde_json::json!({
        "state": user_content,
        "model": model,
        "questions": {
            "is_phishing": jev_question(model)
        }
    });

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
        .map_err(|error| anyhow::anyhow!("Jev API 請求失敗：{error}"))?;

    let status = response.status();
    if (300..=399).contains(&status.as_u16()) {
        let location = response
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("未知");
        bail!(
            "Jev 伺服器回傳重定向 (HTTP {}) 至 {}，請檢查 [llm].base_url 設定",
            status.as_u16(),
            location
        );
    }
    if !status.is_success() {
        let err_body = response
            .body_mut()
            .read_to_string()
            .unwrap_or_else(|_| "(無法讀取回應內文)".into());
        let hint = if status.as_u16() == 404 {
            "（若為 Ollama，請確認已執行 ollama pull nimble 或 ollama pull clef-flash，且版本支援 /v1/systemone）"
        } else {
            ""
        };
        bail!(
            "Jev 伺服器回傳錯誤 (HTTP {})：{}{hint}",
            status.as_u16(),
            err_body
        );
    }

    let resp_val: serde_json::Value = response
        .body_mut()
        .read_json()
        .map_err(|error| anyhow::anyhow!("Jev 回應不是 JSON：{error}"))?;

    parse_jev_probability(&resp_val)
}

/// 呼叫指定之 LLM 後端（API 或 CLI）取得單一郵件判定。
pub fn llm_judge(
    config: &LlmConfig,
    from: &str,
    subject: &str,
    body: &str,
    attachments: &[String],
    docx_targets: &[String],
    auth_summary: &str,
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
            auth_summary,
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
                auth_summary,
                auth_warnings,
            )
        }
        LlmBackend::Jev => {
            let prob = llm_judge_jev(
                config,
                from,
                subject,
                body,
                attachments,
                docx_targets,
                auth_summary,
                auth_warnings,
            )?;
            let is_phishing = prob >= 0.75;
            let reason = format!("Jev 評定釣魚機率 {:.0}%", prob * 100.0);
            Ok(LlmVerdict {
                is_phishing,
                reason,
            })
        }
    }
}
