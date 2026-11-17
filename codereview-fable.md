# Code Review（Fable）— 2026-11-17

審查方式：純閱讀，未修改任何檔案、未執行 `cargo test`。工作樹沒有未提交變更，審查對象為整個程式碼庫（commit `dcb1e5c`）。

**涵蓋範圍**：核心 crate 全部、CLI `main.rs` 全部、GUI 的掃描／搬移／狀態持久化／排程。

**未審查**：GUI 的 UI 繪製（約 1245–2050 行）、字型與系統匣、`theme.rs`、`tests.rs` 內容。

> 修復進度見文末〈修復狀態〉（更新於 2026-11-17，commit `96776b0`）。以下各節保留審查當下的原文與行號，行號已因修正而變動。

## 高嚴重度

### 1. 信件內容可觸發命令執行（prompt injection）

位置：`AntiPhishingCore/src/llm.rs:124-152`

攻擊者可控的郵件內文直接餵給 `codex exec --dangerously-bypass-approvals-and-sandbox` 與 `agy --dangerously-skip-permissions`，兩者都沒有停用工具。釣魚信內嵌指令就可能在本機執行命令，而工作目錄旁就是含 IMAP 密碼的 `config.toml`。

Claude 後端有 `--tools ""`，風險較低，但是否連 MCP 工具也停用**未驗證**。

### 2. 信任清單豁免只要求「沒有失敗」，不是「通過」

位置：`AntiPhishingCore/src/mail.rs:242-251`、`AntiPhishingCore/src/eval.rs:97`、`AntiPhishing/src/main.rs:148`、`AntiPhishingGUI/src/main.rs:2664`

偽造 From 為信任網域、且信件沒有任何驗證標頭（或只有 `dmarc=none`、`spf=softfail`）時，`auth_warnings` 為空，直接跳過規則與 LLM。日誌還寫「且通過安全驗證」。

另外各欄位是分別從任一層 `Authentication-Results` 補齊的，收信 MTA 沒寫的欄位會採用寄件者自帶的偽造標頭。

### 3. `trusted_relay_ips` 可被 HELO 偽造繞過

位置：`AntiPhishingCore/src/mail.rs:374-380`

取 from 段落的第一個 `[`。Postfix 格式是 `from <HELO> (rdns [實際IP])`，寄件端 HELO 自報 `[信任IP]` 就會先被取到。無方括號時取第一個詞也是 HELO 值。

### 4. GUI 待隔離清單不綁定信箱世代，可能搬錯信

位置：`AntiPhishingGUI/src/main.rs:2487-2563`、`188-195`

`PendingMoveItem` 只存 UID，跨重啟保留；`execute_move_task` 不比對 UIDVALIDITY（CLI 有做，`AntiPhishing/src/main.rs:363`）。信箱重建、改了 `source_mailbox` 或帳號後，同一個 UID 會指向別封信。

設定頁欄位直接綁 `self.config`，未按儲存的編輯也會生效。`last_seen` 斷點同理：換信箱後若 UIDVALIDITY 剛好相同，會跳過新信箱的舊 UID。

### 5. CLI 呼叫可能永久卡住，逾時保護不到

位置：`AntiPhishingCore/src/llm.rs:198-202`、`238-239`

prompt 在讀取執行緒啟動前、逾時迴圈之前就整個 `write_all` 到 stdin。子行程不讀 stdin（自訂 command 或卡住）時會永遠阻塞。另外 `cmd /C` 只殺得到 `cmd`，孫行程還握著管線時 `join()` 也可能卡住。

GUI 掃描執行緒卡住後 `receiver` 永不清空，之後所有排程掃描都不會再跑。

## 中嚴重度

### 6. 「連續失敗」計數從不歸零

位置：`AntiPhishing/src/main.rs:92`、`AntiPhishingGUI/src/main.rs:2599`、`AntiPhishingCore/src/eval.rs:148,174`

全專案只有遞增，成功後沒有重設。單一日期內零星 3 次失敗（含 LLM 回的 JSON 解析失敗）就會熔斷，其餘信件只用規則評分。

### 7. GUI 斷點在 LLM 失敗時也會推進

位置：`AntiPhishingGUI/src/main.rs:2777, 2816, 2839`

與 `LastScanState` 的說明（202 行「LLM 判定失敗者不列入，下輪重試」）相反。LLM 服務中斷期間的信只用規則評分就被標為已檢查，排程永不重判。未設定 LLM 時也一樣。抓取或解析失敗的 UID 只要後面有信成功，同樣被跳過。

### 8. 掃描失敗也會更新 `last_check`，補掃範圍縮水

位置：`AntiPhishingGUI/src/main.rs:1022`、`702-707`

關機數天後開機，第一次掃描因網路未就緒失敗，`last_check` 變成現在，之後只掃昨天與今天，中間幾天漏掉。

同一段的 `needs_catchup`（1101-1103）因為 `last_check` 剛設成現在，永遠是 false，等於死碼。

### 9. 全部抓取失敗被回報成「無新郵件」

位置：`AntiPhishingGUI/src/main.rs:2848-2857`

`scanned == 0` 時丟掉 `lines`，錯誤訊息完全不顯示也不寫日誌。

### 10. 規則評分對原始 HTML 比對，誤判偏高

位置：`AntiPhishingCore/src/mail.rs:435-470`

- 關鍵字 `qr`（小寫後）會命中 base64 內嵌圖的內容。
- `https?://` 計數包含 DOCTYPE 與 xmlns 的 w3.org 網址，幾乎每封 HTML 信都拿到「含多個連結 +2」。
- `RE_LINK_WITH_AT` 的 `[^\s/?#]*` 會跨過引號與 `>`，`<a href="https://a.com">user@a.com` 被判成「連結含 @ +3」。

這在規則模式與 Jev 混合評分下會直接影響搬移。

### 11. 截斷可被利用來躲 LLM

位置：`AntiPhishingCore/src/mail.rs:129-133`、`AntiPhishingCore/src/llm.rs:44`

內文是 plain 在前、HTML 在後再截到 `max_chars`。攻擊者放一段長的正常 text/plain，惡意內容只放 HTML（收件軟體顯示的是 HTML），LLM 就看不到。

### 12. backend 打錯字會靜默退回規則模式並直接搬移

位置：`AntiPhishingCore/src/config.rs:138-144`、`AntiPhishing/src/main.rs:331`

`backend = "claud"` 會讓 `llm_config` 回 `None`，CLI 進入傳統模式，而傳統模式不經確認就搬。應該對無法辨識的 backend 報錯。

## 低嚴重度

- **Zip 炸彈防護可能無效**（未驗證）：`AntiPhishingCore/src/mail.rs:572-576` 檢查的是標頭宣告大小，`read_to_string` 沒有上限；改用 `take(MAX)` 即可。
- **`uid_fetch` 取第一筆回應沒核對 UID**：`AntiPhishing/src/main.rs:112`、`AntiPhishingGUI/src/main.rs:2623`；伺服器夾帶別封信的旗標更新時，會被當成「內容為空」跳過。
- **連線中斷後仍逐封重試**：每個 UID 兩次 fetch，各等到 60 秒逾時，大量信件時會拖很久。
- **信任網域 −3 在驗證失敗時仍然套用**：`AntiPhishingCore/src/mail.rs:513-522`。
- **`EXPUNGE` 後備會清掉使用者在別處標記刪除的信**；GUI 自動搬移路徑還忽略其錯誤（`AntiPhishingGUI/src/main.rs:2907`）。
- **熔斷日誌矛盾**：先寫「略過〈…〉」，接著又把同一封加入搬移。
- **CLI 摘要日期不符**：印的是 `args.date`，實際還掃了前一日。
- **Jev 門檻不一致**：`llm_judge` 的 Jev 分支用寫死的 0.75（`AntiPhishingCore/src/llm.rs:579`），與混合評分是兩套邏輯；目前三個呼叫端都先攔掉 Jev，這段實際走不到。
- **判定流程有三份**（CLI、GUI、`eval.rs`）且已出現差異；未設定 LLM 時 CLI 會搬、GUI 不搬。
- **相依套件**：CLI 釘 `zip 8.6`，核心用 `9.0.0-pre.2`；兩個前端還宣告了只有核心在用的套件。
- **GUI release 版每判一封會閃一個主控台視窗**：子行程沒設 `CREATE_NO_WINDOW`。
- **`AntiPhishingGUI/chrome-debug-profile/` 沒在 `.gitignore`**，可能含瀏覽器個資，容易誤提交。

## 建議修復順序

先修 1、2、4、5（安全性繞過、搬錯信、掃描卡死），再處理 6–9（判定可靠性與漏掃）。

## 修復狀態（2026-11-17，commit `96776b0`）

版號：Core 0.2.0 → 0.2.1、CLI 2.7.0 → 2.7.1、GUI 2.8.1 → 2.8.2。

驗證：三個 crate 的 `cargo check --all-targets`、`cargo fmt --check`、`cargo test` 都通過，且沒有編譯警告。

| crate | 測試結果 |
|---|---|
| 核心 | 76 個通過 |
| CLI | 5 個通過 |
| GUI | 32 個通過、1 個忽略 |

### 已修正

| # | 狀態 | 處理方式 | 測試 |
|---|---|---|---|
| 1 | ⏭ 不修 | 判斷 LLM 明確知道自己在處理釣魚信，風險可接受，先跳過 | — |
| 2 | ✅ | 新增 `trust_decision`。信任網域需「無驗證警告且 `dmarc=pass`」；`Authentication-Results` 以最上層的 authserv-id 錨定，下層標頭只在 authserv-id 相同時才合併；三個呼叫端都改用它，日誌會寫出拒絕豁免的原因 | `trusted_domain_requires_dmarc_pass`、`trust_decision_reports_reason_when_rejected`、`auth_status_does_not_merge_lower_headers_without_server_id` |
| 3 | ✅ | `top_received_ip` 先切開 HELO 與括號註解：優先取註解內 `[IP]`，其次取註解第一組的最後一個詞（去掉 `helo=`）；只有沒有註解時才取第一個詞 | `top_received_ip_ignores_helo_brackets` |
| 4 | ✅（部分） | `PendingMoveItem` 記錄 UIDVALIDITY 與來源信箱；搬移前比對，不符就寫日誌並移出清單、不搬移；去重與移除改用 `(uidvalidity, uid)` 為鍵；換信箱時捨棄 `last_seen` | `pending_queue_deduplicates_by_generation_and_uid`、`legacy_pending_item_without_generation_parses` |
| 5 | ✅ | `run_cli_with_stdin` 先啟動讀取執行緒、另開執行緒寫 stdin；逾時用 `taskkill /T /F` 終止整個程序樹；子行程結束後以 `recv_timeout` 等待輸出，不會無限 `join` | `run_cli_times_out_when_child_ignores_stdin` |
| 6 | ✅ | CLI、GUI、`eval.rs` 在 LLM 或 Jev 判定成功時都把失敗計數歸零 | `evaluate_mail_resets_failure_counter_on_success` |
| 7 | ✅ | GUI 新增重試清單（上限 200 筆，存在狀態檔）：抓取失敗、LLM／Jev 失敗或熔斷且分數未達門檻的 UID 下一輪重掃；分數已達門檻的直接列入待隔離 | `retry_uids_merge_within_generation_and_reset_otherwise`、`filter_new_uids` 系列 |
| 8 | ✅ | 整輪失敗（`ScanOutcome.failed`）時不推進 `last_check`；移除死碼 `needs_catchup` | — |
| 9 | ✅ | `scanned == 0` 且有抓取失敗時，回報「掃描失敗：N 封郵件皆無法讀取」並發通知，錯誤訊息寫入日誌 | — |
| 10 | ✅ | 評分前先移除 style／script、data URI 與 DOCTYPE、xmlns 這類非連結 URL；關鍵字比對轉成純文字的內容；`RE_LINK_WITH_AT` 改為不跨越引號與 `<>` | `rule_score_ignores_html_noise` |
| 11 | ✅ | LLM 內文與 `score_body` 改成 HTML 轉出的文字在前、plain 在後 | `llm_body_puts_html_before_plain` |
| 12 | ✅ | 新增 `llm_config_checked`：明確寫了 backend 卻無法辨識或缺少必要參數時報錯；CLI 啟動時直接中止，GUI 寫日誌並視為未設定 LLM | `llm_config_checked_rejects_typo_and_missing_params` |

### 低嚴重度

| 項目 | 狀態 | 處理方式 |
|---|---|---|
| Zip 炸彈防護 | ✅ | `.rels` 改用 `take(MAX+1)` 讀取並檢查長度 |
| `uid_fetch` 未核對 UID | ✅ | CLI 與 GUI 都依 UID 挑出對應的回應 |
| 連線中斷後仍逐封重試 | ❌ 未修 | — |
| 驗證失敗時仍套用信任網域 −3 | ✅ | 有 `auth_warnings` 時不扣分 |
| `EXPUNGE` 後備 | ✅（部分） | 錯誤已寫入日誌；後備本身刻意保留，讓不支援 UIDPLUS 的伺服器仍能用 |
| 熔斷日誌矛盾 | ✅ | 只有分數未達門檻時才寫「略過」 |
| CLI 摘要日期 | ✅ | 改為列出實際掃描的所有日期 |
| Jev 門檻不一致 | ❌ 未修 | 需要業務決定；這段目前實際走不到 |
| 判定流程有三份 | ❌ 未修（部分緩解） | 信任豁免已統一走 `trust_decision`，整體收斂仍屬重構 |
| 相依套件 | ✅（部分） | 已移除 CLI 未使用的 `zip`；兩個前端多宣告的套件尚未清理 |
| 子行程閃主控台視窗 | ✅ | 子行程設定 `CREATE_NO_WINDOW` |
| `chrome-debug-profile/` | ✅ | 已加入 `.gitignore` |
| 未使用的 `bare_config`（測試） | ✅ | 已刪除 |

### 尚未處理

- #1 prompt injection（決定不修）
- #4 的另一半：設定頁沒按儲存的編輯，仍會在掃描時生效
- 連線中斷後仍逐封重試
- Jev 0.75 門檻
- 判定流程三份收斂
- 前端多餘的相依套件

### 行為變更與注意事項

- **信任網域豁免現在需要 `dmarc=pass`。** 收信伺服器若不在 `Authentication-Results` 寫 DMARC 結果，網域豁免等於停用，這些信會改送 LLM 判定。
- **舊版待隔離項目**：UIDVALIDITY 會從狀態檔回填；沒有記錄信箱的項目，搬移時略過信箱比對。
- **未設定 LLM 時，GUI 斷點照常推進**，這是刻意的設計（規則判定沒有「失敗」可重試）。
- **Exim 的 `from [ip] (helo=...)` 格式**現在取不到 IP，結果是不視為信任中繼，屬保守的一側。
- **逾時測試會啟動 PowerShell**，沒有 PowerShell 的環境跑這個測試會失敗。
