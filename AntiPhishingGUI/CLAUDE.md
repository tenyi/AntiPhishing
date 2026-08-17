# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 專案概述

Windows 桌面 GUI 郵件防護工具（Rust 2024 edition，`anti-phishing-gui`）。從 IMAP 讀取指定日期郵件，**逐封送地端 LLM（OpenAI 相容 API）判定是否釣魚**，判定為真者搬移至 `phishing_mailbox`；既有關鍵字/評分規則僅作 log 參考。技術棧：`eframe`（wgpu 後端）+ `tray-icon` + `single-instance`；網路與解析用 `imap`、`mailparse`、`quick-xml`、`zip`、`ureq`。

## 常用指令（PowerShell）

```powershell
cargo check          # 型別檢查
cargo fmt --check    # 格式檢查（CI 級驗證）
cargo fmt            # 格式化
cargo test           # 單元測試（不連線真實 IMAP）
cargo test <名稱>     # 跑單一測試，如 cargo test detects_external_word_image_relationship
cargo run            # 開發模式執行
cargo build --release  # Release 建置
```

Release 執行檔：`.\target\release\anti-phishing-gui.exe`。執行檔旁需有 `config.toml`；從其他工作目錄啟動時，`config.toml` 是相對路徑（`CONFIG_PATH`），須以執行檔所在目錄為工作目錄。

## 架構

所有邏輯集中在單一檔案 `src/main.rs`（含 GUI、IMAP、評分、測試）：

- **設定**：`Config`（imap / detection / gui 三段）載入自專案目錄 `config.toml`，載入失敗時用 `Config::default()` 並顯示警告；GUI「儲存設定」寫回 `config.toml`（`toml::to_string_pretty`）。
- **掃描流程** `scan_mail`：`connect`（imaps 或 starttls）→ `select` 來源信箱 → `uid_search("ON <date>")` → `uid_fetch RFC822` → `parse_mail` → `llm_judge`（判定為 `is_phishing` 者）`move_message`（`uid_copy` + `+FLAGS.SILENT (\Deleted)`）→ `expunge` → `logout`。搬移用 copy+flag+expunge，非 server-side MOVE。
- **LLM 判定（決策依據）** `llm_judge`：POST `{[llm].base_url}/chat/completions`（`ureq`，逾時在 `Agent` 上設定），system 提示要求嚴格 JSON `{"is_phishing": bool, "reason": str}`、不確定一律 false（含 QR code/手機掃描、品牌網域偽裝、關稅/手續費等訊號）；user 內容為 From/Subject/內文（截斷至 `max_chars`），DOCX 外部圖片連結（`external_word_image_targets`）附為提示行。內文經 `extract_body_text` 自 subparts 提取（mailparse 的 `get_body()` 對 multipart 回傳空）：text/plain + text/html 轉純文字（`html_to_text` 剝 style/script、base64 圖，保留 img alt）；charset 未指定（mailparse 預設 us-ascii 會亂碼）時改以 UTF-8 解碼。`parse_llm_verdict` 容許 ` ```json ` 圍欄。**`base_url`/`model` 為空＝停用**（掃描不搬移）；請求或解析失敗＝該封跳過、記 log、繼續。
- **評分** `phishing_score`：可疑寄件網域 +4、關鍵字命中 +min(count,3)、≥2 個連結 +2、連結含 `@` +3、QR 內嵌圖（quishing）+4、品牌偽裝（From 顯示名稱含 DHL/FedEx/UPS 但網域非官方，`BRAND_OFFICIAL_DOMAINS`）+3、DOCX 外部圖片 +`external_word_image_score`、信任網域 −3；**僅寫入 log 供參考，不再決定搬移**。
- **DOCX 偵測**：附件 `ZipArchive` 掃 `word/*.rels`，只取 `Type` 以 `/image` 結尾、`TargetMode=External`、`http(s)://` 開頭的 Relationship。刻意不連網下載、不啟動 Office。
- **排程**：無獨立排程執行緒；`eframe::App::logic` 每幀 poll，`Instant >= next_check` 時觸發掃描（`request_repaint_after(1s)` 保持喚醒）。啟動時掃「前一日＋今日」，之後排程只掃今日。
- **系統匣**：關閉視窗預設轉為縮小至系統匣（`CancelClose` + `Visible(false)` 或 `Minimized(true)`，視 `hide_taskbar_when_minimized`）；真正退出僅經系統匣「結束」（先設 `allow_exit` 再 `Close`）。`single-instance` 在 `main` 入口防重複啟動。
- **字型**：`font_family` 支援字型檔路徑或固定映射（Noto Sans TC → `NotoSansTC-VF.ttf`、微軟正黑體 → `msjh.ttc`），啟動時注入 egui，改後需重啟。

## 開發守則

- UI 文字、日誌、註解一律 **zh-TW 繁體中文**；KISS 原則，不引入多餘抽象。
- 帳密僅存 `config.toml`（已在 `.gitignore`），不得寫死程式碼或提交版本控制。
- 附件偵測不可連網下載外部資源或啟動外部 Office 程式。
- 修改後驗證：`cargo check` + `cargo fmt --check` + `cargo test` 皆須通過。
