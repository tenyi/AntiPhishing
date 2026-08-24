# CLAUDE.md

本檔提供 Claude Code 在本 repo（根目錄與兩個子專案）工作時的指引。

## 專案結構

- `AntiPhishing/`：CLI 版（`anti-phishing`），以地端 LLM 判定釣魚／惡意廣告郵件並搬移；未設定 LLM 時回退傳統評分門檻。
- `AntiPhishingGUI/`：GUI 版（`anti-phishing-gui`），同判定核心的 Windows 桌面工具（eframe + 系統匣）；細節見 `AntiPhishingGUI/CLAUDE.md`。

兩版共用概念：IMAP 掃描（`scan_mail`）、LLM 判定（`llm_judge`，OpenAI 相容 API）、DOCX 外部圖片偵測、搬移確認。修改共用邏輯時，**兩版都要同步修改並各自驗證**。

## 版號規範（必守）

**每次修改完成、提交前，必須更新該子專案 `Cargo.toml` 的 `version`**：

- 新功能：升 minor（如 0.3.0 → 0.4.0）
- 錯誤修正：升 patch（如 0.3.0 → 0.3.1）
- 同時更新 `Cargo.lock`（在該子專案跑一次 `cargo check` 即可）

## 開發守則

- UI 文字、日誌、註解一律 **zh-TW 繁體中文**；KISS 原則。
- 帳密僅存 `config.toml`（已 gitignore），不得寫死或提交。
- 修改後驗證：在對應子專案執行 `cargo check` + `cargo fmt --check` + `cargo test` 皆須通過。
