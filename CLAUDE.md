# CLAUDE.md

本檔提供 Claude Code 在本 repo（根目錄與兩個子專案）工作時的指引。

## 專案結構

- `AntiPhishing/`：CLI 版（`anti-phishing`），以地端 LLM 判定釣魚／惡意廣告郵件並搬移；未設定 LLM 時回退傳統評分門檻。
- `AntiPhishingGUI/`：GUI 版（`anti-phishing-gui`），同判定核心的桌面工具（eframe + 系統匣，Windows／macOS）；細節見 `AntiPhishingGUI/CLAUDE.md`。
- `AntiPhishingCore/`：兩版共用的判定核心 crate（`antiphishing-core`，path 依賴，非 workspace）：設定結構、郵件解析與評分、LLM 判定（OpenAI 相容 API 或 Claude/Codex/Agy CLI）、IMAP 操作、DOCX 外部圖片偵測、.eml 評估。

共用邏輯一律改在 `AntiPhishingCore/`，改完要在**核心與兩個前端**各自驗證；掃描主迴圈（CLI 的 `main`、GUI 的 `scan_mail`）與搬移確認仍分別在各前端，修改時需兩邊對照。

## 版號規範（必守）

**每次修改完成、提交前，必須更新該子專案 `Cargo.toml` 的 `version`**（核心 crate 的修改同時升核心與受影響前端的版號）：

- 新功能：升 minor（如 0.3.0 → 0.4.0）
- 錯誤修正：升 patch（如 0.3.0 → 0.3.1）
- 同時更新 `Cargo.lock`（在該子專案跑一次 `cargo check` 即可）

## 開發守則

- UI 文字、日誌、註解一律 **zh-TW 繁體中文**；KISS 原則。
- 帳密僅存 `config.toml`（已 gitignore），不得寫死或提交。
- 修改後驗證：在對應子專案（含 `AntiPhishingCore/`）執行 `cargo check` + `cargo fmt --check` + `cargo test` 皆須通過。
