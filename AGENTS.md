# AGENTS.md

供 AI Agent 在本 repo 工作時掌握關鍵慣例與陷阱；架構細節見各子專案文件（文末參考）。

## 專案結構

- 兩個**獨立的 Cargo 套件**，不是 workspace（無根 `Cargo.toml`，各自有 `Cargo.lock`）：
  - `AntiPhishing/`：CLI 版（`anti-phishing`），一次性掃描指定日期郵件。
  - `AntiPhishingGUI/`：GUI 版（`anti-phishing-gui`），eframe 桌面常駐 + 系統匣排程。
- 所有邏輯集中在各自的單一檔案 `src/main.rs`（含測試），刻意不拆模組。
- 兩版共用核心概念：IMAP 掃描（`scan_mail`）、LLM 判定（`llm_judge`）、DOCX 外部圖片偵測、搬移確認。**修改共用邏輯時兩版都要同步修改並各自驗證**——只改一邊是最常見的錯誤。

## 指令與驗證

所有 cargo 指令必須在**對應子專案目錄**內執行：

```powershell
cargo check          # 同步更新該子專案的 Cargo.lock
cargo fmt --check
cargo test           # 測試皆為離線單元測試，不連真實 IMAP
cargo test detects_external_word_image_relationship   # 單一測試範例
```

修改後驗證：`cargo check` + `cargo fmt --check` + `cargo test` 三者皆須通過（無 CI，靠手動）。

CLI 實際掃描前先唯讀驗證判定結果：`cargo run -- --date 2026-08-05 --dry-run`；`--date` 可重複掃多天；`-y` 跳過互動確認直接搬移。進度走 stderr、結果走 stdout。

## 必守規範

- **提交前必須升該子專案 `Cargo.toml` 的版號**：新功能 minor、錯誤修正 patch；跑一次 `cargo check` 同步 `Cargo.lock`。
- UI 文字、日誌、註解一律 **zh-TW 繁體中文**；KISS 原則，不引入多餘抽象。
- Commit message 採 conventional commits（`feat(cli):` / `fix(ui):` 等 scope），描述用 zh-TW。
- 帳密僅存 `config.toml`（已 gitignore），不得寫死或提交；建議使用 App Password。
- DOCX 附件偵測只能離線解析 ZIP 內的 relationship XML：不可連網下載外部資源、不可啟動外部 Office 程式。

## 陷阱

- `config.toml` 路徑解析兩版不同：CLI 用 `--config` 參數（預設相對**工作目錄**）；GUI 相對**執行檔所在目錄**（`current_exe()`），從別處啟動 exe 須以 exe 目錄為工作目錄。
- 搬移是 copy 到目標信箱 + `\Deleted` flag + expunge，非 server-side MOVE；CLI 搬移前會重驗 UIDVALIDITY。
- LLM 未設定（`[llm]` 的 base_url 或 model 為空）時兩版行為刻意不同：CLI 回退傳統評分門檻自動搬移；GUI 一律不搬移、無確認。

## 參考文件

- 根 `CLAUDE.md`：版號規範與兩版同步原則。
- `AntiPhishingGUI/AGENTS.md`、`AntiPhishingGUI/CLAUDE.md`：GUI 架構細節（eframe logic/ui 分工、搬移確認 Dialog、系統匣、字型注入等）。
- 各子專案 `README.md`：設定欄位、評分規則、CLI 用法。
