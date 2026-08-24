# AntiPhishing - IMAP 郵件防護與智慧偵測工具

本專案提供基於 Rust 開發的 IMAP 郵件掃描與釣魚/垃圾推銷郵件偵測工具，包含**命令列版本 (CLI)** 與 **Windows 圖形介面版本 (GUI)**。

## 主要特色

- **IMAP 自動掃描**：透過 IMAP 協定自動讀取指定日期的郵件。
- **地端 LLM 智慧判定**：支援地端 LLM（OpenAI 相容 API）智慧判定釣魚、品牌偽裝、Quishing 及惡意推銷郵件。
- **附件安全檢查**：支援 DOCX 外部圖片追蹤等惡意特徵分析（安全離線解析，不執行外部程式）。
- **郵件自動搬移**：判定為目標郵件者，可自動或經由 UI 確認後搬移至指定信箱資料夾。
- **系統匣常駐**：Windows 系統匣常駐支援與排程定時自動掃描功能（GUI 版本）。

## 目錄結構

```text
AntiPhishing/
├── AntiPhishing/          # 命令列版本 (CLI)
│   ├── src/
│   ├── Cargo.toml
│   ├── config.example.toml
│   └── README.md
│
├── AntiPhishingGUI/       # Windows GUI 版本 (桌面應用程式)
│   ├── src/
│   ├── Cargo.toml
│   ├── config.example.toml
│   ├── AGENTS.md
│   └── README.md
│
├── .gitignore             # Git 忽略設定
├── LICENSE.txt            # Apache License 2.0 授權條款
└── README.md              # 專案說明文件
```

## 快速開始

### 1. 環境需求

- Windows 10 / 11
- Rust stable（建議使用最新版本，需支援 Rust 2024 edition）
- 可連線之 IMAP 郵件伺服器（建議使用 App Password 應用程式密碼）

### 2. 設定檔建立

分別進入 `AntiPhishing` 或 `AntiPhishingGUI` 目錄，複製設定範本並填入設定：

```powershell
Copy-Item config.example.toml config.toml
notepad config.toml
```

### 3. 執行程式

- **啟動 GUI 介面**：
  ```powershell
  cd AntiPhishingGUI
  cargo run
  ```

- **執行 CLI 掃描**（以 `2026-08-05` 為例，使用唯讀檢視模式）：
  ```powershell
  cd AntiPhishing
  cargo run -- --date 2026-08-05 --dry-run
  ```

## 授權條款

本專案採用 [Apache License 2.0](LICENSE.txt) 授權，詳情請參閱 `LICENSE.txt`。