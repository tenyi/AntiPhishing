# AGENTS.md

本文件供 AI Agent 快速理解本專案之背景、架構、常用指令與開發原則。

## 專案概述

- **專案名稱**：AntiPhishing GUI (`anti-phishing-gui`)
- **專案類型**：Windows 桌面 GUI 應用程式 (Rust 2024 edition)
- **核心功能**：透過 IMAP 讀取指定日期的郵件，依關鍵字、寄件者網域、DOCX 外部圖片追蹤等偵測疑似釣魚郵件，並將達門檻者搬移至指定資料夾。
- **技術棧**：
  - GUI 與系統：`eframe` (wgpu 圖形後端) + `tray-icon` (Windows 系統匣支援) + `single-instance` (防重複執行)
  - 網路與解析：`imap`, `native-tls`, `mailparse`, `quick-xml`, `zip`
  - 設定：`toml`, `serde`

---

## 常用指令

```powershell
# 檢查與格式化
cargo check
cargo fmt --check
cargo fmt

# 執行單元測試（不連線真實 IMAP）
cargo test

# 開發模式執行
cargo run

# 建置 Release 版本
cargo build --release
```

---

## 專案架構

```text
AntiPhishingGUI/
├── Cargo.toml            # 專案相依與中繼資料 (Rust 2024 edition)
├── build.rs              # Windows 資源編譯 (圖示/資訊)
├── config.example.toml   # 設定檔範本
├── config.toml           # 執行期設定檔 (包含 IMAP 帳密、偵測門檻、GUI 選項)
└── src/
    └── main.rs           # 包含所有主程式邏輯、GUI 介面、IMAP 檢查、郵件評分與測試
```

---

## 開發守則與規範

1. **KISS 原則**：保持簡單直接，避免過度工程與不必要的抽象化。
2. **語言規範**：UI 文字、日誌訊息、程式碼註解與回應一律使用 **zh-TW 繁體中文**。
3. **設定與安全性**：
   - 帳密與敏感資訊僅存於 `config.toml`，切勿寫死在程式碼內或提交至版本控制。
   - 附件偵測不可連網下載外部資源或啟動外部 Office 程式。
4. **驗證方式**：修改程式碼後，請確保 `cargo check` 與 `cargo test` 通過。
