# AntiPhishing - IMAP 郵件防護與智慧偵測工具

基於 Rust 開發的現代化 IMAP 郵件掃描與防護系統，專為防範釣魚詐欺、惡意行銷廣告與垃圾推銷郵件而設計。本專案包含兩個獨立套件：

- **CLI 版本 (`AntiPhishing/`)**：輕量高效率的命令列工具，適合排程掃描指定日期、唯讀乾跑驗證與批次處理。
- **GUI 版本 (`AntiPhishingGUI/`)**：具備 Windows 系統匣常駐、背景排程定時掃描、斷點續掃記憶與搬移確認對話框的桌面應用程式（基於 eframe）。

---

## 主要特色

- **多後端 LLM 智慧判定**：
  - 支援地端/雲端 **OpenAI 相容 HTTP API**（例如 Ollama / LM Studio / llama.cpp / vLLM / OpenAI 相容服務）。
  - 支援 **TypeSafe Jev (System One)** API：以 `noul` primitive 取得精確釣魚機率，採**混合評分制（Composite Scoring）**將機率換算為分數，與安全規則加總判定（非 100% 一票專斷）。
  - 支援直接透過命令列呼叫 **Claude Code CLI (`claude`)**、**OpenAI Codex CLI (`codex`)**、**Antigravity CLI (`agy`)** 或**自訂命令 (`command`)**。
  - 提示詞採用 stdin 管道安全串流傳入，無命令列長度限制；外部 CLI 預設封鎖本地操作權限與工具呼叫，安全隔離。
- **深層威脅特徵識別**：
  - **釣魚與詐欺**：偽裝知名品牌（DHL、FedEx、銀行等）、要求更新個資或繳費、緊急施壓等行為。
  - **惡意行銷與推銷廣告**：仿冒促銷、未經請求推銷、一般性商品廣告、假退訂連結（Opt-Out）。
  - **Quishing 偵測**：識別 HTML 內嵌 QR Code 與手機掃描提示。
  - **白名單直接安全豁免**：寄件來源符合 `trusted_sender_domains` 且未發生 SPF/DMARC 偽造失敗時，直接安全豁免跳過（不耗費 token、不搬移）；若有驗證失敗則取消豁免並警示送檢。
  - **安全驗證與傳輸狀態感知**：解析最外層受信邊界之 SPF、DKIM、DMARC 驗證結果與 TLS (SMTPS) 加密狀態，完整注入 LLM / Jev Prompt；資安通報與隔離報告在驗證通過時排除誤判。
  - **DOCX 外部圖片追蹤**：安全離線解析 Word 附件關聯 XML，偵測外部 Web Bug / 開啟追蹤圖片（不啟動 Office、不下載外部資源）。
- **搬移確認機制（防誤判）**：
  - **CLI 版**：掃描完成後列出判定清單，支援 `[a]` 全部搬移、`[s]` 全部跳過、`[c]` 逐封決定；可帶 `-y` 參數非互動直接搬移。
  - **GUI 版**：完成掃描後彈出待確認清單對話框，核對無誤後才搬移至指定資料夾。
- **斷點續掃與日誌管理（GUI）**：
  - 透過 `scan_state.toml` 跨重啟記憶檢查斷點（`max_checked_uid`），重啟後自動略過已完成判定的信件，節省 LLM 資源。
  - 每日獨立日誌檔（`logs/YYYY-MM-DD.log`），啟動時依設定自動清理過期紀錄。
- **安全防護**：
  - 支援 App Password 應用程式密碼，設定檔 `config.toml` 已預設加入 `.gitignore`。
  - 搬移前重驗來源信箱 `UIDVALIDITY`，避免信箱結構變動時誤搬。

---

## 專案結構

本儲存庫由兩個**獨立的 Cargo 套件**組成（各自擁有獨立的 `Cargo.toml` 與 `Cargo.lock`）：

```text
AntiPhishing/
├── AntiPhishing/              # CLI 命令列版套件 (anti-phishing)
│   ├── src/main.rs            # CLI 單一檔案主程式與單元測試
│   ├── Cargo.toml             # CLI 相依性與版號
│   ├── config.example.toml    # CLI 設定範本
│   └── README.md              # CLI 詳細說明
│
├── AntiPhishingGUI/           # GUI 桌面版套件 (anti-phishing-gui)
│   ├── src/main.rs            # GUI 單一檔案主程式與單元測試
│   ├── Cargo.toml             # GUI 相依性與版號
│   ├── config.example.toml    # GUI 設定範本
│   ├── AntiPhishing.ico       # 應用程式圖示
│   └── README.md              # GUI 詳細說明
│
├── docs/                      # 系統架構與設計藍圖文件
├── AGENTS.md                  # AI Agent 開發慣例與守則
├── CLAUDE.md                  # 專案指引與版號規範
├── DETECTION.md               # 釣魚郵件判定機制與防護體系說明書
├── LICENSE.txt                # Apache 2.0 授權條款
└── README.md                  # 專案總覽文件
```

---

## 快速上手

### 1. 環境需求

- Windows 10 / 11（64 位元）
- Rust stable（支援 Rust 2024 edition）
- 支援 IMAP 之電子信箱（強烈建議使用應用程式專用密碼 App Password）
- （選用）LLM 服務或 CLI 工具：Ollama / LM Studio、Claude Code、Codex CLI 或 Antigravity CLI

### 2. 設定檔配置

在欲執行的子專案目錄下複製設定檔範本：

```powershell
# 設定 CLI 版
cd AntiPhishing
Copy-Item config.example.toml config.toml
notepad config.toml

# 或設定 GUI 版
cd AntiPhishingGUI
Copy-Item config.example.toml config.toml
notepad config.toml
```

#### 設定重點範例 (`config.toml`)

```toml
[imap]
host = "imap.example.com"
port = 993
protocol = "imaps"                  # 可選 "imaps" 或 "starttls"
username = "your_account@example.com"
password = "your_app_password"      # 請使用應用程式密碼
source_mailbox = "INBOX"
phishing_mailbox = "Phishing"       # 隔離目標資料夾

[detection]
threshold = 8                       # 傳統評分搬移門檻（未設定 LLM 時回退使用）
suspicious_sender_domains = ["evil.example"]
trusted_sender_domains = ["company.example"]
suspicious_keywords = ["verify", "urgent", "password", "login", "帳戶", "驗證", "緊急", "密碼"]
external_word_image_score = 6

# --- LLM 智慧判定設定 ---
[llm]
# 後端類型：可選 "api" (預設)、"jev"、"claude"、"codex"、"agy"、"command"
backend = "claude"

# [api 模式適用]
base_url = "http://127.0.0.1:11434/v1"
api_key = ""

# [jev 模式適用（TypeSafe Jev System One 混合評分）]
# backend = "jev"
# base_url = "https://api.typesafe.ai"  # 選填，預設 https://api.typesafe.ai
# model = "jev-latest"                  # 選填，預設 jev-latest
# api_key = "sk-..."                   # 必填
# jev_max_score = 10                    # Jev 分數換算上限（預設 10；機率 <0.6 不計分，0.6~1.0 線性換算）

# [共用設定]
# 模型名稱。CLI 模式留空則自動使用該 CLI 預設模型；亦可明確指定（如 "claude-3-7-sonnet"、"o3-mini"）
model = ""
timeout_secs = 120                  # 逾時時間（秒）
max_chars = 6000                    # 郵件內文最大字元數

# [command 模式適用]
# command = "ollama run llama3.1"
```

---

## 執行方式

### A. 命令列版本 (CLI)

所有指令請在 `AntiPhishing/` 目錄內執行：

```powershell
cd AntiPhishing

# 1. 唯讀檢視（--dry-run）：只分析與判定，不實際搬移任何郵件
cargo run -- --date 2026-09-23 --dry-run

# 2. 正常掃描並互動確認：掃描完成後列出清單，由使用者確認是否搬移
cargo run -- --date 2026-09-23

# 3. 掃描多個日期（可重複傳入 --date）
cargo run -- --date 2026-09-22 --date 2026-09-23

# 4. 自動搬移（-y / --yes）：判定為釣魚/垃圾信即直接搬移，不進行提示確認
cargo run -- --date 2026-09-23 -y
```

> **提示**：掃描進度輸出至 `stderr`，分析結果輸出至 `stdout`，方便透過管線重新導向或儲存紀錄（例如 `cargo run -- --date 2026-09-23 2>progress.log | tee result.log`）。

### B. 圖形介面版本 (GUI)

所有指令請在 `AntiPhishingGUI/` 目錄內執行：

```powershell
cd AntiPhishingGUI

# 開發模式啟動
cargo run

# 編譯正式釋出版本
cargo build --release
```

- 正式執行檔位於 `AntiPhishingGUI/target/release/anti-phishing-gui.exe`。
- **系統匣功能**：支援關閉視窗最小化至系統匣、系統匣選單隨時手動觸發掃描、自訂排程間隔掃描。
- **開機背景常駐**：可搭配 `start_minimized_to_tray = true`，啟動即縮小至系統匣。

---

## 開發與測試守則

本專案採嚴格之品質與同步規範：

1. **雙版同步原則**：兩版共用核心概念（IMAP 掃描、LLM 判定、DOCX 外部圖片偵測、搬移確認），**修改共用邏輯時必須兩版同步修改並各自驗證**。
2. **版號升級規範**：提交變更前必須升級該專案 `Cargo.toml` 之版號（新功能 minor、錯誤修正 patch），並執行 `cargo check` 同步 `Cargo.lock`。
3. **驗證指令**（必須於對應子專案目錄分別執行）：

   ```powershell
   cargo check          # 檢查編譯與同步 Cargo.lock
   cargo fmt --check    # 格式檢查
   cargo test           # 執行離線單元測試（不連線真實 IMAP）
   ```

---

## 授權條款

本專案採用 [Apache License 2.0](LICENSE.txt) 授權釋出，詳細內容請參閱 `LICENSE.txt`。
