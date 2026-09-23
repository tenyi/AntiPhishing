# AntiPhishing GUI

Windows GUI 版 IMAP 郵件防護工具。程式從指定日期的 IMAP 郵件中讀取內容，由地端 LLM（OpenAI 相容 API）智慧判定是否為釣魚郵件、詐欺郵件或惡意行銷廣告/垃圾推銷郵件（如仿冒知名品牌促銷、販賣一般性物品/假冒產品之垃圾信），並將符合目標的郵件搬移到設定的指定信箱。

## 環境需求

- Windows 10/11
- Rust stable（建議使用最新版，需支援 Rust 2024 edition）
- 可連線至 IMAP 伺服器
- IMAP 帳號建議使用 App Password，不要使用主要登入密碼
- GUI 使用 eframe `wgpu` 圖形後端，不要求 OpenGL 2.0。

## 設定

在專案目錄執行：

```powershell
cd D:\Git\Program\Rust\AntiPhishingGUI
Copy-Item config.example.toml config.toml
notepad config.toml
```

`config.toml` 主要設定如下：

```toml
[imap]
host = "imap.example.com"
port = 993
protocol = "imaps"       # imaps 或 starttls
username = "you@example.com"
password = "App Password"
source_mailbox = "INBOX"
phishing_mailbox = "Phishing"

[detection]
threshold = 8
suspicious_sender_domains = ["evil.example"]
trusted_sender_domains = []
suspicious_keywords = ["verify", "urgent", "password", "login", "驗證", "緊急"]
external_word_image_score = 6

[gui]
check_interval_minutes = 10
minimize_to_tray = true
hide_taskbar_when_minimized = true
start_minimized_to_tray = false
log_retention_days = 30       # 每日日誌保留天數；0 表示永不清理
font_family = "Noto Sans TC"  # 也可填「微軟正黑體」或字型檔完整路徑

# LLM 智慧判定設定（支援 Claude Code / Agy / Codex CLI、Jev API 與 OpenAI API）
[llm]
backend = "claude"            # 可選 "claude"、"agy"、"codex"、"api"、"jev"、"command"
model = ""                    # 可選。CLI 模式留空使用該工具預設模型，亦可指定特定模型
timeout_secs = 120            # 逾時時間（秒）
max_chars = 6000              # 郵件內文最大字元數
```

設定說明：

- `protocol = "imaps"` 通常使用 993 埠；STARTTLS 請改用 `protocol = "starttls"` 並填入伺服器要求的埠號。
- `threshold` 是判定門檻（預設 8）。傳統評分模式下達到門檻的郵件會搬到 `phishing_mailbox`；一般 LLM 模式下評分僅供 log 參考；Jev 模式下採混合評分制，Jev 機率分數與規則分數加總達標才隔離。
- `external_word_image_score` 用於 DOCX 外部圖片追蹤偵測；預設 6 分。
- `check_interval_minutes` 是排程掃描間隔，範圍為 1–1440 分鐘。
- `log_retention_days` 是每日日誌檔的保留天數，超過即於啟動時刪除；預設 30，設為 0 表示永不清理。
- GUI 啟動後會立即掃描前一日與今日郵件；啟動掃描完成後，排程每次只掃描今日郵件。
- `minimize_to_tray` 開啟後，關閉視窗會留在 Windows 系統匣。
- `hide_taskbar_when_minimized` 開啟後，縮小至系統匣時隱藏工作列項目。
- `start_minimized_to_tray` 開啟後，下次啟動時不顯示主視窗，直接留在 Windows 系統匣。
- `font_family` 可填 `Noto Sans TC`、`微軟正黑體`、`Microsoft JhengHei`，或 `.ttf/.ttc/.otf` 字型檔完整路徑；變更後需重新啟動程式。

---

## LLM 智慧判定設定（支援 Claude Code / Agy / Codex 等 CLI 工具與 Jev API）

本程式支援透過 **Claude Code CLI**、**Antigravity CLI**、**OpenAI Codex CLI**、**TypeSafe Jev (System One) API** 或 **OpenAI 相容 HTTP API** 智慧判定釣魚與垃圾推銷郵件。

### 後端模式對照與特性

| 後端 (`backend`) | 依賴工具 | 必要欄位 | 可選欄位 | 特性說明 |
| :--- | :--- | :--- | :--- | :--- |
| **`jev`** | TypeSafe Jev API | `backend = "jev"`, `api_key` | `base_url`, `model`, `jev_max_score`, `timeout_secs`, `max_chars` | 呼叫 TypeSafe System One API 取得 0.0~1.0 機率，依比例換算為 0~jev_max_score 分數（未滿 60% 不計分，60%~100% 線性換算）並與規則分數加總判定（混合評分制）。 |
| **`claude`** | Claude Code (`claude`) | `backend = "claude"` | `model`, `timeout_secs`, `max_chars` | 自動以 `-p --tools "" --output-format text` 執行，**直接使用本機已登入的 Claude 憑據**，免開本機 API Server、免設定 API Key。 |
| **`agy`** | Antigravity CLI (`agy`) | `backend = "agy"` | `model`, `timeout_secs`, `max_chars` | 自動以 `--output-format text --disable-slash-commands` 執行，**直接使用本機已登入的 agy 憑據**，停用斜線指令。 |
| **`codex`** | OpenAI Codex CLI (`codex`) | `backend = "codex"` | `model`, `timeout_secs`, `max_chars` | 自動以 `exec --skip-git-repo-check --ephemeral --color never -s read-only -` 執行，沙箱唯讀不儲存 session。 |
| **`api`** | HTTP 伺服器 (Ollama 等) | `base_url`, `model` | `api_key`, `timeout_secs`, `max_chars` | 標準 OpenAI 相容 API（未指定 `backend` 時若 `base_url` 非空自動採用此模式）。 |
| **`command`** | 任意自訂命令 | `backend = "command"`, `command` | `timeout_secs`, `max_chars` | 執行自訂指令字串（如 `ollama run llama3.1`），將 Prompt 透過 stdin 傳入。 |

> **事前準備**：使用 CLI 模式前，請先於 Windows 終端機確認該工具已安裝且可執行（例如可正常執行 `claude --version` 或 `agy --version` 並已完成登入授權）。

### 各模式 `config.toml` 設定範例

#### 1. 使用 Claude Code CLI (`backend = "claude"`)
最推薦的方式之一，無需在本機常駐 Ollama，只要本機有安裝 Claude Code 即可：
```toml
[llm]
backend = "claude"
# model 留空使用 Claude Code 當前預設模型；亦可指定如 "claude-3-7-sonnet"、"claude-3-5-haiku"
model = ""
timeout_secs = 120
max_chars = 6000
```

#### 2. 使用 Google DeepMind Antigravity CLI (`backend = "agy"`)
適合使用 Google Antigravity 生態系的使用者：
```toml
[llm]
backend = "agy"
# model 留空使用 agy 預設模型；亦可指定特定模型
model = ""
timeout_secs = 120
max_chars = 6000
```

#### 3. 使用 OpenAI Codex CLI (`backend = "codex"`)
```toml
[llm]
backend = "codex"
# model 留空使用 codex 預設模型；亦可指定如 "o3-mini"
model = ""
timeout_secs = 120
max_chars = 6000
```

#### 4. 使用地端 Ollama / LM Studio (`backend = "api"`)
```toml
[llm]
backend = "api"
base_url = "http://127.0.0.1:11434/v1"
model = "llama3.1"
api_key = ""                             # 地端免認證模型可留空
timeout_secs = 120
max_chars = 6000
```

#### 5. 使用自訂命令列 (`backend = "command"`)
```toml
[llm]
backend = "command"
command = "ollama run llama3.1"
timeout_secs = 120
max_chars = 6000
```

#### 6. 使用 TypeSafe Jev API (`backend = "jev"`，混合評分制)
適合使用 TypeSafe System One 模型（以機率為核心的判定）：
```toml
[llm]
backend = "jev"
# base_url 留空預設為 "https://api.typesafe.ai"
base_url = "https://api.typesafe.ai"
# model 留空預設為 "jev-latest"
model = "jev-latest"
api_key = "sk-typesafe-..."              # 必填：TypeSafe API Key
jev_max_score = 10                       # Jev 換算分數上限（預設 10；機率 <0.6 不計分，0.6~1.0 線性換算）
timeout_secs = 120
max_chars = 6000
```

> **注意**：
> - **白名單直接安全豁免**：寄件來源符合 `trusted_sender_domains` 且未發生 SPF/DMARC 偽造失敗者，直接豁免略過（不耗費 token、不送 LLM/Jev、不搬移）；若安全驗證失敗則取消白名單豁免並告警送檢。
> - **安全驗證與傳輸狀態感知**：自動解析最外層受信邊界之 SPF、DKIM、DMARC 狀態與 TLS 加密，完整注入至 LLM 與 Jev Prompt，並指示模型對來源正常的資安通報或垃圾信隔離明細不予誤判。
> - 若皆未設定 `[llm]`，或 `backend` 與 `base_url` 皆留空，則自動停用 LLM 判定（GUI 模式下不會搬移任何郵件，傳統評分僅供執行紀錄參考）。
> - 在 Jev 模式下，Jev 評定的釣魚機率未滿 60% 不計分，60%~100% 依比例換算為 \(0 \sim \text{jev\_max\_score}\) 分並與安全規則分數加總，達到 `threshold` 門檻才進行隔離（可於 GUI 設定面板調整後端模式與 Jev 評分上限）。

程式不會開啟 Word 或連線下載附件內容；DOCX 僅檢查 ZIP 內的 Word relationship XML，找出外部 HTTP(S) 圖片連結。

## 日誌與掃描進度檔

程式會在**執行檔所在目錄**維護兩種檔案（皆已加入 `.gitignore`，不應提交）：

- `logs\YYYY-MM-DD.log`：每日一個日誌檔，每行帶 `[YYYY-MM-DD HH:MM:SS]` 時間戳，記錄郵件掃描與判定結果（無新郵件之空掃不寫入日誌）。啟動時自動刪除超過保留天數的舊日誌，天數由 `[gui] log_retention_days` 設定（預設 30；設為 0 表示永不清理）。
- `scan_state.toml`：掃描進度檔。記錄來源信箱的 UIDVALIDITY、已完整判定的最大 UID（斷點）、最後判定郵件的 UID／主旨／所屬日期與最後檢查時間。**啟動時讀取此檔續用斷點**，重啟後第一輪掃描即跳過已檢查過的信件，避免重複送 LLM 判定浪費資源。

GUI「執行紀錄」區只顯示當日條目（重啟時回填今日日誌尾端約 200 行），完整歷史請看每日日誌檔。若進度檔損毀或刪除，程式會警告並重新檢查近兩日郵件（安全側行為）。

## 開發模式執行

```powershell
cd D:\Git\Program\Rust\AntiPhishingGUI
cargo run
```

啟動後可在 GUI 修改設定。按「儲存設定」會將內容寫入專案目錄的 `config.toml`；按「立即掃描指定日期」會依畫面上的日期執行掃描。排程掃描則會自動掃描當日郵件。

## 編譯與執行 Release 版本

```powershell
cd D:\Git\Program\Rust\AntiPhishingGUI
cargo build --release
.\target\release\anti-phishing-gui.exe
```

可直接執行的檔案是 `target\release\anti-phishing-gui.exe`。執行檔旁需要有 `config.toml`；若從其他工作目錄啟動，請先切換到執行檔所在目錄，或使用絕對路徑設定工作目錄。

## 測試

```powershell
cargo fmt --check
cargo test
```

測試不會連線到真實 IMAP 信箱。

## 系統匣操作

系統匣圖示的選單提供：

- 顯示視窗
- 立即掃描當日郵件
- 結束程式

## 安全注意事項

`config.toml` 會包含明文密碼，請限制檔案存取權限，並避免將它提交到 Git。專案已將 `config.toml` 加入 `.gitignore`。第一次使用建議先設定較高門檻並觀察結果，確認規則後再正式啟用自動搬移。
