# AntiPhishing GUI

Windows GUI 版 IMAP 郵件防護工具。程式從指定日期的 IMAP 郵件中讀取內容，依偵測分數判斷疑似 phishing mail，並將符合門檻的郵件搬到指定的釣魚信箱。

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
threshold = 5
suspicious_sender_domains = ["evil.example"]
trusted_sender_domains = []
suspicious_keywords = ["verify", "urgent", "password", "login", "驗證", "緊急"]
external_word_image_score = 5

[gui]
check_interval_minutes = 10
minimize_to_tray = true
hide_taskbar_when_minimized = true
start_minimized_to_tray = false
font_family = "Noto Sans TC"  # 也可填「微軟正黑體」或字型檔完整路徑
```

設定說明：

- `protocol = "imaps"` 通常使用 993 埠；STARTTLS 請改用 `protocol = "starttls"` 並填入伺服器要求的埠號。
- `threshold` 是判定門檻。分數達到門檻的郵件會搬到 `phishing_mailbox`。
- `external_word_image_score` 用於 DOCX 外部圖片追蹤偵測；預設 5 分。
- `check_interval_minutes` 是排程掃描間隔，範圍為 1–1440 分鐘。
- GUI 啟動後會立即掃描前一日與今日郵件；啟動掃描完成後，排程每次只掃描今日郵件。
- `minimize_to_tray` 開啟後，關閉視窗會留在 Windows 系統匣。
- `hide_taskbar_when_minimized` 開啟後，縮小至系統匣時隱藏工作列項目。
- `start_minimized_to_tray` 開啟後，下次啟動時不顯示主視窗，直接留在 Windows 系統匣。
- `font_family` 可填 `Noto Sans TC`、`微軟正黑體`、`Microsoft JhengHei`，或 `.ttf/.ttc/.otf` 字型檔完整路徑；變更後需重新啟動程式。

程式不會開啟 Word 或連線下載附件內容；DOCX 僅檢查 ZIP 內的 Word relationship XML，找出外部 HTTP(S) 圖片連結。

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
