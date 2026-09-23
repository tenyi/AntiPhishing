# AntiPhishing

依指定日期掃描 IMAP 郵件，以地端 LLM（OpenAI 相容 API）判定釣魚／詐欺／惡意行銷廣告郵件，搬移至指定信箱；未設定 LLM 時回退傳統評分規則。

## 使用方式

1. 將 `config.example.toml` 複製為 `config.toml`，填入 IMAP 帳號與應用程式密碼。不要將 `config.toml` 提交至版本控制。
2. 先以唯讀模式檢視判定結果：

```powershell
cargo run -- --date 2026-08-05 --dry-run
```

3. 執行掃描與搬移：

```powershell
cargo run -- --date 2026-08-05            # LLM 判定後逐封互動確認再搬移
cargo run -- --date 2026-08-04 --date 2026-08-05   # 可重複 --date 掃描多天
cargo run -- --date 2026-08-05 -y         # 跳過互動確認，直接搬移全部判定郵件
```

- 掃描進度顯示在 stderr，判定結果輸出至 stdout，方便管線處理（如 `| tee scan.log`）。
- 搬移方式為先複製到 `phishing_mailbox`，再以 UID EXPUNGE 只清除本輪已搬移的信件；目標信箱不存在時會自動建立。
- 搬移前會重新比對 UIDVALIDITY，避免信箱重建後誤搬。

## LLM 智慧判定（建議）

支援地端/雲端 OpenAI 相容 API、**TypeSafe Jev (System One)** API，以及直接以命令列呼叫 **Claude Code CLI**、**Antigravity CLI**、**OpenAI Codex CLI** 或**自訂命令**。

### 後端模式對照與快速設定

| 後端 (`backend`) | 依賴工具 | 必要欄位 | 可選欄位 | 特性與預設參數 |
| :--- | :--- | :--- | :--- | :--- |
| **`jev`** | TypeSafe Jev API | `backend = "jev"`, `api_key` | `base_url`, `model`, `jev_max_score`, `timeout_secs`, `max_chars` | 呼叫 TypeSafe System One API 取得 0.0~1.0 機率，依比例換算為 0~jev_max_score 分數（未滿 60% 不計分，60%~100% 線性換算）並與規則分數加總判定（混合評分制）。 |
| **`claude`** | Claude Code (`claude`) | `backend = "claude"` | `model`, `timeout_secs`, `max_chars` | 自動帶入 `-p --tools "" --output-format text`，直接使用本機登入憑據，無須 API 金鑰，停用本地工具安全隔離。 |
| **`agy`** | Antigravity CLI (`agy`) | `backend = "agy"` | `model`, `timeout_secs`, `max_chars` | 自動帶入 `--output-format text --disable-slash-commands`，直接使用本機登入憑據，停用斜線指令。 |
| **`codex`** | OpenAI Codex CLI (`codex`) | `backend = "codex"` | `model`, `timeout_secs`, `max_chars` | 自動帶入 `exec --skip-git-repo-check --ephemeral --color never -s read-only -`，沙箱唯讀不儲存 session。 |
| **`api`** | HTTP 伺服器 (Ollama 等) | `base_url`, `model` | `api_key`, `timeout_secs`, `max_chars` | 標準 OpenAI 相容 API（未指定 `backend` 時若 `base_url` 非空自動採用此模式）。 |
| **`command`** | 任意自訂命令 | `backend = "command"`, `command` | `timeout_secs`, `max_chars` | 執行自訂命令（如 `ollama run llama3.1`），將 Prompt 經 stdin 管道輸入。 |

> **提示**：使用 CLI 工具模式（`claude` / `agy` / `codex`）前，請先確保該工具已安裝於系統環境變數 PATH 中並完成初次登入（例如可於終端機執行 `claude --version` 或 `agy --version`）。

---

### 常見設定範例

#### 範例 1：使用 Anthropic Claude Code CLI（超省事，免開 API Server、免填 Key）
```toml
[llm]
backend = "claude"
# model 留空即使用 Claude Code 當前預設模型；亦可指定例如 "claude-3-7-sonnet" 或 "claude-3-5-haiku"
model = ""
timeout_secs = 120
max_chars = 6000
```

#### 範例 2：使用 Google DeepMind Antigravity CLI (`agy`)
```toml
[llm]
backend = "agy"
# model 留空即使用 agy 當前預設模型；亦可指定例如 "gemini-2.5-pro" 或 "gemini-2.5-flash"
model = ""
timeout_secs = 120
max_chars = 6000
```

#### 範例 3：使用 OpenAI Codex CLI (`codex`)
```toml
[llm]
backend = "codex"
# model 留空即使用 codex 預設模型；亦可指定例如 "o3-mini"
model = ""
timeout_secs = 120
max_chars = 6000
```

#### 範例 4：使用地端 Ollama / LM Studio (OpenAI 相容 HTTP API)
```toml
[llm]
backend = "api"
base_url = "http://127.0.0.1:11434/v1"
model = "llama3.1"
api_key = ""                             # 地端免認證模型可留空
timeout_secs = 120
max_chars = 6000
```

#### 範例 5：使用自訂命令列 (`command`)
```toml
[llm]
backend = "command"
command = "ollama run llama3.1"
timeout_secs = 120
max_chars = 6000
```

#### 範例 6：使用 TypeSafe Jev API (`backend = "jev"`，混合評分制)
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

---

### 判定流程與搬移確認

- **白名單直接安全豁免**：寄件來源命中 `trusted_sender_domains` 且未發生 SPF/DMARC 偽造失敗者，直接豁免略過（不耗費 token、不送 LLM/Jev、不搬移）；若安全驗證失敗則取消白名單豁免並告警送檢。
- **安全驗證與傳輸加密資訊傳遞**：每封信件自動解析最外層受信邊界之 SPF、DKIM、DMARC 狀態與 TLS 加密，注入至 LLM 與 Jev Prompt，並指示模型對來源正常的資安通報或垃圾信隔離明細不予誤判。
- **一般 LLM 模式（api / claude / agy / codex / command）**：每封信的內文連同寄件者、主旨送 LLM 判定；LLM 判定為「釣魚、詐欺、惡意行銷廣告或垃圾推銷」者列為待搬移（啟發式規則評分僅供 log 參考）。
- **Jev 模式（jev，混合評分制）**：每封信送 TypeSafe Jev API 判定得到釣魚機率 \(p \in [0.0, 1.0]\)，未滿 60% 不計分，\(0.6 \sim 1.0\) 依比例換算為 \(0 \sim \text{jev\_max\_score}\) 分並與規則分數加總；總分達到 `threshold`（預設 8 分）者列為待搬移。這讓 Jev 做為其中一種分數共同評估，避免單一模型 100% 獨斷。

預設於掃描結束後列出清單互動確認：

```text
以下 2 封郵件判定為釣魚／惡意廣告：
  [0] UID 123　評分 7　〈DHL：包裹待領取〉
      理由：偽裝 DHL 且要求支付關稅
  [1] UID 124　評分 9　〈限時優惠〉
      理由：Jev 評定釣魚機率 88%（+7分）；含 2 個可疑關鍵字
搬移方式：[a]全部搬移 [s]全部跳過 [c]逐封決定？
```

- `[a]` 全部搬移、`[s]` 全部跳過（直接按 Enter 亦為跳過）、`[c]` 逐封決定。
- LLM 請求失敗（工具異常、服務不可用）時退回規則評分判讀：本封若啟發式分數達 `threshold` 仍會被列入待搬移清單，掃描繼續執行而不中斷；同一日期內若 LLM 連續失敗 ≥3 次，本輪後續信件直接採規則評分。
- 未設定 LLM 時沿用傳統門檻模式：啟發式評分 ≥ `threshold` 即自動搬移（維持舊有行為，不互動確認）。

## 傳統評分規則（log 參考；未設定 LLM 時為搬移依據）

- 可疑寄件網域：+4
- 可疑關鍵字：每個 +1，最多 +3
- 兩個以上 URL：+2
- URL 中含 `@`（常用於混淆真正網域）：+3
- HTML 內嵌 QR code 圖片（quishing）：+4
- 品牌偽裝（顯示名稱含 DHL/FedEx/UPS 但非官方網域）：+3
- Word 附件的外部圖片（開啟時可能回連追蹤伺服器）：+6
- 信任寄件網域：未被直接豁免時扣 3 分（最低為 0）

Word 附件的檢查只讀取 DOCX ZIP 中的 relationship XML，不會開啟 Word、下載圖片或連線至附件所列網址。這是輔助分類工具，不能保證偵測所有釣魚信。請先使用 `--dry-run` 調整規則。
