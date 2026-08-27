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

## LLM 判定（建議）

在 `config.toml` 加入 `[llm]`（base_url 或 model 留空即停用）：

```toml
[llm]
base_url = "http://127.0.0.1:11434/v1"   # Ollama / LM Studio / llama.cpp 或雲端 API
model = "llama3.1"
api_key = ""                             # 可選：API 金鑰（地端免認證模型可留空）
timeout_secs = 120                       # 可選：單一請求逾時（秒）
max_chars = 6000                         # 可選：送給 LLM 的內文最大字元數
```

啟用後每封信的 text/plain 與 HTML 內文（轉純文字、去除 style/base64 噪音）連同寄件者、主旨送地端 LLM 判定；LLM 判定為「釣魚、詐欺、惡意行銷廣告或垃圾推銷」者列為待搬移，預設於掃描結束後列出清單互動確認：

```text
以下 2 封郵件判定為釣魚／惡意廣告：
  [0] UID 123　評分 7　〈DHL：包裹待領取〉
      理由：偽裝 DHL 且要求支付關稅
  [1] UID 124　評分 5　〈限時優惠〉
      理由：未經請求的推銷廣告
搬移方式：[a]全部搬移 [s]全部跳過 [c]逐封決定？
```

- `[a]` 全部搬移、`[s]` 全部跳過（直接按 Enter 亦為跳過）、`[c]` 逐封決定。
- LLM 請求失敗（服務不可用、設定錯誤）時立即中止本輪且不搬移任何郵件。
- 未設定 LLM 時沿用傳統門檻模式：啟發式評分 ≥ `threshold` 即自動搬移（維持舊有行為，不互動確認）。

## 傳統評分規則（log 參考；未設定 LLM 時為搬移依據）

- 可疑寄件網域：+4
- 可疑關鍵字：每個 +1，最多 +3
- 兩個以上 URL：+2
- URL 中含 `@`（常用於混淆真正網域）：+3
- HTML 內嵌 QR code 圖片（quishing）：+4
- 品牌偽裝（顯示名稱含 DHL/FedEx/UPS 但非官方網域）：+3
- Word 附件的外部圖片（開啟時可能回連追蹤伺服器）：+5
- 信任寄件網域：-3（最低為 0）

Word 附件的檢查只讀取 DOCX ZIP 中的 relationship XML，不會開啟 Word、下載圖片或連線至附件所列網址。這是輔助分類工具，不能保證偵測所有釣魚信。請先使用 `--dry-run` 調整規則。
