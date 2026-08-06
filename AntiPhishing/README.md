# AntiPhishing

依指定日期掃描 IMAP 郵件，將達到可設定風險分數的信件移到釣魚信箱。

## 使用方式

1. 將 `config.example.toml` 複製為 `config.toml`，填入 IMAP 帳號與應用程式密碼。不要將 `config.toml` 提交至版本控制。
2. 先以唯讀模式檢視判定結果：

```powershell
cargo run -- --date 2026-08-05 --dry-run
```

3. 確認規則後執行搬移：

```powershell
cargo run -- --date 2026-08-05
```

搬移方式為先複製到 `phishing_mailbox`，再標記來源信件刪除並 expunge；目標信箱必須事先存在。

## 判定規則

- 可疑寄件網域：+4
- 可疑關鍵字：每個 +1，最多 +3
- 兩個以上 URL：+2
- URL 中含 `@`（常用於混淆真正網域）：+3
- Word 附件的外部圖片（開啟時可能回連追蹤伺服器）：+5
- 信任寄件網域：-3（最低為 0）

Word 附件的檢查只讀取 DOCX ZIP 中的 relationship XML，不會開啟 Word、下載圖片或連線至附件所列網址。這是輔助分類工具，不能保證偵測所有釣魚信。請先使用 `--dry-run` 調整規則。
