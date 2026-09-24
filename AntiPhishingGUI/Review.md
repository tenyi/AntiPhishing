# AntiPhishing 程式碼精準審查報告

> **審查日期**：2026-09-24  
> **涵蓋範圍**：`AntiPhishingGUI/`（GUI 版本，`src/main.rs`）與 `AntiPhishing/`（CLI 版本，`src/main.rs`）  
> **專案原則確認**：遵循專案核心規範——**所有邏輯集中於各自的單一檔案 `src/main.rs`，刻意不拆模組，堅持 KISS 原則；修改共用邏輯時 CLI 與 GUI 兩版必須同步修改並各自驗證**。

---

## 0. 審查摘要與問題總覽

本報告經過原始碼逐行比對、RFC 規範核實以及跨平台（Windows / macOS / Linux）行為驗證，剔除所有不實幻覺與違反專案原則的過度工程建議，僅保留**客觀存在、真正影響安全與可靠性**的問題。

| 嚴重性 | 編號 | 問題標題 | 影響模組 / 函式 | 需同步修復版本 |
|:---:|:---:|---|---|:---:|
| 🔴 **High** | H-1 | 信任清單採用子字串匹配，攻擊者可繞過白名單豁免 | `is_trusted_sender`, `phishing_score` | GUI + CLI |
| 🔴 **High** | H-2 | 設定檔與狀態檔寫入非原子操作，異常終止有檔案截斷損毀風險 | `App::save`, `save_scan_state` | GUI |
| 🔴 **High** | H-3 | 郵件安全驗證警告（warnings）未與權威 MTA 結果保持一致 | `check_auth_status` | GUI + CLI |
| 🟠 **Medium** | M-1 | 品牌偽裝偵測使用子字串比對，短品牌名可能誤判英文單字 | `phishing_score` | GUI + CLI |
| 🟠 **Medium** | M-2 | 待確認隔離佇列（`pending_queue`）缺乏防禦性容量上限 | `App::poll`, `scan_mail` | GUI |
| 🟠 **Medium** | M-3 | 儲存設定檔時未於 Unix/macOS 設定檔案存取權限（0600） | `App::save` | GUI |
| 🟡 **Low** | L-1 | 存在未使用的死代碼封裝函式 | `is_docx_part`, `external_word_image_targets_from_docx` | GUI + CLI |
| 🟡 **Low** | L-2 | 單元測試暫存目錄命名應加入進程/執行緒 ID 強化隔離 | `temp_test_dir` | GUI |

---

## 1. 高嚴重性問題（需優先修正）

### 🔴 H-1：信任清單採用子字串比對，攻擊者可繞過白名單豁免

- **相關位置**：
  - GUI：[`src/main.rs:3936-3949`](file:///Users/tenyi/Projects/AntiPhishing/AntiPhishingGUI/src/main.rs#L3936-L3949)（`is_trusted_sender`）、[`src/main.rs:4065-4072`](file:///Users/tenyi/Projects/AntiPhishing/AntiPhishingGUI/src/main.rs#L4065-L4072)（`phishing_score` 扣分）
  - CLI：[`src/main.rs:1679-1692`](file:///Users/tenyi/Projects/AntiPhishing/AntiPhishing/src/main.rs#L1679-L1692)（`is_trusted_sender`）、[`src/main.rs:1820-1827`](file:///Users/tenyi/Projects/AntiPhishing/AntiPhishing/src/main.rs#L1820-L1827)（`phishing_score` 扣分）
- **問題分析**：
  - 當前 `is_trusted_sender` 實作如下：
    ```rust
    let from_lower = from.to_lowercase();
    for d in trusted_domains {
        ...
        if from_lower.contains(&d_lower) {
            return Some(trimmed.to_string());
        }
    }
    ```
  - **漏洞威脅 1（相似網域）**：若設定信任清單為 `hinet.net`，攻擊者自行註冊 `evil-hinet.net`，該網域子字串內含 `hinet.net`。只要攻擊者配置好該網域的 SPF/DMARC 通過驗證，該信件將直接命中 `is_trusted_sender`，並在後續流程中觸發「白名單直接安全豁免」，**完全跳過 LLM 判定與搬移**。
  - **漏洞威脅 2（顯示名稱偽造，更嚴重）**：`from_lower` 是整行 `From` 標頭字串（包含 Display Name）。攻擊者即使從完全不相關的網域發信，只要將顯示名稱偽造為 `"hinet.net" <attacker@phishing-server.com>`，`from_lower.contains("hinet.net")` 同樣成立，白名單防線全面失守。
- **正確修正方案**：
  先解析並抽取 `From` 標頭中真正的電子郵件位址網域，再進行**嚴格全等匹配**或**子網域後綴匹配（以 `.{domain}` 結尾）**：
  ```rust
  /// 檢查寄件者是否命中信任清單（不區分大小寫）
  /// 
  /// 規則：只比對實際郵件地址的網域，必須與信任網域完全相同，或是其合法的子網域（以 . 結尾），
  /// 避免 evil-hinet.net 或顯示名稱內含關鍵字造成繞過。
  fn is_trusted_sender(from: &str, trusted_domains: &[String]) -> Option<String> {
      let from_lower = from.to_lowercase();
      // 從 From 字串中提取寄件網域（例如：從 "Name <user@domain.com>" 取出 "domain.com"）
      let email_domain = RE_EMAIL_DOMAIN
          .captures(&from_lower)
          .map(|c| c[1].to_string())?;

      for d in trusted_domains {
          let trimmed = d.trim().trim_start_matches('@').to_lowercase();
          if trimmed.is_empty() {
              continue;
          }
          // 嚴格比對：必須為完全相同之網域，或是該網域的子網域（如 soc.hinet.net 比對 hinet.net）
          if email_domain == trimmed || email_domain.ends_with(&format!(".{trimmed}")) {
              return Some(trimmed);
          }
      }
      None
  }
  ```
  *(注：`phishing_score` 內的信任清單扣分邏輯亦須同步套用相同的嚴格網域比對)*

---

### 🔴 H-2：設定檔與狀態檔寫入非原子操作，異常終止有檔案截斷損毀風險

- **相關位置**：
  - GUI：[`src/main.rs:276-279`](file:///Users/tenyi/Projects/AntiPhishing/AntiPhishingGUI/src/main.rs#L276-L279)（`save_scan_state`）、[`src/main.rs:671-676`](file:///Users/tenyi/Projects/AntiPhishing/AntiPhishingGUI/src/main.rs#L671-L676)（`App::save`）
- **問題分析**：
  - 當前使用 `fs::write(path, text)`，其標準行為是開啟檔案、截斷長度至 0，接著分段寫入新資料。
  - 若在截斷後、尚未寫入完成前發生突發斷電、作業系統強制終止（SIGKILL / 工作管理員結束工作）或系統崩潰，檔案將呈現 0 位元組或不完整狀態。
  - `config.toml` 損毀會導致使用者的 IMAP 連線帳密與 API Key 永久遺失；`scan_state.toml` 損毀會導致進度重設並引發大範圍重複掃描。
- **跨平台注意事項與正確修正方案**：
  - **重要陷阱**：在 Windows 作業系統中，若目標檔案已存在，直接呼叫標準函式庫的 `std::fs::rename(tmp, target)` 會因目標檔已被佔用或存在而回傳錯誤（與 POSIX 系統保證覆寫的原子語意不同）。
  - **建議安全寫入流程**：
    寫入同一目錄下的暫存檔（確保在同一檔案系統內避免跨磁區移動失敗），接著以跨平台安全的方式取代舊檔（若在 Windows 可先移除舊檔或使用支援覆寫的置換邏輯）：
    ```rust
    /// 安全寫入檔案：先寫入同目錄暫存檔，完成後再替換目標檔，避免中途斷電造成檔案截斷
    fn safe_write_file(path: &Path, content: &str) -> Result<()> {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let tmp_path = parent.join(format!(".{}.tmp", path.file_name().unwrap().to_string_lossy()));
        
        // 1. 完整寫入暫存檔
        fs::write(&tmp_path, content)?;
        
        // 2. 替換目標檔（Windows 需確保覆寫安全）
        #[cfg(windows)]
        {
            if path.exists() {
                let _ = fs::remove_file(path);
            }
            if let Err(e) = fs::rename(&tmp_path, path) {
                let _ = fs::remove_file(&tmp_path);
                return Err(e.into());
            }
        }
        #[cfg(not(windows))]
        {
            if let Err(e) = fs::rename(&tmp_path, path) {
                let _ = fs::remove_file(&tmp_path);
                return Err(e.into());
            }
        }
        Ok(())
    }
    ```

---

### 🔴 H-3：郵件安全驗證警告（warnings）未與權威 MTA 結果保持一致

- **相關位置**：
  - GUI：[`src/main.rs:3882-3896`](file:///Users/tenyi/Projects/AntiPhishing/AntiPhishingGUI/src/main.rs#L3882-L3896)（`check_auth_status`）
  - CLI：[`src/main.rs:1625-1639`](file:///Users/tenyi/Projects/AntiPhishing/AntiPhishing/src/main.rs#L1625-L1639)（`check_auth_status`）
- **問題分析**：
  - 依照 RFC 5322，郵件在轉遞過程中，每個 MTA 節點會將其新生成的標頭（如 `Received`、`Authentication-Results`）**Prepend（加在郵件最上方）**。因此，由收件端自身 MTA 所產生的最權威驗證標頭永遠位於**最上方（第一個）**。
  - 當前程式在解析狀態值時（`status.dmarc` / `status.dkim` / `status.spf`），有正確利用 `is_none()` 鎖定第一個出現的結果。
  - **但是下方產生警示的邏輯卻沒有與權威判定保持一致**：
    ```rust
    // 偽造警告判斷
    if (lower.contains("dmarc=fail") || lower.contains("dmarc=reject"))
        && !status.warnings.iter().any(|w: &String| w.contains("DMARC"))
    {
        status.warnings.push("DMARC 驗證失敗（寄件者網域遭偽造）".into());
    }
    ```
  - **衝突場景**：若第一個 Header（最權威 MTA）判定 `dmarc=pass`，`status.dmarc` 正確被設為 `Some("pass")`。但若後續的轉寄標頭、內部 Hop 或信件下層殘留有 `dmarc=fail`，迴圈巡訪到該標頭時，`status.warnings` 仍會被硬生生塞入 `"DMARC 驗證失敗"`！
  - 這會導致 `status.dmarc` 為 `"pass"`，但 `status.warnings` 卻存在失敗警告的矛盾現象，直接導致白名單豁免機制（要求 `auth_warnings.is_empty()`）無辜被破壞。
- **正確修正方案**：
  `warnings` 應直接由最終鎖定的權威狀態（`status.dmarc`、`status.spf`）決定，而非在迴圈中見到 fail 就無差別記錄：
  ```rust
  // 於所有標頭解析完成後，依據最終權威狀態產生相應警告
  if let Some(ref dmarc) = status.dmarc {
      if dmarc == "fail" || dmarc == "reject" {
          status.warnings.push("DMARC 驗證失敗（寄件者網域遭偽造）".into());
      }
  }
  if let Some(ref spf) = status.spf {
      if spf == "fail" {
          status.warnings.push("SPF 驗證失敗（發信伺服器未獲授權）".into());
      }
  }
  ```

---

## 2. 中嚴重性問題（建議於近期版本優化）

### 🟠 M-1：品牌偽裝偵測使用子字串比對，短品牌名可能誤判英文單字

- **相關位置**：
  - GUI：[`src/main.rs:4023-4038`](file:///Users/tenyi/Projects/AntiPhishing/AntiPhishingGUI/src/main.rs#L4023-L4038)（`phishing_score`）
  - CLI：[`src/main.rs:1776-1793`](file:///Users/tenyi/Projects/AntiPhishing/AntiPhishing/src/main.rs#L1776-L1793)（`phishing_score`）
- **問題分析**：
  - 品牌名稱常數包含短字元名稱，如 `"ups"`。
  - 當前比對為 `display_name.contains(brand)`。若合法郵件的寄件者顯示名稱為 `Google Groups <noreply@google.com>` 或 `Data Backups <admin@company.com>`，`display_name` 內含 `"ups"`（來自 `groups` 或 `backups`），且發信網域並非 UPS 官方網域，就會觸發「品牌偽裝：顯示名稱含 ups 但網域非 ups.com」的誤判加分。
- **正確修正方案**：
  對英文字元品牌加上詞邊界（Word Boundary）檢查，確保品牌名獨立出現：
  ```rust
  let is_brand_match = if brand.chars().all(|c| c.is_ascii_alphanumeric()) {
      // 英文品牌：確保前後不銜接其他字母，避免 groups、backups 誤中 ups
      let re_pattern = format!(r"(?i)\b{}\b", regex::escape(brand));
      regex::Regex::new(&re_pattern).map(|re| re.is_match(display_name)).unwrap_or(false)
  } else {
      // 中文品牌（如：蝦皮）：直接以子字串匹配
      display_name.contains(brand)
  };
  ```

---

### 🟠 M-2：待確認隔離佇列（`pending_queue`）缺乏防禦性容量上限

- **相關位置**：
  - GUI：[`src/main.rs:941-949`](file:///Users/tenyi/Projects/AntiPhishing/AntiPhishingGUI/src/main.rs#L941-L949)（`App::poll`）
- **問題分析**：
  - 目前程式對 `pending_queue` 具備 UID 去重機制，同封信不會重複入列。
  - 然而若使用者始終選擇「稍後處理」且信箱持續收到大量被判定為釣魚/廣告的郵件，跨重啟保留的佇列規模可能會隨時間不斷增大。
- **改善建議**：
  為 `pending_queue` 設定防禦性上限（例如最多保留 500 筆），達到上限時自動捨棄最舊紀錄，保障記憶體與 UI 渲染流暢度。

---

### 🟠 M-3：儲存設定檔時未於 Unix/macOS 設定檔案存取權限（0600）

- **相關位置**：
  - GUI：[`src/main.rs:671-676`](file:///Users/tenyi/Projects/AntiPhishing/AntiPhishingGUI/src/main.rs#L671-L676)（`App::save`）
- **問題分析**：
  - `config.toml` 內部含有 IMAP 密碼與 LLM 金鑰。
  - 在 Unix / Linux 系統上，由 `fs::write` 建立的檔案通常受 umask 影響而呈現 `0644` 權限（同主機其他本機帳號可讀）。
  - 在 macOS 2.1.0 版中，路徑已導向 `~/Library/Application Support/AntiPhishing/`（目錄預設為 0700），具備部分防護，但直接對檔案標註明確權限更為完善。
- **改善建議**：
  在非 Windows 系統儲存設定檔後，調用 `std::os::unix::fs::PermissionsExt` 將 `config.toml` 設定為 `0600`。

---

## 3. 低嚴重性問題與程式碼清理（可選改善）

### 🟡 L-1：清理死代碼（無人呼叫之包裝函式）

- **相關位置**：
  - GUI：[`src/main.rs:4107-4110`](file:///Users/tenyi/Projects/AntiPhishing/AntiPhishingGUI/src/main.rs#L4107-L4110)（`is_docx_part`）、[`src/main.rs:4162-4165`](file:///Users/tenyi/Projects/AntiPhishing/AntiPhishingGUI/src/main.rs#L4162-L4165)（`external_word_image_targets_from_docx`）
  - CLI：[`src/main.rs:1850-1853`](file:///Users/tenyi/Projects/AntiPhishing/AntiPhishing/src/main.rs#L1850-L1853)、[`src/main.rs:1905-1908`](file:///Users/tenyi/Projects/AntiPhishing/AntiPhishing/src/main.rs#L1905-L1908)
- **說明**：
  上述兩個函式純粹包裝底層函式（`is_word_part`、`external_word_image_targets_from_word`），已被標註為 `#[allow(dead_code)]` 且全專案無任何實體呼叫，建議直接清理以維持程式碼整潔。

---

### 🟡 L-2：單元測試暫存目錄命名強化

- **相關位置**：
  - GUI：[`src/main.rs:4958-4966`](file:///Users/tenyi/Projects/AntiPhishing/AntiPhishingGUI/src/main.rs#L4958-L4966)（`temp_test_dir`）
- **說明**：
  目前測試暫存目錄使用 `nanos` 與標籤作為名稱。在特定時鐘解析度較低的環境（如部分 Windows 虛擬機）且進行高併行測試時，建議額外串接當前行程 ID（`std::process::id()`），進一步消除潛在目錄衝突。

---

## 4. 針對外部常見錯誤建議之澄清與辨析

此處特別針對外部工具或一般審查常提出的**不切實際或具破壞性建議**進行澄清，避免日後誤踩陷阱：

1. ❌ **拆分單一檔案為十餘個模組**：
   * **不可採納**。本專案明確秉持 KISS 原則，將邏輯集中於單一檔案，核心優勢在於：能夠直觀地將核心偵測演算法在 CLI 與 GUI 兩大子專案之間比對、同步與驗證。過早拆分為大量模組只會平白增加抽象層次與同步維護成本。
2. ❌ **IMAP 搜尋擴大為 `[date-1, date, date+1]`**：
   * **無必要**。現有實作的 `startup_scan_dates` 與 `scan_dates_since_last` 已經強制涵蓋「前一日 + 今日」，足以完全吸收 UTC 與台灣時區（UTC+8）凌晨跨日的伺服器時間落差。搜尋未來的 `date+1` 只會浪費網路連線時間。
3. ❌ **無 Authentication-Results 標頭時直接取消白名單信任豁免**：
   * **不可採納**。實務上大量企業內網 Mail Server 或特定合法轉發服務並不具備或未配置 `Authentication-Results`。若無此標頭就一律拒絕豁免，使用者手動信任的合法來源將失去白名單保護，引發嚴重誤報（False Positive）。

---

## 5. 建議修正實施清單（依序執行）

- [ ] **第一階段（安全性修復）**：
  1. 修正 `is_trusted_sender` 與 `phishing_score` 扣分邏輯（改為嚴格網域後綴比對）。
  2. 修正 `check_auth_status`（確保 `warnings` 僅依據最外層權威 MTA 結果產生）。
  3. **同步套用上述修正至 `AntiPhishing/`（CLI）與 `AntiPhishingGUI/`（GUI）**。
- [ ] **第二階段（穩定性加固）**：
  4. 實作 `safe_write_file`，為 GUI 的 `config.toml` 與 `scan_state.toml` 加上跨平台安全原子寫入。
  5. 強化 `phishing_score` 中 `BRAND_OFFICIAL_DOMAINS` 的英文詞邊界匹配。
- [ ] **第三階段（清理與發布驗證）**：
  6. 移除無用 dead code 封裝。
  7. 升級兩子專案 `Cargo.toml` 版號（如修復 Patch 升至下一小版）。
  8. 分別於兩目錄執行 `cargo check`、`cargo fmt --check` 與 `cargo test` 確保全部通過。
