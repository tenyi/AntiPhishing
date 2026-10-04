use std::{
    io::Read,
    net::{TcpStream, ToSocketAddrs},
    time::Duration,
};

use anyhow::{Context, Result, bail};
use imap::Session;

use crate::*;

/// IMAP TCP 連線逾時
pub const IMAP_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// IMAP 讀寫逾時（避免伺服器停滯時 worker 永久卡死）
pub const IMAP_IO_TIMEOUT: Duration = Duration::from_secs(60);

/// 建立 IMAP 連線：手動 TCP+TLS 以確保連線與讀寫皆有逾時，
/// 避免伺服器停滯時 worker 永久卡死、排程掃描全面癱瘓。
pub fn connect(config: &ImapConfig) -> Result<Session<imap::Connection>> {
    let host = config.host.trim();
    if host.is_empty() {
        bail!("IMAP 伺服器位址為空");
    }
    let tcp = tcp_stream_with_timeout(host, config.port)?;
    match config.protocol.as_str() {
        "imaps" => {
            let connector = native_tls::TlsConnector::new().context("無法建立 TLS 連接器")?;
            let tls = connector.connect(host, tcp).context("IMAP TLS 交握失敗")?;
            let mut client = imap::Client::<imap::Connection>::new(Box::new(tls));
            client.read_greeting().context("讀取 IMAP 問候訊息失敗")?;
            finish_login(client, config)
        }
        "starttls" => {
            // imap crate 未公開「升級前送出任意指令」的 API，
            // 故 STARTTLS 前置交談（問候＋STARTTLS 指令）在此手工完成。
            let mut plain = tcp;
            let greeting = read_imap_line(&mut plain)?;
            if !greeting.starts_with("* ") {
                bail!("非預期的 IMAP 問候訊息：{greeting}");
            }
            const TAG: &str = "AP1";
            use std::io::Write as _;
            write!(plain, "{TAG} STARTTLS\r\n").context("送出 STARTTLS 指令失敗")?;
            plain.flush().context("送出 STARTTLS 指令失敗")?;
            let done_line = loop {
                let line = read_imap_line(&mut plain)?;
                if line.starts_with(TAG) {
                    break line;
                }
                // 忽略未標記回應（如 * CAPABILITY）
            };
            if !done_line
                .split_whitespace()
                .nth(1)
                .is_some_and(|status| status.eq_ignore_ascii_case("OK"))
            {
                // 伺服器拒絕即中止，絕不退回明文登入，避免降級攻擊
                bail!("STARTTLS 升級被伺服器拒絕：{}", done_line.trim());
            }
            let connector = native_tls::TlsConnector::new().context("無法建立 TLS 連接器")?;
            let tls = connector
                .connect(host, plain)
                .context("IMAP TLS 交握失敗")?;
            let mut client = imap::Client::<imap::Connection>::new(Box::new(tls));
            // 問候訊息已在升級前讀取
            client.greeting_read = true;
            finish_login(client, config)
        }
        other => bail!("不支援的 protocol：{other}"),
    }
}

/// 以 connect_timeout 逐一嘗試所有解析出的位址，並設定讀寫逾時。
pub fn tcp_stream_with_timeout(host: &str, port: u16) -> Result<TcpStream> {
    let addrs = (host, port)
        .to_socket_addrs()
        .with_context(|| format!("無法解析 IMAP 伺服器位址：{host}"))?;
    let mut last_error = None;
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, IMAP_CONNECT_TIMEOUT) {
            Ok(stream) => {
                stream
                    .set_read_timeout(Some(IMAP_IO_TIMEOUT))
                    .context("設定讀取逾時失敗")?;
                stream
                    .set_write_timeout(Some(IMAP_IO_TIMEOUT))
                    .context("設定寫入逾時失敗")?;
                return Ok(stream);
            }
            Err(error) => last_error = Some(error),
        }
    }
    bail!(last_error.map_or_else(
        || format!("IMAP TCP 連線失敗：{host}:{port}（沒有可嘗試的位址）"),
        |error| format!("IMAP TCP 連線失敗：{host}:{port}（{error}）")
    ))
}

/// 逐位元組讀取一行 IMAP 回應（不含行尾 CRLF）；
/// 逐位元組是為了避免緩衝區超讚吃掉 TLS 交握後的第一批資料。
pub fn read_imap_line(stream: &mut TcpStream) -> Result<String> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let read = stream.read(&mut byte).context("IMAP 連線讀取失敗")?;
        if read == 0 {
            bail!("IMAP 連線意外中斷");
        }
        if byte[0] == b'\n' {
            break;
        }
        line.push(byte[0]);
        if line.len() > 8192 {
            bail!("IMAP 回應行過長");
        }
    }
    let mut text = String::from_utf8_lossy(&line).into_owned();
    if text.ends_with('\r') {
        text.pop();
    }
    Ok(text)
}

pub fn finish_login(
    client: imap::Client<imap::Connection>,
    config: &ImapConfig,
) -> Result<Session<imap::Connection>> {
    client
        .login(&config.username, &config.password)
        .map_err(|(error, _)| error)
        .context("IMAP 登入失敗")
}

/// 判斷郵件旗標清單中是否為未讀（不含 \Seen 旗標）。
pub fn is_message_unread(flags: &[imap::types::Flag]) -> bool {
    !flags.iter().any(|f| matches!(f, imap::types::Flag::Seen))
}

/// 若郵件在掃描前為未讀，於處理後還原未讀狀態（移除 \Seen 旗標）。
pub fn restore_unread_status(session: &mut Session<imap::Connection>, uid: u32) -> Result<()> {
    session
        .uid_store(uid.to_string(), "-FLAGS.SILENT (\\Seen)")
        .with_context(|| format!("還原郵件 UID {uid} 未讀狀態失敗"))?;
    Ok(())
}

pub fn move_message(session: &mut Session<imap::Connection>, uid: u32, target: &str) -> Result<()> {
    session
        .uid_copy(uid.to_string(), target)
        .with_context(|| format!("無法複製郵件到：{target}"))?;
    session.uid_store(uid.to_string(), "+FLAGS.SILENT (\\Deleted)")?;
    Ok(())
}

/// 確認目標信箱存在，不存在則嘗試建立。
pub fn ensure_phishing_mailbox(session: &mut Session<imap::Connection>, name: &str) -> Result<()> {
    let exists = session
        .list(Some(""), Some(name))
        .with_context(|| format!("無法查詢信箱是否存在：{name}"))?
        .iter()
        .any(|mailbox| mailbox.name() == name);
    if !exists {
        session
            .create(name)
            .with_context(|| format!("無法建立信箱：{name}"))?;
    }
    Ok(())
}

/// 從 IMAP 伺服器取得所有 mailbox 清單（原始名稱）。
pub fn fetch_mailbox_list(config: &ImapConfig) -> Result<Vec<String>> {
    let mut session = connect(config)?;
    let names = session
        .list(Some(""), Some("*"))
        .context("無法取得信箱清單")?;
    let mut list: Vec<String> = names.iter().map(|n| n.name().to_string()).collect();
    session.logout().ok();
    list.sort();
    list.dedup();
    Ok(list)
}

/// 將 IMAP Modified Base64 解碼為 bytes。
/// IMAP Modified Base64 使用 ',' 取代 '/'，且不含 '=' padding。
pub fn imap_modified_base64_decode(input: &str) -> Option<Vec<u8>> {
    let mut table = [255u8; 256];
    for (i, &b) in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+"
        .iter()
        .enumerate()
    {
        table[b as usize] = i as u8;
    }
    table[b',' as usize] = 63;
    table[b'/' as usize] = 63;

    let clean: Vec<u8> = input
        .bytes()
        .filter(|&b| b != b'=' && !b.is_ascii_whitespace())
        .collect();
    let mut out = Vec::with_capacity(clean.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0;

    for &b in &clean {
        let val = table[b as usize];
        if val == 255 {
            return None;
        }
        buf = (buf << 6) | (val as u32);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// 將 UTF-16BE bytes 轉換為 UTF-8 String。
pub fn utf16be_bytes_to_string(bytes: &[u8]) -> String {
    let mut u16_vec = Vec::with_capacity(bytes.len() / 2);
    for chunk in bytes.chunks_exact(2) {
        u16_vec.push(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    String::from_utf16_lossy(&u16_vec)
}

/// 將 IMAP modified UTF-7 字串解碼為 UTF-8 Unicode 字串（例如將 Mail2000 的 &...- 解回中文）。
pub fn decode_imap_utf7(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut rest = s;

    while let Some(start_idx) = rest.find('&') {
        result.push_str(&rest[..start_idx]);
        let after_amp = &rest[start_idx + 1..];
        if let Some(end_idx) = after_amp.find('-') {
            let inner = &after_amp[..end_idx];
            if inner.is_empty() {
                // "&-" 表示字元 '&'
                result.push('&');
            } else if let Some(bytes) = imap_modified_base64_decode(inner) {
                result.push_str(&utf16be_bytes_to_string(&bytes));
            } else {
                // 解碼失敗時保留原始字串
                result.push('&');
                result.push_str(inner);
                result.push('-');
            }
            rest = &after_amp[end_idx + 1..];
        } else {
            // 沒有找到結尾 '-'，保留剩餘字串
            result.push('&');
            result.push_str(after_amp);
            rest = "";
            break;
        }
    }
    result.push_str(rest);
    result
}
