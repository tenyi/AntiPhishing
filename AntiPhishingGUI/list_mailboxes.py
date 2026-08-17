# -*- coding: utf-8 -*-
"""列出 IMAP 伺服器上所有 mailbox 的真實名稱（IMAP LIST）。

用法：python list_mailboxes.py
帳密直接讀同目錄 config.toml（避免手打）。
"""
import imaplib
import re
import sys
from pathlib import Path


def load_imap_cfg(path: Path):
    """從 config.toml 抓 [imap] 段的 host/port/username/password。"""
    cfg = {}
    in_imap = False
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith("["):
            in_imap = line.strip("[]") == "imap"
            continue
        if in_imap and "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            cfg[k.strip()] = v.split("#", 1)[0].strip().strip('"')
    return cfg


def imap_utf7_to_unicode(s: str) -> str:
    """IMAP 名稱用 modified UTF-7；把 &...- 片段解回 unicode（如中文）。"""
    def dec(m):
        inner = m.group(1).replace(",", "/")
        # IMAP modified UTF-7：base 字元以 , 代替 /
        table = {chr(65 + i): chr(32 + i) for i in range(26)}
        table.update({chr(97 + i): chr(64 + i) for i in range(26)})
        table["/"] = "/"
        # 解 base64（含 , 已換回 /）
        import base64
        pad = inner + "=" * (-len(inner) % 4)
        raw = base64.b64decode(pad)
        return raw.decode("utf-16-be")

    return re.sub(r"&([^&]*)-", dec, s)


def main():
    cfg = load_imap_cfg(Path(__file__).parent / "config.toml")
    host, user, pw = cfg["host"], cfg["username"], cfg["password"]
    port = int(cfg.get("port", "993"))
    proto = cfg.get("protocol", "imaps")

    conn = imaplib.IMAP4_SSL(host, port) if proto == "imaps" else imaplib.IMAP4(host, port)
    conn.login(user, pw)
    # LIST "" * 列出全部
    _, data = conn.list()
    for raw in data:
        line = raw.decode("utf-8", "replace")
        # 行格式：(FLAGS (\HasNoChildren)) "/" "名稱"
        m = re.search(r'/ "?(.*?)"?$', line)
        name = m.group(1) if m else line
        print(f"{name:40}  ->  {imap_utf7_to_unicode(name)}")
    conn.logout()


if __name__ == "__main__":
    sys.exit(main())
