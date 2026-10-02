#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import threading
import time
import requests
import base64
import urllib.parse
import socket
from typing import List

# ===================== تنظیمات =====================
TEXT_PATH = "normal20.txt"
FIN_PATH = "final20.txt"

# ===================== تنظیمات اضافی =====================
MAX_THREADS = 10       # حداکثر تعداد تردها برای پردازش
PING_TIMEOUT = 2.0     # تایم اوت پینگ به ثانیه
PING_MAX_MS = 1800     # بالاتر از این مقدار تایم اوت محسوب می‌شود

LINK_PATH = [
    "https://raw.githubusercontent.com/tepo98/kv98/main/final.txt",
    "https://raw.githubusercontent.com/tepo18/online-sshmax98/main/final2.txt",
    "https://raw.githubusercontent.com/tepo18/tepo90/main/final2.txt",
    "https://raw.githubusercontent.com/tepo98/kv98/refs/heads/main/shah.html",
    "https://raw.githubusercontent.com/tepo80/sab-vip90/main/almasi.txt",
    "https://raw.githubusercontent.com/tepo98/kv98/main/final.txt",
    "https://raw.githubusercontent.com/tepo18/online-sshmax98/main/final.txt",
    "https://raw.githubusercontent.com/tepo18/tepo90/main/final2.txt",
    "https://raw.githubusercontent.com/tepo80/sab-vip90/main/vip.txt",
    "https://raw.githubusercontent.com/tepo18/sab-vip10/main/final.txt"
]

FILE_HEADER_TEXT = "//profile-title: base64:2YfZhduM2LTZhyDZgdi52KfZhCDwn5iO8J+YjvCfmI4gaGFtZWRwNzE="

# ===================== توابع =====================

def fetch_link(url: str) -> List[str]:
    try:
        r = requests.get(url, timeout=15)
        if r.status_code == 200:
            lines = r.text.splitlines()
            return [l.strip() for l in lines if l.strip()]
    except Exception as e:
        print(f"[⚠️] Cannot fetch {url}: {e}")
    return []

def is_valid_config(line: str) -> bool:
    line = line.strip()
    if not line or len(line) < 5:
        return False
    lower = line.lower()
    if "pin=0" in lower or "pin=red" in lower or "pin=قرمز" in lower:
        return False
    return True

def parse_config_line(line: str):
    try:
        line = urllib.parse.unquote(line.strip())
        for p in ["vmess", "vless", "trojan", "hy2", "hysteria2", "ss", "socks", "wireguard"]:
            if line.startswith(p + "://"):
                return line
    except:
        pass
    return None

def tcp_test(host: str, port: int, timeout=PING_TIMEOUT) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except:
        return False

def process_configs(lines: List[str], precise_test=False) -> List[str]:
    valid_configs = []
    lock = threading.Lock()

    def worker(line):
        cfg = parse_config_line(line)
        passed = False

        if cfg:
            try:
                import re
                m = re.search(r"@([^:]+):(\d+)", cfg)
                host, port = (m.group(1), int(m.group(2))) if m else ("", 443)

                if precise_test and host:
                    passed = tcp_test(host, port)
                else:
                    passed = True
            except:
                passed = False

        if passed and is_valid_config(line):
            with lock:
                valid_configs.append(line)

    threads = []
    for i, line in enumerate(lines):
        t = threading.Thread(target=worker, args=(line,))
        threads.append(t)
        t.start()
        # محدود کردن تعداد تردها به MAX_THREADS
        while threading.active_count() > MAX_THREADS:
            time.sleep(0.05)

    for t in threads:
        t.join()

    final_list = list(dict.fromkeys(valid_configs))
    return final_list

def save_outputs(lines: List[str]):
    try:
        with open(TEXT_PATH, "w", encoding="utf-8") as f:
            f.write("")
        with open(FIN_PATH, "w", encoding="utf-8") as f:
            f.write("")

        normal_lines = lines
        with open(TEXT_PATH, "w", encoding="utf-8") as f:
            f.write("\n".join([FILE_HEADER_TEXT] + normal_lines))
        print(f"[ℹ️] Stage 1: {len(normal_lines)} configs saved to {TEXT_PATH}")

        final_lines = process_configs(normal_lines, precise_test=True)
        with open(FIN_PATH, "w", encoding="utf-8") as f:
            f.write("\n".join(final_lines))
        print(f"[ℹ️] Stage 2: {len(final_lines)} configs saved to {FIN_PATH}")

        print(f"[✅] Update complete. Total sources: {len(lines)}")
        print(f"  -> Normal configs: {len(normal_lines)}")
        print(f"  -> Final configs: {len(final_lines)}")

    except Exception as e:
        print(f"[❌] Error saving files: {e}")

def update_subs():
    all_lines = []

    for url in LINK_PATH:
        fetched = fetch_link(url)
        if not fetched:
            print(f"[⚠️] Cannot fetch or empty source: {url}")
        else:
            all_lines.extend(fetched)

    print(f"[*] Total lines fetched from sources: {len(all_lines)}")
    all_lines = process_configs(all_lines)
    save_outputs(all_lines)

# ===================== اجرای دستی =====================
if __name__ == "__main__":
    print("[*] Starting manual subscription update...")
    update_subs()
    print("[*] Done. Run this script manually whenever needed.")
