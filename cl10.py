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
TEXT_PATH = "normal10.txt"
FIN_PATH = "final10.txt"

# ===================== تنظیمات اضافی =====================
MAX_THREADS = 50
PING_TIMEOUT = 2.8
PING_MAX_MS = 5000

# ===================== سورس‌های جدید =====================
# سورس‌های قبلی کامل حذف شده‌اند
LINK_PATH = [
    "https://wlzmgdefumms.ahsan-tepo1390.workers.dev/feed/ZEUS-W72H7NZ3",
    "https://raw.githubusercontent.com/patterniha/Free-Configs/refs/heads/main/configs_base64.txt",
    "https://old-limit-e122-edge-333.ahsan-tepo1383online.workers.dev/sub?token=8bfaf9cc1c81e4005289b8d8c738077c",
    "https://troll_hastam_nat1m.shah-tepo98.workers.dev/sync?sub=tepo90&flag=raw",
    "https://878bmx86p0vqtwdgrv5b9.ahsan-tepo1383online.workers.dev/oD21lBZY1DtV/sub/raw?app=xray#%F0%9F%92%A6%20BPB%20Raw"
]

FILE_HEADER_TEXT = "//profile-title: base64:2YfZhduM2LTZhyDZgdi52KfZhCDwn5iO8J+YjvCfmI4gaGFtZWRwNzE="

# ===================== توابع =====================

def fetch_link(url: str) -> List[str]:
    try:
        r = requests.get(
            url,
            timeout=15,
            headers={
                "User-Agent": "Mozilla/5.0"
            }
        )

        if r.status_code == 200:
            lines = r.text.splitlines()
            return [l.strip() for l in lines if l.strip()]

        print(f"[⚠️] HTTP {r.status_code}: {url}")

    except Exception as e:
        print(f"[⚠️] Cannot fetch {url}: {e}")

    return []


def is_valid_config(line: str) -> bool:
    line = line.strip()

    if not line or len(line) < 5:
        return False

    lower = line.lower()

    if "pin=0" in lower:
        return False

    if "pin=red" in lower:
        return False

    if "pin=قرمز" in lower:
        return False

    return True


def parse_config_line(line: str):
    try:
        line = urllib.parse.unquote(line.strip())

        for p in [
            "vmess",
            "vless",
            "trojan",
            "hy2",
            "hysteria2",
            "ss",
            "socks",
            "wireguard"
        ]:
            if line.startswith(p + "://"):
                return line

    except Exception:
        pass

    return None


def tcp_test(host: str, port: int, timeout=PING_TIMEOUT) -> bool:
    try:
        with socket.create_connection(
            (host, port),
            timeout=timeout
        ):
            return True

    except Exception:
        return False


def process_configs(
    lines: List[str],
    precise_test=False
) -> List[str]:

    valid_configs = []
    lock = threading.Lock()

    def worker(line):

        cfg = parse_config_line(line)
        passed = False

        if cfg:
            try:
                import re

                m = re.search(
                    r"@([^:]+):(\d+)",
                    cfg
                )

                host, port = (
                    (m.group(1), int(m.group(2)))
                    if m
                    else ("", 443)
                )

                if precise_test and host:
                    passed = tcp_test(
                        host,
                        port
                    )
                else:
                    passed = True

            except Exception:
                passed = False

        if passed and is_valid_config(line):

            with lock:
                valid_configs.append(line)

    threads = []

    for line in lines:

        t = threading.Thread(
            target=worker,
            args=(line,)
        )

        threads.append(t)
        t.start()

        while threading.active_count() > MAX_THREADS:
            time.sleep(0.05)

    for t in threads:
        t.join()

    # حذف کانفیگ‌های تکراری، حفظ ترتیب
    final_list = list(
        dict.fromkeys(valid_configs)
    )

    return final_list


def save_outputs(lines: List[str]):

    try:

        # پاک‌سازی فایل‌های قبلی
        with open(TEXT_PATH, "w", encoding="utf-8") as f:
            f.write("")

        with open(FIN_PATH, "w", encoding="utf-8") as f:
            f.write("")

        # ===================== Stage 1 =====================

        normal_lines = lines

        with open(
            TEXT_PATH,
            "w",
            encoding="utf-8"
        ) as f:

            f.write(
                "\n".join(
                    [FILE_HEADER_TEXT] + normal_lines
                )
            )

        print(
            f"[ℹ️] Stage 1: "
            f"{len(normal_lines)} configs saved to "
            f"{TEXT_PATH}"
        )

        # ===================== Stage 2 =====================

        final_lines = process_configs(
            normal_lines,
            precise_test=True
        )

        with open(
            FIN_PATH,
            "w",
            encoding="utf-8"
        ) as f:

            f.write(
                "\n".join(final_lines)
            )

        print(
            f"[ℹ️] Stage 2: "
            f"{len(final_lines)} configs saved to "
            f"{FIN_PATH}"
        )

        print(
            f"[✅] Update complete. "
            f"Total sources: {len(LINK_PATH)}"
        )

        print(
            f"  -> Downloaded lines: {len(lines)}"
        )

        print(
            f"  -> Normal configs: {len(normal_lines)}"
        )

        print(
            f"  -> Final configs: {len(final_lines)}"
        )

    except Exception as e:

        print(
            f"[❌] Error saving files: {e}"
        )


def update_subs():

    all_lines = []

    print(
        f"[*] Fetching {len(LINK_PATH)} subscription sources..."
    )

    for index, url in enumerate(
        LINK_PATH,
        start=1
    ):

        print(
            f"\n[{index}/{len(LINK_PATH)}] "
            f"Fetching source..."
        )

        fetched = fetch_link(url)

        if not fetched:

            print(
                f"[⚠️] Cannot fetch or empty source:"
            )

            print(url)

        else:

            print(
                f"[✓] Received {len(fetched)} lines"
            )

            all_lines.extend(fetched)

    print(
        f"\n[*] Total lines fetched from sources: "
        f"{len(all_lines)}"
    )

    # حذف تکراری‌ها قبل از پردازش
    all_lines = list(
        dict.fromkeys(all_lines)
    )

    print(
        f"[*] Unique lines: {len(all_lines)}"
    )

    # پردازش اولیه
    all_lines = process_configs(
        all_lines
    )

    print(
        f"[*] Valid configs after Stage 1: "
        f"{len(all_lines)}"
    )

    save_outputs(all_lines)


# ===================== اجرای دستی =====================

if __name__ == "__main__":

    print(
        "[*] Starting manual subscription update..."
    )

    update_subs()

    print(
        "[*] Done. Run this script manually whenever needed."
)
