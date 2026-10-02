#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import requests
import base64
import threading
import urllib.parse
import socket
import glob

# ===================== مسیر فایل‌ها =====================
INPUT_FILE = "input.txt"
OUTPUT_DIR = "base64"  # همه فایل‌های ساب داخل این پوشه
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ===================== توابع =====================

def fetch_url(url):
    """خواندن محتوا از لینک با timeout و کنترل خطا"""
    try:
        r = requests.get(url, timeout=15)
        if r.status_code == 200:
            return r.text.strip()
    except Exception as e:
        print(f"[⚠️] Cannot fetch {url}: {e}")
    return None

def safe_base64_encode(text):
    """تبدیل متن به Base64 استاندارد"""
    try:
        return base64.b64encode(text.encode('utf-8')).decode('utf-8')
    except Exception as e:
        print(f"[⚠️] Base64 encode error: {e}")
        return None

def is_valid_line(line):
    """بررسی خط خراب یا ناقص"""
    line = line.strip()
    if not line or len(line) < 5:
        return False
    lower = line.lower()
    if "pin=0" in lower or "pin=red" in lower or "pin=قرمز" in lower:
        return False
    return True

def parse_line(line):
    """تبدیل لینک یا خط به فرمت استاندارد قبل Base64"""
    try:
        decoded = urllib.parse.unquote(line.strip())
        return decoded
    except:
        return None

def get_file_name_from_sub(sub_url):
    """اسم فایل خروجی هر ساب: آخرین قسمت لینک + .txt"""
    sub_url = sub_url.strip()
    if not sub_url:
        return "unknown.txt"
    last_part = sub_url.split('/')[-1].split('#')[0].split('?')[0]
    if not last_part:
        last_part = "unknown"
    if '.' in last_part:
        name = last_part.rsplit('.', 1)[0]
        return f"{name}.txt"
    else:
        return f"{last_part}.txt"

def process_sub(sub_content, file_name):
    """تبدیل محتوا به Base64 و ذخیره در فایل خودش"""
    results = []
    lines = sub_content.splitlines()
    for line in lines:
        if not is_valid_line(line):
            continue
        parsed = parse_line(line)
        if parsed:
            encoded = safe_base64_encode(parsed)
            if encoded:
                results.append(encoded)
    # حذف تکراری
    results = list(dict.fromkeys(results))
    if results:
        out_path = os.path.join(OUTPUT_DIR, file_name)
        with open(out_path, "w", encoding="utf-8") as f:
            f.write("\n".join(results))
        print(f"[✔] {file_name} saved ({len(results)} lines)")
    return results

def process_sub_wrapper(sub_url):
    """خواندن ساب، تبدیل، ذخیره"""
    content = fetch_url(sub_url)
    if content:
        file_name = get_file_name_from_sub(sub_url)
        return process_sub(content, file_name)
    else:
        print(f"[⏭] Skipped (fetch failed)")
        return []

# ===================== MAIN =====================
def main():
    # خواندن input.txt و شناسایی ساب‌ها
    subs = []
    if os.path.exists(INPUT_FILE):
        with open(INPUT_FILE, "r", encoding="utf-8") as f:
            current_sub = []
            for line in f:
                if line.strip() == "":
                    if current_sub:
                        subs.append("\n".join(current_sub))
                        current_sub = []
                else:
                    current_sub.append(line.strip())
            if current_sub:
                subs.append("\n".join(current_sub))
    else:
        print(f"[⚠️] {INPUT_FILE} not found.")
        return

    print(f"[*] Unique sub blocks found: {len(subs)}")

    # پردازش هر ساب با thread
    all_results = []
    threads = []
    sub_results_dict = {}

    for sub_block in subs:
        t = threading.Thread(target=lambda b=sub_block: sub_results_dict.update({b: process_sub_wrapper(b)}))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    # ==================== ساخت فایل mix.txt ====================
    all_lines = []
    for res in sub_results_dict.values():
        all_lines.extend(res)

    # حذف تکراری‌ها (اختیاری)
    all_lines = list(dict.fromkeys(all_lines))

    mix_file = "mix.txt"
    with open(mix_file, "w", encoding="utf-8") as f:
        f.write("\n".join(all_lines))

    print(f"[🟢] Mix file created: {mix_file} ({len(all_lines)} total lines)")

# ===================== RUN =====================
if __name__ == "__main__":
    main()
