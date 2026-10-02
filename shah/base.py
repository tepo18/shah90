#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import requests
import base64
import urllib.parse
import shutil

INPUT_FILE = "input.txt"
OUTPUT_DIR = "base64"
REPORT_FILE = "report.txt"

# -------------------- ابزارها --------------------

def fetch_url(url):
    try:
        r = requests.get(url, timeout=15)
        if r.status_code == 200:
            return r.text.strip()
        else:
            print(f"[⚠️] Bad status for {url} -> {r.status_code}")
    except Exception as e:
        print(f"[⚠️] Cannot fetch {url}: {e}")
    return None

def safe_base64_encode(text):
    try:
        return base64.b64encode(text.encode('utf-8')).decode('utf-8')
    except:
        return None

def is_valid_line(line):
    line = line.strip()
    if not line or len(line) < 5:
        return False
    lower = line.lower()
    if "pin=0" in lower or "pin=red" in lower or "pin=قرمز" in lower:
        return False
    return True

def parse_line(line):
    try:
        return urllib.parse.unquote(line.strip())
    except:
        return None

# -------------------- خواندن ساب‌ها --------------------

def read_sub_blocks():
    if not os.path.exists(INPUT_FILE):
        print("input.txt not found.")
        return []

    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        lines = f.read().splitlines()

    blocks = []
    current_block = []

    for line in lines:
        if line.strip() == "":
            if current_block:
                blocks.append("\n".join(current_block).strip())
                current_block = []
        else:
            current_block.append(line.strip())

    if current_block:
        blocks.append("\n".join(current_block).strip())

    # حذف ساب‌های تکراری
    unique_blocks = list(dict.fromkeys(blocks))

    return unique_blocks

# -------------------- ریست خروجی --------------------

def reset_output():
    if os.path.exists(OUTPUT_DIR):
        shutil.rmtree(OUTPUT_DIR)
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # ریست گزارش
    if os.path.exists(REPORT_FILE):
        os.remove(REPORT_FILE)

# -------------------- برنامه اصلی --------------------

def main():
    reset_output()

    sub_blocks = read_sub_blocks()
    total_subs = len(sub_blocks)
    print(f"[*] Unique sub blocks found: {total_subs}")

    sab_counter = 1
    processed_files = []
    skipped_subs = 0

    for block in sub_blocks:
        content = fetch_url(block)
        if not content:
            print("[⏭] Skipped (fetch failed)")
            skipped_subs += 1
            continue

        results = []
        lines = content.splitlines()

        for line in lines:
            if not is_valid_line(line):
                continue
            parsed = parse_line(line)
            if parsed:
                encoded = safe_base64_encode(parsed)
                if encoded:
                    results.append(encoded)

        if not results:
            print("[⏭] Skipped (no valid lines)")
            skipped_subs += 1
            continue

        output_path = os.path.join(OUTPUT_DIR, f"sab{sab_counter}.txt")
        with open(output_path, "w", encoding="utf-8") as out:
            out.write("\n".join(results))

        print(f"[✔] sab{sab_counter}.txt saved ({len(results)} lines)")
        processed_files.append(f"sab{sab_counter}.txt")
        sab_counter += 1

    # -------------------- نوشتن گزارش --------------------
    with open(REPORT_FILE, "w", encoding="utf-8") as report:
        report.write(f"Total sub blocks: {total_subs}\n")
        report.write(f"Processed subs: {len(processed_files)}\n")
        report.write(f"Skipped/failed subs: {skipped_subs}\n")
        report.write("Files created:\n")
        for f in processed_files:
            report.write(f" - {f}\n")

    print("[✅] Done. Report saved to report.txt")

if __name__ == "__main__":
    main()

