#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import random
import subprocess
import ipaddress
import glob
from datetime import datetime
from pathlib import Path

from colorama import Fore, init

init(autoreset=True)


# ============================================================
# COLORS
# ============================================================

BRICK = Fore.LIGHTYELLOW_EX
CYAN_MENU = Fore.LIGHTCYAN_EX
LILAC = Fore.LIGHTMAGENTA_EX
ORANGE = Fore.LIGHTRED_EX
GREEN = Fore.LIGHTGREEN_EX
WHITE = Fore.WHITE
RESET = Fore.RESET

TITLE_COLOR = Fore.CYAN


# ============================================================
# GENERAL
# ============================================================

VERSION = "2.0 PRO"

OUTPUT_DIR = Path("output")
OUTPUT_DIR.mkdir(exist_ok=True)

BANNER = f"""
{Fore.CYAN}╔════════════════════════════════════════════════════╗
{Fore.CYAN}║ {Fore.GREEN} EXACT CONFIG COPY & IP REPLACER PRO {Fore.CYAN}       ║
{Fore.CYAN}║ {Fore.YELLOW} Version {VERSION}                              ║
{Fore.CYAN}╚════════════════════════════════════════════════════╝
"""


def clear_screen():
    os.system("clear")


def pause():
    input(
        f"\n{Fore.GREEN}Press Enter to return to Main Menu..."
        f"{Fore.RESET}"
    )


def copy_to_clipboard(text):

    try:

        p = subprocess.Popen(
            ["termux-clipboard-set"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        p.communicate(
            text.encode("utf-8")
        )

        return True

    except Exception:

        return False


# ============================================================
# SCRIPT 1 - EXACT CONFIG COPY
# ============================================================

def clean_text(text):

    return text.strip().replace(
        "\r",
        ""
    )


def is_valid_ip(ip):

    try:

        ipaddress.ip_address(ip)

        return True

    except ValueError:

        return False


def extract_ips(text):

    result = []

    items = re.split(
        r"[\s,;\n\r\t]+",
        text
    )

    for item in items:

        item = item.strip()

        if not item:
            continue

        item = re.sub(
            r":\d+$",
            "",
            item
        )

        if is_valid_ip(item):

            if item not in result:
                result.append(item)

    return result


def detect_protocol(config):

    config_lower = config.lower()

    if config_lower.startswith("vless://"):
        return "VLESS"

    if config_lower.startswith("vmess://"):
        return "VMESS"

    if config_lower.startswith("trojan://"):
        return "TROJAN"

    if config_lower.startswith("ss://"):
        return "SHADOWSOCKS"

    if config_lower.startswith("hysteria"):
        return "HYSTERIA"

    return "UNKNOWN"


def extract_host(config):

    config = config.strip()

    if "@" in config:

        try:

            after_at = config.split(
                "@",
                1
            )[1]

            host = re.split(
                r"[:/?#]",
                after_at
            )[0]

            return host

        except Exception:

            pass

    return None


def replace_host(config, old_host, new_ip):

    if not old_host:
        return config

    new_config = config

    new_config = new_config.replace(
        "@" + old_host + ":",
        "@" + new_ip + ":"
    )

    if new_config == config:

        new_config = new_config.replace(
            "@" + old_host,
            "@" + new_ip
        )

    return new_config


def remove_duplicates(items):

    seen = set()
    result = []

    for item in items:

        if item not in seen:

            seen.add(item)
            result.append(item)

    return result


def load_configs_from_text(text):

    configs = []

    for line in text.splitlines():

        line = line.strip()

        if "://" in line:

            configs.append(line)

    return configs


def load_file(path):

    try:

        with open(
            path,
            "r",
            encoding="utf-8",
            errors="ignore"
        ) as f:

            return f.read()

    except Exception:

        return ""


def save_output(filename, content):

    path = OUTPUT_DIR / filename

    with open(
        path,
        "w",
        encoding="utf-8"
    ) as f:

        f.write(content)

    return path


def generate_configs(base_configs, ips):

    output = []

    stats = {}

    for config in base_configs:

        proto = detect_protocol(
            config
        )

        stats[proto] = (
            stats.get(proto, 0) + 1
        )

        old_host = extract_host(
            config
        )

        if not old_host:
            continue

        for ip in ips:

            new_conf = replace_host(
                config,
                old_host,
                ip
            )

            output.append(
                new_conf
            )

    output = remove_duplicates(
        output
    )

    return output, stats


def show_stats(base, ips, result):

    print(
        "\n" + "=" * 45
    )

    print(
        f"{Fore.CYAN}Base Configs : "
        f"{Fore.GREEN}{len(base)}"
    )

    print(
        f"{Fore.CYAN}Clean IPs    : "
        f"{Fore.GREEN}{len(ips)}"
    )

    print(
        f"{Fore.CYAN}Generated    : "
        f"{Fore.GREEN}{len(result)}"
    )

    print(
        "=" * 45
    )


# ============================================================
# SENPAI FILE LOADER
# ============================================================

def load_scanner_file():

    files = []

    for f in os.listdir("."):

        if (
            f.startswith("SenPaiScannerResult")
            or f.startswith("GOOD")
            or f.startswith("BAD")
        ):

            files.append(f)

    if not files:

        print(
            f"{Fore.RED}"
            "No scanner files found."
            f"{Fore.RESET}"
        )

        return ""

    print(
        "\nAvailable Files:"
    )

    for i, f in enumerate(files):

        print(
            f"[{i}] {f}"
        )

    try:

        choice = int(
            input(
                "\nSelect file: "
            )
        )

        if (
            choice < 0
            or choice >= len(files)
        ):

            return ""

        return load_file(
            files[choice]
        )

    except Exception:

        return ""


# ============================================================
# SCRIPT 1 - ADVANCED SENPAI SEARCH
# Hidden from main menu but functionality preserved
# ============================================================

def find_senpai_files():

    paths = [
        ".",
        "/data/data/com.termux/files/home",
        "/data/data/com.termux/files/home/storage/downloads",
        "/data/data/com.termux/files/home/storage/shared"
    ]

    found = []

    for base in paths:

        if not os.path.exists(base):
            continue

        try:

            for root, dirs, files in os.walk(base):

                for file in files:

                    if (
                        "SenPaiScannerResult" in file
                        or file.startswith("GOOD")
                        or file.startswith("BAD")
                    ):

                        found.append(
                            os.path.join(
                                root,
                                file
                            )
                        )

        except Exception:

            pass

    return list(
        set(found)
    )


def sort_ips(ip_list):

    try:

        return sorted(
            ip_list,
            key=lambda x: [
                int(i)
                for i in x.split(".")
            ]
        )

    except Exception:

        return ip_list


def save_ip_list(ips):

    ips = sort_ips(
        ips
    )

    filename = (
        "clean_ips_"
        +
        datetime.now().strftime(
            "%Y%m%d_%H%M%S"
        )
        +
        ".txt"
    )

    path = OUTPUT_DIR / filename

    with open(
        path,
        "w",
        encoding="utf-8"
    ) as f:

        f.write(
            "\n".join(ips)
        )

    return path


def advanced_scanner_menu():

    clear_screen()

    print(BANNER)

    files = find_senpai_files()

    if not files:

        print(
            f"{Fore.RED}"
            "No SenPai files found"
            f"{Fore.RESET}"
        )

        pause()

        return []

    print(
        f"{Fore.CYAN}"
        "Scanner files found:"
        f"{Fore.RESET}"
    )

    for i, f in enumerate(files):

        print(
            f"[{i}] {f}"
        )

    try:

        num = int(
            input(
                "\nSelect file: "
            )
        )

        if num < 0 or num >= len(files):

            print(
                f"{Fore.RED}"
                "Invalid selection"
                f"{Fore.RESET}"
            )

            pause()

            return []

        data = load_file(
            files[num]
        )

        ips = extract_ips(
            data
        )

        ips = sort_ips(
            ips
        )

        saved = save_ip_list(
            ips
        )

        print(
            f"\n{Fore.GREEN}"
            f"Found IPs: {len(ips)}"
        )

        print(
            f"{Fore.CYAN}"
            f"Saved: {saved}"
        )

        if ips:

            if copy_to_clipboard(
                "\n".join(ips)
            ):

                print(
                    f"{Fore.GREEN}"
                    "Copied to clipboard"
                )

        pause()

        return ips

    except Exception:

        print(
            f"{Fore.RED}"
            "Invalid selection"
            f"{Fore.RESET}"
        )

        pause()

        return []


# ============================================================
# SCRIPT 2 - IP CLEANER
# Hidden operations preserved
# ============================================================

INPUT = "input.txt"
OUTPUT = "output_ips.txt"


def clean_ips(data):

    ips = re.findall(
        r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        data
    )

    valid = []

    for ip in ips:

        try:

            if all(
                0 <= int(x) <= 255
                for x in ip.split(".")
            ):

                valid.append(ip)

        except Exception:

            pass

    valid = list(
        dict.fromkeys(valid)
    )

    random.shuffle(
        valid
    )

    return valid


def copy_clipboard(valid):

    try:

        subprocess.run(
            ["termux-clipboard-set"],
            input="\n".join(valid),
            text=True,
            check=True
        )

        print(
            f"{Fore.GREEN}"
            "✓ Copied to Android Clipboard"
            f"{Fore.RESET}"
        )

    except Exception:

        print(
            f"{Fore.YELLOW}"
            "! Clipboard unavailable"
            f"{Fore.RESET}"
        )


def save_output_ips(valid):

    with open(
        OUTPUT,
        "w",
        encoding="utf-8"
    ) as f:

        f.write(
            "\n".join(valid)
        )


def show_output(valid):

    print(
        f"\n{Fore.CYAN}"
        "========== OUTPUT =========="
        f"{Fore.RESET}\n"
    )

    for ip in valid:

        print(ip)

    print(
        f"\n{Fore.GREEN}"
        f"Total IPs: {len(valid)}"
        f"{Fore.RESET}"
    )

    print(
        f"{Fore.GREEN}"
        f"Saved: {OUTPUT}"
        f"{Fore.RESET}"
    )


def manual_clean():

    clear_screen()

    print(BANNER)

    if not os.path.exists(INPUT):

        open(
            INPUT,
            "w",
            encoding="utf-8"
        ).close()

    os.system(
        f'nano "{INPUT}"'
    )

    with open(
        INPUT,
        "r",
        encoding="utf-8",
        errors="ignore"
    ) as f:

        data = f.read()

    valid = clean_ips(
        data
    )

    save_output_ips(
        valid
    )

    copy_clipboard(
        valid
    )

    show_output(
        valid
    )

    open(
        INPUT,
        "w",
        encoding="utf-8"
    ).close()

    pause()

    return valid


def scan_browser():

    clear_screen()

    print(BANNER)

    files = glob.glob(
        os.path.expanduser(
            "~/SenPaiScannerResult-*.txt"
        )
    )

    if not files:

        print(
            f"{Fore.RED}"
            "No Scan Result Found"
            f"{Fore.RESET}"
        )

        pause()

        return

    files.sort(
        reverse=True
    )

    print(
        f"\n{Fore.CYAN}"
        "====== SCAN RESULTS ======"
        f"{Fore.RESET}\n"
    )

    for i, file in enumerate(
        files,
        1
    ):

        print(
            f"{Fore.GREEN}[{i}]"
            f"{Fore.RESET} "
            f"{os.path.basename(file)}"
        )

    print(
        f"\n{Fore.RED}[0]"
        f"{Fore.RESET} Back"
    )

    try:

        choice = int(
            input(
                f"\n{Fore.YELLOW}"
                "Select File Number: "
                f"{Fore.RESET}"
            )
        )

    except Exception:

        return

    if choice == 0:

        return

    if (
        choice < 1
        or choice > len(files)
    ):

        print(
            f"{Fore.RED}"
            "Invalid Selection"
            f"{Fore.RESET}"
        )

        pause()

        return

    selected = files[
        choice - 1
    ]

    with open(
        selected,
        "r",
        encoding="utf-8",
        errors="ignore"
    ) as f:

        data = f.read()

    valid = clean_ips(
        data
    )

    save_output_ips(
        valid
    )

    copy_clipboard(
        valid
    )

    show_output(
        valid
    )

    pause()


# ============================================================
# MAIN MENU
#
# ONLY THESE OPTIONS ARE SHOWN:
#
# 1 = Load Configs (Paste)
# 2 = Scan Result Browser
# 3 = Generate New Configs
# 0 = Exit
#
# Other original functions remain in the script.
# ============================================================

def main():

    base_configs = []

    while True:

        clear_screen()

        print(BANNER)

        if base_configs:

            print(
                f"{Fore.CYAN}"
                "Loaded Configs: "
                f"{Fore.GREEN}"
                f"{len(base_configs)}"
            )

        else:

            print(
                f"{Fore.CYAN}"
                "Loaded Configs: "
                f"{Fore.RED}"
                "None"
            )

        print(
            "\n" + "=" * 55
        )

        print(
            f"{TITLE_COLOR}"
            "# MAIN MENU"
            f"{RESET}"
        )

        print()

        # ====================================================
        # OPTION 1
        # ====================================================

        print(
            f"{WHITE}[1]{RESET} "
            f"{BRICK}"
            "Load Configs (Paste)"
            f"{RESET}"
        )

        # ====================================================
        # OPTION 2
        # ====================================================

        print(
            f"{WHITE}[2]{RESET} "
            f"{LILAC}"
            "Scan Result Browser"
            f"{RESET}"
        )

        # ====================================================
        # OPTION 3
        # ====================================================

        print(
            f"{WHITE}[3]{RESET} "
            f"{ORANGE}"
            "Generate New Configs"
            f"{RESET}"
        )

        print(
            "\n" + "=" * 55
        )

        # ====================================================
        # EXIT
        # ====================================================

        print(
            f"{GREEN}"
            "# EXIT"
            f"{RESET}"
        )

        print()

        print(
            f"{WHITE}[0]{RESET} "
            f"{GREEN}"
            "Exit"
            f"{RESET}"
        )

        print(
            "=" * 55
        )

        choice = input(
            f"\n{Fore.GREEN}"
            "Select: "
            f"{Fore.RESET}"
        ).strip()

        # ====================================================
        # OPTION 1
        # ====================================================

        if choice == "1":

            clear_screen()

            print(BANNER)

            print(
                f"{Fore.YELLOW}"
                "Paste configs"
                f"{Fore.RESET}"
            )

            print(
                f"{Fore.LIGHTBLACK_EX}"
                "(Finish with CTRL+D)"
                f"{Fore.RESET}\n"
            )

            data = []

            while True:

                try:

                    line = input()

                    if line.strip():

                        data.append(line)

                except EOFError:

                    break

            base_configs = load_configs_from_text(
                "\n".join(data)
            )

            print(
                f"\n{Fore.GREEN}"
                f"Loaded: {len(base_configs)}"
                f"{Fore.RESET}"
            )

            pause()

        # ====================================================
        # OPTION 2
        # ====================================================

        elif choice == "2":

            scan_browser()

        # ====================================================
        # OPTION 3
        # ====================================================

        elif choice == "3":

            clear_screen()

            print(BANNER)

            if not base_configs:

                print(
                    f"{Fore.RED}"
                    "Load configs first!"
                    f"{Fore.RESET}"
                )

                pause()

                continue

            print(
                f"\n{Fore.YELLOW}"
                "Paste clean IPs"
                f"{Fore.RESET}"
            )

            print(
                f"{Fore.LIGHTBLACK_EX}"
                "(CTRL+D when finished)"
                f"{Fore.RESET}\n"
            )

            lines = []

            while True:

                try:

                    line = input()

                    if line.strip():

                        lines.append(line)

                except EOFError:

                    break

            ips = extract_ips(
                "\n".join(lines)
            )

            if not ips:

                print(
                    f"{Fore.RED}"
                    "No valid IP found"
                    f"{Fore.RESET}"
                )

                pause()

                continue

            results, stats = generate_configs(
                base_configs,
                ips
            )

            if not results:

                print(
                    f"{Fore.RED}"
                    "Nothing generated"
                    f"{Fore.RESET}"
                )

                pause()

                continue

            show_stats(
                base_configs,
                ips,
                results
            )

            timestamp = datetime.now().strftime(
                "%Y%m%d_%H%M%S"
            )

            filename = (
                f"exact_configs_"
                f"{timestamp}.txt"
            )

            output = "\n\n".join(
                results
            )

            path = save_output(
                filename,
                output
            )

            print(
                f"\n{Fore.GREEN}"
                f"✔ Saved: {path}"
                f"{Fore.RESET}"
            )

            if copy_to_clipboard(
                output
            ):

                print(
                    f"{Fore.GREEN}"
                    "✔ Copied to clipboard"
                    f"{Fore.RESET}"
                )

            else:

                print(
                    f"{Fore.YELLOW}"
                    "Clipboard unavailable"
                    f"{Fore.RESET}"
                )

            pause()

        # ====================================================
        # EXIT
        # ====================================================

        elif choice == "0":

            clear_screen()

            print(
                f"{GREEN}"
                "Exit..."
                f"{RESET}"
            )

            break

        # ====================================================
        # INVALID
        # ====================================================

        else:

            print(
                f"{Fore.RED}"
                "Invalid Option"
                f"{Fore.RESET}"
            )

            pause()


# ============================================================
# START
# ============================================================

if __name__ == "__main__":

    main()

