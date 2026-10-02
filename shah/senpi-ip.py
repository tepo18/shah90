#!/usr/bin/env python3

import os
import re
import random
import subprocess
import glob

INPUT = "input.txt"
OUTPUT = "output_ips.txt"


# =========================
# COLORS
# =========================

CYAN = "\033[96m"
GREEN = "\033[92m"
BLUE = "\033[94m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"


def clean_ips(data):

    ips = re.findall(
        r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        data
    )

    valid = []

    for ip in ips:
        try:
            if all(0 <= int(x) <= 255 for x in ip.split(".")):
                valid.append(ip)
        except:
            pass

    # remove duplicates
    valid = list(dict.fromkeys(valid))

    # shuffle
    random.shuffle(valid)

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
            f"{GREEN}✓ Copied to Android Clipboard{RESET}"
        )

    except:

        print(
            f"{YELLOW}! Clipboard unavailable{RESET}"
        )



def save_output(valid):

    with open(
        OUTPUT,
        "w",
        encoding="utf-8"
    ) as f:
        f.write("\n".join(valid))



def show_output(valid):

    print(
        f"\n{CYAN}========== OUTPUT =========={RESET}\n"
    )

    for ip in valid:
        print(ip)

    print(
        f"\n{GREEN}Total IPs: {len(valid)}{RESET}"
    )

    print(
        f"{GREEN}Saved: {OUTPUT}{RESET}"
    )



# =========================
# OPTION 1
# =========================

def manual_clean():

    if not os.path.exists(INPUT):
        open(INPUT,"w").close()


    os.system(
        f"nano {INPUT}"
    )


    with open(
        INPUT,
        "r",
        encoding="utf-8",
        errors="ignore"
    ) as f:

        data = f.read()


    valid = clean_ips(data)


    save_output(valid)

    copy_clipboard(valid)

    show_output(valid)


    open(INPUT,"w").close()



# =========================
# OPTION 2
# =========================

def scan_browser():

    files = glob.glob(
        os.path.expanduser(
            "~/SenPaiScannerResult-*.txt"
        )
    )


    if not files:

        print(
            f"{RED}No Scan Result Found{RESET}"
        )

        return



    # newest first
    files.sort(reverse=True)



    print(
        f"\n{CYAN}====== SCAN RESULTS ======{RESET}\n"
    )


    for i, file in enumerate(files,1):

        print(
            f"{GREEN}[{i}]{RESET} {os.path.basename(file)}"
        )


    print(
        f"\n{RED}[0]{RESET} Back"
    )


    try:

        choice = int(
            input(
                f"\n{YELLOW}Select File Number: {RESET}"
            )
        )

    except:

        return



    if choice == 0:
        return



    if choice < 1 or choice > len(files):

        print(
            f"{RED}Invalid Selection{RESET}"
        )

        return



    selected = files[choice-1]


    with open(
        selected,
        "r",
        encoding="utf-8",
        errors="ignore"
    ) as f:

        data = f.read()



    valid = clean_ips(data)


    save_output(valid)

    copy_clipboard(valid)

    show_output(valid)




# =========================
# MAIN MENU
# =========================

def main():


    while True:


        print(
f"""
{CYAN}╔══════════════════════════╗
║      IP CLEANER TOOL     ║
╚══════════════════════════╝{RESET}

{GREEN}[1]{RESET} Clean Manual Input

{BLUE}[2]{RESET} Scan Result Browser

{RED}[3]{RESET} Exit

"""
        )


        choice = input(
            f"{YELLOW}Select Option: {RESET}"
        )



        if choice == "1":

            manual_clean()



        elif choice == "2":

            scan_browser()



        elif choice == "3":

            print(
                f"{RED}Exit...{RESET}"
            )

            break



        else:

            print(
                f"{RED}Invalid Option{RESET}"
            )



if __name__ == "__main__":

    main()


