#!/usr/bin/env python3
import os

scripts = [

    "backup30.py",
    "cofing20.py",
    "root.py",
    "shah5.py",
    "shah10.py",
    "base.py",
    "tarkibi.sh",
    "tarkib20.sh",
    "ip_cleaner.sh",
    "ip_merge.sh",
    "install_senpi.sh",
    "clean_ips.sh",
    "ips.txt",
    "senpi"

]


def show_menu():
    os.system("clear")

    print("\033[96m")
    print("╔══════════════════════════════╗")
    print("║       SCANNER LAUNCHER       ║")
    print("╚══════════════════════════════╝")
    print("\033[0m")

    for i, s in enumerate(scripts, 1):
        print(f"\033[92m[{i}]\033[0m {s}")

        if i == 5:
            print("\n\033[93m#next\033[0m\n")

        if i == 9:
            print("\n\033[93m#next\033[0m\n")

    print("\n\033[91m[0]\033[0m Exit")


while True:
    show_menu()
    choice = input("Select: ").strip()

    if choice == "0":
        break

    if choice.isdigit():
        idx = int(choice) - 1

        if 0 <= idx < len(scripts):
            file = scripts[idx]

            os.system("clear")
            print(f"Running: {file}\n")

            if file.endswith(".py"):
                os.system(f"python3 '{file}'")
            elif file.endswith(".sh"):
                os.system(f"bash '{file}'")
            else:
                os.system(f"'{file}'")

            input("\nFinished. Press Enter...")
        else:
            input("Invalid!")
        continue

    input("Invalid! Enter...")
