#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import shutil
import subprocess
from datetime import datetime

from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table


console = Console()


# ============================================================
# PATHS
# ============================================================

BASE_BACKUP_DIR = "/sdcard/Download"
TERMUX_HOME = "/data/data/com.termux/files/home"

BACKUP_EXTENSIONS = (".py", ".sh")

os.makedirs(
    BASE_BACKUP_DIR,
    exist_ok=True
)


# ============================================================
# HELPERS
# ============================================================

def is_script_file(filename):
    """
    Return True ONLY for .py and .sh files.
    """

    return filename.lower().endswith(
        BACKUP_EXTENSIONS
    )


def is_backup_dir(name):
    """
    Accept:

        backup
        backup_YYYYMMDD_HHMMSS
    """

    return (
        name == "backup"
        or name.startswith("backup_")
    )


def get_backups():
    """
    Find backup folders directly inside Download.

    Newest backup first.
    """

    backups = []

    try:

        for name in os.listdir(
            BASE_BACKUP_DIR
        ):

            full_path = os.path.join(
                BASE_BACKUP_DIR,
                name
            )

            if (
                os.path.isdir(full_path)
                and is_backup_dir(name)
            ):

                backups.append(name)

    except Exception as e:

        console.print(
            "[bold red]Cannot read backup directory:[/bold red]"
        )

        console.print(
            f"[yellow]{e}[/yellow]"
        )

        return []

    # Newest first
    backups.sort(
        key=lambda name: os.path.getmtime(
            os.path.join(
                BASE_BACKUP_DIR,
                name
            )
        ),
        reverse=True
    )

    return backups


# ============================================================
# BACKUP
# ============================================================

def backup_selected():
    """
    Backup ONLY .py and .sh files directly inside TERMUX_HOME.

    IMPORTANT:

    - Does NOT scan subdirectories.
    - Does NOT copy directories.
    - Does NOT create directories inside backup.
    - Only direct files in HOME are copied.
    """

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    backup_dir = os.path.join(
        BASE_BACKUP_DIR,
        f"backup_{timestamp}"
    )

    # The backup folder itself is required.
    os.makedirs(
        backup_dir,
        exist_ok=True
    )

    count = 0
    failed = 0

    console.print()

    console.print(
        "[bold cyan]Starting backup...[/bold cyan]"
    )

    console.print()

    # ========================================================
    # IMPORTANT:
    # os.listdir() is intentionally used instead of os.walk().
    #
    # Therefore subdirectories are NEVER entered.
    # ========================================================

    try:

        entries = os.listdir(
            TERMUX_HOME
        )

    except Exception as e:

        console.print(
            "[bold red]Cannot read Termux HOME.[/bold red]"
        )

        console.print(
            f"[yellow]{e}[/yellow]"
        )

        return

    for filename in entries:

        src = os.path.join(
            TERMUX_HOME,
            filename
        )

        # ----------------------------------------------------
        # Ignore directories completely
        # ----------------------------------------------------

        if not os.path.isfile(src):
            continue

        # ----------------------------------------------------
        # Only .py and .sh
        # ----------------------------------------------------

        if not is_script_file(filename):
            continue

        dst = os.path.join(
            backup_dir,
            filename
        )

        try:

            shutil.copy2(
                src,
                dst
            )

            count += 1

        except Exception as e:

            failed += 1

            console.print(
                f"[red]Failed:[/red] {filename}"
            )

            console.print(
                f"[yellow]{e}[/yellow]"
            )

    # ========================================================
    # RESULT
    # ========================================================

    console.print()

    console.print(
        "[bold green]Backup complete.[/bold green]"
    )

    console.print(
        f"[cyan]Location:[/cyan] {backup_dir}"
    )

    console.print(
        f"[cyan]Files copied:[/cyan] {count}"
    )

    if failed:

        console.print(
            f"[bold red]Failed:[/bold red] {failed}"
        )

    console.print()

    console.print(
        "[cyan]Backup contains only:[/cyan] "
        ".py + .sh"
    )

    console.print(
        "[cyan]Subdirectories:[/cyan] ignored"
    )


# ============================================================
# RESTORE
# ============================================================

def restore_files():
    """
    Restore ONLY .py and .sh files directly from
    the selected backup folder.

    No directories from inside the backup are restored.
    """

    backups = get_backups()

    # ========================================================
    # NO BACKUPS
    # ========================================================

    if not backups:

        console.print()

        console.print(
            "[bold red]No backup folders found.[/bold red]"
        )

        console.print(
            f"[yellow]Checked:[/yellow] "
            f"{BASE_BACKUP_DIR}"
        )

        return

    # ========================================================
    # SHOW BACKUPS
    # ========================================================

    table = Table(
        title="Available Backups"
    )

    table.add_column(
        "No",
        style="cyan",
        justify="center"
    )

    table.add_column(
        "Backup Folder",
        style="green"
    )

    table.add_column(
        "Location",
        style="white"
    )

    for index, backup_name in enumerate(
        backups,
        start=1
    ):

        backup_path = os.path.join(
            BASE_BACKUP_DIR,
            backup_name
        )

        table.add_row(
            str(index),
            backup_name,
            backup_path
        )

    console.print()
    console.print(table)
    console.print()

    # ========================================================
    # SELECT BACKUP
    # ========================================================

    choice = Prompt.ask(
        "[bold cyan]Select backup number[/bold cyan] "
        "[yellow](0 = cancel)[/yellow]",
        default="0"
    ).strip()

    if choice == "0":

        console.print(
            "[yellow]Cancelled.[/yellow]"
        )

        return

    # ========================================================
    # VALIDATE
    # ========================================================

    try:

        index = int(choice) - 1

        if index < 0 or index >= len(backups):
            raise ValueError

        backup_name = backups[index]

    except (ValueError, TypeError):

        console.print(
            "[bold red]Invalid selection.[/bold red]"
        )

        return

    backup_dir = os.path.join(
        BASE_BACKUP_DIR,
        backup_name
    )

    if not os.path.isdir(
        backup_dir
    ):

        console.print(
            "[bold red]Backup folder does not exist.[/bold red]"
        )

        return

    # ========================================================
    # RESTORE
    # ========================================================

    restored = 0
    failed = 0

    console.print()

    console.print(
        f"[bold cyan]Restoring:[/bold cyan] "
        f"{backup_name}"
    )

    console.print()

    # ========================================================
    # IMPORTANT:
    # os.listdir() means we NEVER enter subdirectories.
    # ========================================================

    try:

        entries = os.listdir(
            backup_dir
        )

    except Exception as e:

        console.print(
            "[bold red]Cannot read backup.[/bold red]"
        )

        console.print(
            f"[yellow]{e}[/yellow]"
        )

        return

    for filename in entries:

        src = os.path.join(
            backup_dir,
            filename
        )

        # ----------------------------------------------------
        # Ignore directories completely
        # ----------------------------------------------------

        if not os.path.isfile(src):
            continue

        # ----------------------------------------------------
        # Only .py and .sh
        # ----------------------------------------------------

        if not is_script_file(filename):
            continue

        dst = os.path.join(
            TERMUX_HOME,
            filename
        )

        try:

            # Replace existing file automatically
            shutil.copy2(
                src,
                dst
            )

            restored += 1

        except Exception as e:

            failed += 1

            console.print(
                f"[red]Failed:[/red] {filename}"
            )

            console.print(
                f"[yellow]{e}[/yellow]"
            )

    # ========================================================
    # RESTORE RESULT
    # ========================================================

    console.print()

    console.print(
        "[bold green]Restore complete.[/bold green]"
    )

    console.print(
        f"[cyan]Files restored:[/cyan] "
        f"{restored}"
    )

    if failed:

        console.print(
            f"[bold red]Failed:[/bold red] "
            f"{failed}"
        )

    console.print(
        f"[cyan]Restore destination:[/cyan] "
        f"{TERMUX_HOME}"
    )

    # ========================================================
    # EXECUTE PERMISSIONS
    # ========================================================

    try:

        result = subprocess.run(
            "chmod +x ~/*.py ~/*.sh 2>/dev/null",
            shell=True,
            executable="/system/bin/sh"
        )

        console.print()

        if result.returncode == 0:

            console.print(
                "[bold green]"
                "Execute permissions applied."
                "[/bold green]"
            )

            console.print(
                "[cyan]Command:[/cyan] "
                "chmod +x ~/*.py ~/*.sh 2>/dev/null"
            )

        else:

            console.print(
                "[yellow]"
                "No matching .py/.sh files "
                "or no changes needed."
                "[/yellow]"
            )

    except Exception as e:

        console.print()

        console.print(
            "[bold red]"
            "Failed to apply execute permissions."
            "[/bold red]"
        )

        console.print(
            f"[yellow]{e}[/yellow]"
        )


# ============================================================
# MAIN MENU
# ============================================================

def main():

    while True:

        console.print()

        console.print(
            "[bold yellow]"
            "══════════════════════════════════════"
            "[/bold yellow]"
        )

        console.print(
            "[bold cyan]"
            "        TERMUX BACKUP MANAGER"
            "[/bold cyan]"
        )

        console.print(
            "[bold yellow]"
            "══════════════════════════════════════"
            "[/bold yellow]"
        )

        console.print(
            "[green]1[/green]  Backup .py + .sh"
        )

        console.print(
            "[green]2[/green]  Restore"
        )

        console.print(
            "[red]0[/red]  Exit"
        )

        console.print()

        choice = Prompt.ask(
            "[bold cyan]Select[/bold cyan]",
            default="0"
        ).strip()

        # ====================================================
        # BACKUP
        # ====================================================

        if choice == "1":

            backup_selected()

        # ====================================================
        # RESTORE
        # ====================================================

        elif choice == "2":

            restore_files()

        # ====================================================
        # EXIT
        # ====================================================

        elif choice == "0":

            console.print(
                "[bold yellow]Exit.[/bold yellow]"
            )

            break

        # ====================================================
        # INVALID
        # ====================================================

        else:

            console.print(
                "[bold red]Invalid option.[/bold red]"
            )


# ============================================================
# START
# ============================================================

if __name__ == "__main__":
    main()
