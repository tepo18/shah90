#!/bin/bash  
# ------------------- COLORS & STYLE -------------------  
CYAN="\e[96m"  
BOLD="\e[1m"  
RESET="\e[0m"  
  
# ------------------- PATHS -------------------  
BASE_PATH="$HOME"  
DOWNLOAD_DIR="/sdcard/Download/Akbar98"  
EXPORT_DIR="/sdcard/Download"   # مسیر ثابت برای گزینه 17  
  
# ------------------- GLOBAL VARIABLES -------------------  
CURRENT_REPO=""  
REPO_PATH=""  
GIT_USER=""  
PASSWORD="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"  # ذخیره پسورد ثابت برای گزینه 18
  
# ------------------- FUNCTIONS -------------------  
choose_account() {  
    echo -e "${BOLD}${CYAN}Select GitHub account:${RESET}"  
    echo "1) tepo18"  
    echo "2) almasi98"  
    echo "3) tepo98"  
    read -rp "Enter number: " ACC_CHOICE  
    case $ACC_CHOICE in  
        1) GIT_USER="tepo18" ;;  
        2) GIT_USER="almasi98" ;;  
        3) GIT_USER="tepo98" ;;  
        *) echo -e "${CYAN}Invalid choice, defaulting to tepo18${RESET}"; GIT_USER="tepo18" ;;  
    esac  
    echo -e "${CYAN}GitHub account set to: $GIT_USER${RESET}"  
}  
  
switch_repo() {  
    echo -ne "${BOLD}${CYAN}Enter repo name to switch/use: ${RESET}"  
    read -r REPO_NAME  
    CURRENT_REPO="$REPO_NAME"  
    REPO_PATH="$BASE_PATH/$CURRENT_REPO"  
    if [ ! -d "$REPO_PATH" ]; then  
        echo -e "${CYAN}Cloning repo...${RESET}"  
        git clone "https://github.com/$GIT_USER/$CURRENT_REPO.git" "$REPO_PATH" || { echo "Clone failed!"; return; }  
    else  
        echo -e "${CYAN}Using existing repo.${RESET}"  
    fi  
    cd "$REPO_PATH" || { echo "Cannot enter repo folder."; return; }  
    echo -e "${CYAN}Repo switched to: $CURRENT_REPO${RESET}"  
}  
  
reset_update_local_repo() {  
    if [ -z "$REPO_PATH" ]; then  
        echo -e "${CYAN}No repo selected. Please switch repo first.${RESET}"  
        return  
    fi  
  
    read -rp "Are you sure you want to reset the local repo? This will discard all local changes! (yes/no): " CONFIRM  
    if [ "$CONFIRM" != "yes" ]; then  
        echo -e "${CYAN}Reset cancelled.${RESET}"  
        return  
    fi  
  
    echo -e "${CYAN}Resetting and updating local repo...${RESET}"  
    git reset --hard  
    git pull origin main  
    echo -e "${CYAN}Local repo reset and updated successfully!${RESET}"  
}  

# Function to generate unique filename if file exists
generate_unique_filename() {
    local DIR="$1"
    local FILENAME="$2"
    local BASENAME="${FILENAME%.*}"
    local EXT="${FILENAME##*.}"
    local COUNT=1
    local NEWFILE="$DIR/$FILENAME"
    while [ -e "$NEWFILE" ]; do
        NEWFILE="$DIR/${BASENAME}${COUNT}.$EXT"
        COUNT=$((COUNT + 1))
    done
    echo "$NEWFILE"
}

main_menu() {  
    while true; do  
        echo -e "\n${BOLD}${CYAN}===== LOCAL / DEVICE =====${RESET}"  
        echo "1) Select account"  
        echo "2) Switch repo"  
        echo "3) Reset repo"  
        echo "---------------------------"  
        echo -e "${BOLD}${CYAN}===== MAIN MENU =====${RESET}"  
        echo "4) Create file"  
        echo "5) Edit file"  
        echo "6) Delete file(s)"  
        echo "7) Clear file(s)"  
        echo "8) Commit"  
        echo "9) Push Git"  
        echo "10) Copy from Download"  
        echo "11) Copy content to clipboard"  
        echo "12) Custom copy files"  
        echo "13) Copy all repo files to Download"  
        echo "14) Copy password"  
  
        echo -ne "${BOLD}${CYAN}Choice: ${RESET}"  
        read -r CHOICE  
  
        case $CHOICE in  
            1) choose_account ;;  
            2) switch_repo ;;  
            3) reset_update_local_repo ;;  
            4)  
                read -rp "Enter new filename: " NEWFILE  
                [ -e "$NEWFILE" ] && echo -e "${CYAN}File exists${RESET}" || (touch "$NEWFILE" && echo -e "${CYAN}File created${RESET}")  
                ;;  
            5)  
                read -rp "Enter filename to edit: " EDITFILE  
                [ ! -e "$EDITFILE" ] && echo -e "${CYAN}File not found${RESET}" || nano "$EDITFILE"  
                ;;  
            6)  
                read -rp "Enter filenames (space-separated): " DELFILES  
                for f in $DELFILES; do  
                    [ -e "$f" ] && rm -i "$f" && echo -e "${CYAN}$f deleted${RESET}" || echo -e "${CYAN}$f not found${RESET}"  
                done  
                ;;  
            7)  
                read -rp "Enter filenames to clear: " CLEARFILES  
                for f in $CLEARFILES; do  
                    [ -e "$f" ] && >"$f" && echo -e "${CYAN}$f cleared${RESET}" || echo -e "${CYAN}$f not found${RESET}"  
                done  
                ;;  
            8)  
                git status  
                read -rp "Commit message (default: auto update): " MSG  
                [ -z "$MSG" ] && MSG="auto update from script"  
                git add .  
                git commit -m "$MSG" 2>/dev/null || echo -e "${CYAN}Nothing to commit${RESET}"  
                ;;  
            9)  
                read -rp "Push changes? (yes/no): " PUSH_ANSWER  
                if [ "$PUSH_ANSWER" == "yes" ]; then  
                    git add .  
                    read -rp "Commit message (default: auto update): " MSG  
                    [ -z "$MSG" ] && MSG="auto update from script"  
                    git commit -m "$MSG" --allow-empty  
                    git push "https://github.com/$GIT_USER/$CURRENT_REPO.git" && echo -e "${CYAN}Pushed successfully${RESET}" || echo -e "${CYAN}Push failed${RESET}"  
                fi  
                ;;  
            10)  
                read -rp "Source file in Download: " SRC  
                read -rp "Target filename in repo: " TARGET  
                if [ -f "$DOWNLOAD_DIR/$SRC" ]; then  
                    cat "$DOWNLOAD_DIR/$SRC" > "$TARGET" && echo -e "${CYAN}Copied content${RESET}"  
                else  
                    echo -e "${CYAN}Source file not found${RESET}"  
                fi  
                ;;  
            11)  
                if [ -z "$REPO_PATH" ]; then  
                    echo -e "${CYAN}No repo selected. Switch first.${RESET}"  
                else  
                    cd "$REPO_PATH" || { echo -e "${CYAN}Cannot access repo path${RESET}"; continue; }  
                    read -rp "Enter filename: " COPYFILE  
                    if [ -f "$COPYFILE" ]; then  
                        termux-clipboard-set < "$COPYFILE"  
                        echo -e "${CYAN}Content copied to clipboard${RESET}"  
                    else  
                        echo -e "${CYAN}File not found${RESET}"  
                    fi  
                fi  
                ;;  
            12)  
                if [ -z "$REPO_PATH" ]; then  
                    echo -e "${CYAN}No repo selected. Switch first.${RESET}"  
                else  
                    cd "$REPO_PATH" || { echo -e "${CYAN}Cannot access repo path${RESET}"; continue; }  
                    mkdir -p "$EXPORT_DIR/ahoora98"
                    read -rp "Enter filenames (space-separated): " FILES  
                    for f in $FILES; do  
                        if [ -f "$f" ]; then  
                            DEST_FILE=$(generate_unique_filename "$EXPORT_DIR/ahoora98" "$f")
                            cp "$f" "$DEST_FILE"
                            echo -e "${CYAN}Copied $f to $DEST_FILE${RESET}"  
                        else  
                            echo -e "${CYAN}$f not found${RESET}"  
                        fi  
                    done  
                fi  
                ;;  
            13)  
                if [ -z "$REPO_PATH" ]; then
                    echo -e "${CYAN}No repo selected. Switch first.${RESET}"
                else
                    cd "$REPO_PATH" || { echo -e "${CYAN}Cannot access repo path${RESET}"; continue; }
                    echo -e "${BOLD}${CYAN}Select option:${RESET}"
                    echo "1) Copy all repo files"
                    echo "2) Copy custom files"
                    echo -ne "${BOLD}${CYAN}Choice: ${RESET}"
                    read -r SUBCHOICE

                    case $SUBCHOICE in
                        1)  # Copy all repo files to one txt in Download
                            read -rp "Enter output filename (without extension): " OUTFILE
                            OUTPATH="$EXPORT_DIR/$OUTFILE.txt"
                            UNIQUE_OUTPATH=$(generate_unique_filename "$EXPORT_DIR" "$OUTFILE.txt")
                            > "$UNIQUE_OUTPATH"  # create or clear file
                            for f in *; do
                                if [ -f "$f" ]; then
                                    echo "===== $f =====" >> "$UNIQUE_OUTPATH"
                                    cat "$f" >> "$UNIQUE_OUTPATH"
                                    echo -e "\n" >> "$UNIQUE_OUTPATH"
                                fi
                            done
                            echo -e "${CYAN}All repo files merged into $UNIQUE_OUTPATH${RESET}"
                            ;;
                        2)  # Copy custom files to ahoora98
                            mkdir -p "$EXPORT_DIR/ahoora98"
                            read -rp "Enter filenames (space-separated): " FILES
                            for f in $FILES; do
                                if [ -f "$f" ]; then
                                    DEST_FILE=$(generate_unique_filename "$EXPORT_DIR/ahoora98" "$f")
                                    cp "$f" "$DEST_FILE"
                                    echo -e "${CYAN}Copied $f to $DEST_FILE${RESET}"
                                else
                                    echo -e "${CYAN}$f not found${RESET}"
                                fi
                            done
                            ;;
                        *) echo -e "${CYAN}Invalid choice${RESET}" ;;
                    esac
                fi
                ;;  

            14)
                echo -e "${CYAN}Stored password:${RESET} $PASSWORD"
                ;;  

            *) echo -e "${CYAN}Invalid choice${RESET}" ;;  
        esac  
    done  
}  
  
# ------------------- SCRIPT START -------------------  
main_menu
