#!/bin/bash

echo "Enter source file name (inside Download):"
read src

SRC="/storage/emulated/0/Download/$src"
DEST="$HOME/ips.txt"

if [ ! -f "$SRC" ]; then
  echo "File not found: $SRC"
  exit 1
fi

echo "Cleaning and processing..."

# remove old output
rm -f "$DEST"

# process: remove ports + extract IPs + unique + shuffle + write
cat "$SRC" \
| sed 's/:.*//' \
| grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' \
| sort -u \
| shuf \
> "$DEST"

echo "Done -> $DEST"
