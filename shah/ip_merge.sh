#!/bin/bash

DEST="$HOME/ips.txt"
TMP_INPUT="/data/data/com.termux/files/home/new_ips.txt"

echo "Paste IPs in nano, then save and exit..."
nano "$TMP_INPUT"

if [ ! -f "$TMP_INPUT" ]; then
  echo "No input file created"
  exit 1
fi

echo "Processing..."

# merge old + new
cat "$DEST" "$TMP_INPUT" 2>/dev/null \
| sed 's/:.*//' \
| grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' \
| sort -u \
| shuf \
> "$DEST"

# cleanup temp
rm -f "$TMP_INPUT"

echo "Done -> $DEST"
