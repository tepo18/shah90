#!/data/data/com.termux/files/usr/bin/bash

FILE="$HOME/ips.txt"

if [ ! -f "$FILE" ]; then
    echo "ERROR: $FILE not found."
    exit 1
fi

TMP=$(mktemp)

awk '
{
    gsub(/\r/,"")
    gsub(/^[[:space:]]+|[[:space:]]+$/,"")

    split($0,a,":")
    ip=a[1]

    if(ip ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}$/){
        split(ip,o,".")
        ok=1
        for(i=1;i<=4;i++){
            if(o[i] < 0 || o[i] > 255){
                ok=0
                break
            }
        }
        if(ok) print ip
    }
}
' "$FILE" | awk '!seen[$0]++' | shuf > "$TMP"

mv "$TMP" "$FILE"

echo "=================================="
echo "DONE"
echo "FILE : $FILE"
echo "COUNT: $(wc -l < "$FILE")"
echo "=================================="
