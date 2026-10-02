#!/data/data/com.termux/files/usr/bin/bash

CYAN='\033[1;36m'
GREEN='\033[1;32m'
NC='\033[0m'

clear
echo -e "${CYAN}=== STRICT NO-TOUCH CUSTOM ENGINE ===${NC}"
echo
echo "Paste trojan links (CTRL + D to finish):"
INPUT=$(cat)

echo

# ===== FULL FIXED TEMPLATE (EVERYTHING LOCKED) =====
BASE='{
"remarks":"tepo98-custom🎖",

"log":{
"access":"",
"error":"",
"loglevel":"info",
"dnsLog":false
},

"inbounds":[
{
"tag":"in_proxy",
"port":1080,
"protocol":"socks",
"listen":"0.0.0.0",
"settings":{"auth":"noauth","udp":true,"userLevel":8},
"sniffing":{"enabled":false}
},
{
"tag":"http-in",
"port":10808,
"listen":"::",
"protocol":"http"
}
],

"outbounds":[
{
"tag":"proxy",
"protocol":"trojan",
"settings":{
"servers":[
{
"address":"🌟",
"method":"chacha20-poly1305",
"ota":false,
"password":"🌟",
"port":443,
"level":8,
"flow":""
}
]
},
"streamSettings":{
"network":"ws",
"security":"tls",
"wsSettings":{
"path":"🌟",
"headers":{"Host":"🌟"}
},
"tlsSettings":{
"allowInsecure":true,
"serverName":"🌟",
"alpn":["http/1.1"],
"fingerprint":"ios",
"show":false
},
"sockopt":{
"dialerProxy":"fragment",
"tcpKeepAliveIdle":100,
"tcpNoDelay":true
}
},
"mux":{
"enabled":false,
"concurrency":8
}
},

{
"tag":"fragment",
"protocol":"freedom",
"settings":{
"domainStrategy":"AsIs",
"fragment":{
"packets":"tlshello",
"length":"100-200",
"interval":"10-20"
}
},
"streamSettings":{
"sockopt":{
"tcpKeepAliveIdle":100,
"tcpNoDelay":true
}
}
},

{
"tag":"direct",
"protocol":"freedom",
"settings":{"domainStrategy":"UseIp"}
},

{
"tag":"blackhole",
"protocol":"blackhole",
"settings":{}
}
],

"dns":{"servers":["8.8.8.8"]},

"routing":{
"domainStrategy":"UseIp",
"rules":[],
"balancers":[]
}
}'

ALL_OUTPUT=""

while IFS= read -r line; do
    [ -z "$line" ] && continue

    IP=$(echo "$line" | sed -n 's/.*@\([^:]*\):.*/\1/p')
    PORT=$(echo "$line" | sed -n 's/.*:\([0-9]*\)?.*/\1/p')
    PASSWORD=$(echo "$line" | sed -n 's|trojan://\([^@]*\)@.*|\1|p' | sed 's/%.*//')

    PATHWS=$(echo "$line" | sed -n 's/.*path=\([^&]*\).*/\1/p')
    HOST=$(echo "$line" | sed -n 's/.*host=\([^&]*\).*/\1/p')
    SNI=$(echo "$line" | sed -n 's/.*sni=\([^&#]*\).*/\1/p')

    [ -z "$PORT" ] && PORT=443

    OUTPUT="$BASE"

    OUTPUT=$(echo "$OUTPUT" | sed "0,/🌟/s//${IP}/")
    OUTPUT=$(echo "$OUTPUT" | sed "0,/🌟/s//${PASSWORD}/")
    OUTPUT=$(echo "$OUTPUT" | sed "0,/🌟/s//${PATHWS}/")
    OUTPUT=$(echo "$OUTPUT" | sed "0,/🌟/s//${HOST}/")
    OUTPUT=$(echo "$OUTPUT" | sed "0,/🌟/s//${SNI}/")

    echo -e "${GREEN}==============================${NC}"
    echo "$OUTPUT"
    echo

    ALL_OUTPUT+="$OUTPUT
"

done <<< "$INPUT"

# ===== COPY ALL OUTPUT TO CLIPBOARD =====
termux-clipboard-set <<< "$ALL_OUTPUT"

echo -e "${CYAN}DONE ✔ copied all configs to clipboard${NC}"
