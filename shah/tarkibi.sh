#!/data/data/com.termux/files/usr/bin/bash

CYAN='\033[1;36m'
GREEN='\033[1;32m'
NC='\033[0m'

clear
echo -e "${CYAN}=== CUSTOM CONFIG GENERATOR ===${NC}"
echo

# ---- INPUTS ----
read -r -p "NAME (remarks): " REMARKS
read -r -p "IP / ADDRESS: " IP

# PORT with default 443
read -r -p "PORT (default 443): " PORT
PORT=${PORT:-443}

read -r -p "PASSWORD: " PASSWORD
read -r -p "HOST: " HOST
read -r -p "SNI: " SNI
read -r -p "PATH: " PATHWS

echo
echo -e "${GREEN}=== GENERATED CONFIG ===${NC}"
echo

# ---- OUTPUT + COPY ----
cat <<EOF | tee >(termux-clipboard-set)
{
"remarks": "$REMARKS",

"log": {
"access": "",
"error": "",
"loglevel": "info",
"dnsLog": false
},

"inbounds": [
{
"tag": "in_proxy",
"port": 1080,
"protocol": "socks",
"listen": "0.0.0.0",
"settings": {
"auth": "noauth",
"udp": true,
"userLevel": 8
},
"sniffing": {
"enabled": false
}
},
{
"tag": "http-in",
"port": 10808,
"listen": "::",
"protocol": "http"
}
],

"outbounds": [
{
"tag": "proxy",
"protocol": "trojan",
"settings": {
"servers": [
{
"address": "$IP",
"port": $PORT,
"password": "$PASSWORD",
"level": 8
}
]
},
"streamSettings": {
"network": "ws",
"security": "tls",
"wsSettings": {
"path": "$PATHWS",
"headers": {
"Host": "$HOST"
}
},
"tlsSettings": {
"allowInsecure": true,
"serverName": "$SNI",
"alpn": ["http/1.1"],
"fingerprint": "ios"
}
},
"mux": {
"enabled": false,
"concurrency": 8
}
}
],

"dns": {
"servers": ["8.8.8.8"]
},

"routing": {
"domainStrategy": "UseIp",
"rules": []
}
}
EOF

echo
echo -e "${GREEN}✔ CONFIG GENERATED + COPIED TO CLIPBOARD${NC}"

