#!/data/data/com.termux/files/usr/bin/bash

set -e

echo "======================================"
echo "     SenPaiScanner Installer"
echo "======================================"

echo "[1/7] Updating Termux..."
pkg update -y

echo "[2/7] Installing required packages..."
pkg install -y git golang

echo "[3/7] Checking project..."

if [ ! -d "$HOME/SenPaiScanner/.git" ]; then
    git clone https://github.com/MatinSenPai/SenPaiScanner.git "$HOME/SenPaiScanner"
else
    echo "SenPaiScanner already exists."
fi

echo "[4/7] Configuring Go..."
go env -w GOPROXY=direct
go env -w GOSUMDB=off

echo "[5/7] Downloading Go dependencies..."
cd "$HOME/SenPaiScanner"
go mod download

echo "[6/7] Building SenPaiScanner..."
go build -o "$HOME/SenPaiScanner/senpaiscanner" ./cmd/senpaiscanner
chmod +x "$HOME/SenPaiScanner/senpaiscanner"

echo "[7/7] Installing global senpi command..."

cat > "$PREFIX/bin/senpi" <<'SENPI'
#!/data/data/com.termux/files/usr/bin/bash
exec "$HOME/SenPaiScanner/senpaiscanner" "$@"
SENPI

chmod +x "$PREFIX/bin/senpi"
hash -r

cd "$HOME"

echo
echo "======================================"
echo "       INSTALLATION COMPLETE"
echo "======================================"
echo
echo "SenPaiScanner is ready."
echo
echo "Run from anywhere with:"
echo
echo "    senpi"
echo
echo "======================================"
