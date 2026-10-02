#!/data/data/com.termux/files/usr/bin/python3
# -*- coding: utf-8 -*-

import os, re, json, socket, time, subprocess, base64, yaml
from urllib.parse import unquote, urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed


# ============================================================
# PATHS
# ============================================================

BASE_DIR = "/storage/emulated/0/Download/Akbar98"
os.makedirs(BASE_DIR, exist_ok=True)

INPUT_PATH = os.path.join(BASE_DIR, "input_mobile.txt")

with open(INPUT_PATH, "w", encoding="utf-8") as f:
    f.write("")

try:
    subprocess.call(["nano", INPUT_PATH])
except Exception:
    pass


out_folder = input("Enter output folder name in Download: ").strip()

if not out_folder:
    print("Folder name required.")
    raise SystemExit(1)

OUT_DIR = os.path.join(
    "/storage/emulated/0/Download",
    out_folder
)

os.makedirs(OUT_DIR, exist_ok=True)


out_name = input("Enter output file name (without extension): ").strip()

if not out_name:
    print("File name required.")
    raise SystemExit(1)

OUT_PATH = os.path.join(
    OUT_DIR,
    f"{out_name}.yaml"
)


# ============================================================
# HELPERS
# ============================================================

def b64fix(s):
    if not s:
        return ""

    s = str(s).strip()
    s = s.replace("\n", "")
    s = s.replace(" ", "")
    s = s.replace("-", "+")
    s = s.replace("_", "/")

    pad = len(s) % 4

    if pad:
        s += "=" * (4 - pad)

    return s


def safe_int(x, default=0):
    try:
        return int(x)
    except Exception:
        return default


_used = set()


def uniq_name(x):
    base = re.sub(
        r"[^A-Za-z0-9_\- .\u0600-\u06FF]",
        "",
        x or ""
    )

    if not base:
        base = "Proxy"

    name = base
    i = 2

    while name in _used:
        name = f"{base} {i}"
        i += 1

    _used.add(name)

    return name


def tail(x, n=6):
    s = re.sub(r"-", "", str(x or ""))
    return s[-n:]


# ============================================================
# PING
# ============================================================

def ping_proxy(host, port, attempts=3, timeout=1.5):

    try:
        host_ip = socket.gethostbyname(host)
    except Exception:
        return None

    best = None

    for _ in range(attempts):

        try:
            t0 = time.monotonic()

            s = socket.create_connection(
                (host_ip, int(port)),
                timeout=timeout
            )

            s.close()

            ms = int(
                (time.monotonic() - t0) * 1000
            )

            if best is None or ms < best:
                best = ms

        except Exception:
            pass

    return best


def attach_ping(p):

    p["_ping"] = ping_proxy(
        p["server"],
        p["port"]
    )

    p["_status"] = (
        "ok"
        if p["_ping"] is not None
        else "dead"
    )

    return p


# ============================================================
# FULL PARSER
# ============================================================

def parse_link(line):

    line = line.strip()

    try:

        # ====================================================
        # VLESS
        # ====================================================

        if line.startswith("vless://"):

            parsed = urlparse(line)

            uid = parsed.username or ""
            host = parsed.hostname or ""
            port = parsed.port or 443

            q = parse_qs(parsed.query)

            if not (uid and host and port):
                return None

            net = (
                q.get("type", ["tcp"])[0]
                or "tcp"
            ).lower()

            tls_flag = (
                q.get("security", [""])[0]
                or ""
            ).lower() in ("tls", "reality")

            name = uniq_name(
                f"vless-{host}-{tail(uid)}"
            )

            p = {
                "name": name,
                "type": "vless",
                "server": host,
                "port": port,
                "uuid": uid,
                "encryption": "none",
                "udp": True,
                "network": net
            }

            if net == "ws":

                p["ws-opts"] = {
                    "path": q.get("path", ["/"])[0]
                }

                hosth = (
                    q.get("host", [])
                    or q.get("Host", [])
                )

                if hosth:
                    p["ws-opts"]["headers"] = {
                        "Host": hosth[0]
                    }

            elif net == "grpc":

                svc = q.get(
                    "serviceName",
                    [""]
                )[0]

                if svc:
                    p["grpc-opts"] = {
                        "grpc-service-name": svc
                    }

            if tls_flag:

                sni = (
                    q.get("sni", [])
                    or q.get("servername", [])
                    or [host]
                )

                p["tls"] = True
                p["servername"] = sni[0]

            return p


        # ====================================================
        # VMESS
        # ====================================================

        elif line.startswith("vmess://"):

            payload = line[8:]

            try:
                decoded = base64.b64decode(
                    b64fix(payload)
                ).decode(
                    errors="ignore"
                )

                info = json.loads(decoded)

            except Exception:
                return None

            host = (
                info.get("add")
                or info.get("server")
                or ""
            )

            port = safe_int(
                info.get("port"),
                0
            )

            uid = info.get("id") or ""

            if not (host and port and uid):
                return None

            net = (
                info.get("net")
                or "tcp"
            ).lower()

            tls_flag = (
                str(
                    info.get("tls", "")
                ).lower() == "tls"
            )

            name = uniq_name(
                f"vmess-{host}-{tail(uid)}"
            )

            p = {
                "name": name,
                "type": "vmess",
                "server": host,
                "port": port,
                "uuid": uid,
                "alterId": safe_int(
                    info.get(
                        "aid",
                        info.get(
                            "alterId",
                            0
                        )
                    )
                ),
                "cipher": info.get(
                    "scy",
                    "auto"
                ),
                "udp": True,
                "network": net
            }

            if net == "ws":

                path = (
                    info.get("path")
                    or "/"
                )

                hosth = (
                    info.get("host")
                    or ""
                )

                p["ws-opts"] = {
                    "path": path
                }

                if hosth:
                    p["ws-opts"]["headers"] = {
                        "Host": hosth
                    }

            if tls_flag:

                sni = (
                    info.get("sni")
                    or info.get("host")
                    or host
                )

                p["tls"] = True
                p["servername"] = sni

            return p


        # ====================================================
        # TROJAN
        # ====================================================

        elif line.startswith("trojan://"):

            parsed = urlparse(line)

            pwd = parsed.username or ""
            host = parsed.hostname or ""
            port = parsed.port or 443

            if not (pwd and host and port):
                return None

            q = parse_qs(
                parsed.query
            )

            sni = q.get(
                "sni",
                [host]
            )[0]

            name = uniq_name(
                f"trojan-{host}-{tail(pwd)}"
            )

            p = {
                "name": name,
                "type": "trojan",
                "server": host,
                "port": port,
                "password": pwd,
                "udp": True,
                "network": "tcp",
                "tls": True,
                "sni": sni
            }

            return p


        # ====================================================
        # SHADOWSOCKS
        # ====================================================

        elif line.startswith("ss://"):

            try:

                after = line[5:]

                if (
                    "@" in after
                    and ":" in after.split(
                        "@",
                        1
                    )[0]
                ):

                    cred, rest = after.split(
                        "@",
                        1
                    )

                    method, password = cred.split(
                        ":",
                        1
                    )

                    host, port = rest.split(
                        "#",
                        1
                    )[0].rsplit(
                        ":",
                        1
                    )

                else:

                    b64cred, rest = after.split(
                        "@",
                        1
                    )

                    method_password = (
                        base64.urlsafe_b64decode(
                            b64fix(b64cred)
                        ).decode()
                    )

                    method, password = (
                        method_password.split(
                            ":",
                            1
                        )
                    )

                    host, port = rest.split(
                        "#",
                        1
                    )[0].rsplit(
                        ":",
                        1
                    )

                port = safe_int(port)

                if not (
                    method
                    and password
                    and host
                    and port
                ):
                    return None

                name = uniq_name(
                    f"ss-{host}-{port}"
                )

                p = {
                    "name": name,
                    "type": "ss",
                    "server": host,
                    "port": port,
                    "cipher": method,
                    "password": password,
                    "udp": True
                }

                return p

            except Exception:
                return None


        # ====================================================
        # HYSTERIA
        # ====================================================

        elif line.startswith("hysteria://"):

            parsed = urlparse(line)

            passwd = parsed.password or ""
            host = parsed.hostname or ""
            port = parsed.port or 443

            q = parse_qs(
                parsed.query
            )

            protocol = q.get(
                "protocol",
                ["udp"]
            )[0]

            obfs = q.get(
                "obfs",
                ["none"]
            )[0]

            auth = q.get(
                "auth",
                [""]
            )[0]

            if not (
                host
                and port
                and passwd
            ):
                return None

            name = uniq_name(
                f"hysteria-{host}-{tail(passwd)}"
            )

            p = {
                "name": name,
                "type": "hysteria",
                "server": host,
                "port": port,
                "password": passwd,
                "protocol": protocol,
                "obfs": obfs,
                "auth": auth,
                "udp": True
            }

            return p

    except Exception:
        return None

    return None


# ============================================================
# VALIDATOR
# ============================================================

def validate_proxy(p):

    if not p:
        return False

    if "server" not in p:
        return False

    if "port" not in p:
        return False

    return True


# ============================================================
# LOAD INPUT
# ============================================================

try:

    content = open(
        INPUT_PATH,
        "r",
        encoding="utf-8"
    ).read()

except Exception:

    content = ""


lines = [
    l.strip()
    for l in content.splitlines()
    if l.strip()
]


proxies = []


for line in lines:

    p = parse_link(line)

    if validate_proxy(p):
        proxies.append(p)


if not proxies:

    print(
        "[ERROR] No valid proxies found."
    )

    raise SystemExit(1)


print(
    f"[INFO] Valid proxies found: {len(proxies)}"
)


# ============================================================
# INITIAL PING
#
# این Ping فقط یک بار قبل از خروجی انجام می‌شود.
# هیچ Ping بعد از ساخت YAML وجود ندارد.
# ============================================================

with ThreadPoolExecutor(
    max_workers=20
) as ex:

    futures = [
        ex.submit(
            attach_ping,
            p
        )
        for p in proxies
    ]

    pinged = []

    for future in as_completed(futures):

        try:
            pinged.append(
                future.result()
            )

        except Exception:
            pass


proxies = pinged


# ============================================================
# KEEP ONLY ALIVE PROXIES
# ============================================================

alive = [
    p
    for p in proxies
    if p.get("_status") == "ok"
]


if not alive:

    print(
        "[ERROR] All proxies are dead."
    )

    raise SystemExit(1)


# ============================================================
# SORT BY INITIAL PING
# ============================================================

alive_sorted = sorted(
    alive,
    key=lambda x: x.get(
        "_ping",
        999999
    )
)


print(
    f"[INFO] Alive proxies: {len(alive_sorted)}"
)


# ============================================================
# CLEAN INTERNAL PING DATA
#
# Ping برای فیلتر و مرتب‌سازی استفاده شد.
# داده‌های داخلی Ping وارد YAML نمی‌شوند.
# ============================================================

for p in alive_sorted:

    p.pop("_ping", None)
    p.pop("_status", None)


# ============================================================
# SINGLE STATIC SELECT GROUP
#
# فقط یک گروه.
# بدون url-test
# بدون fallback
# بدون load-balance
# بدون interval
# بدون tolerance
# بدون live ping
# ============================================================

proxy_names = [
    p["name"]
    for p in alive_sorted
]


yaml_data = {

    "proxies": alive_sorted,

    "proxy-groups": [

        {
            "name": "Mobile-Fast❤",
            "type": "select",
            "proxies": proxy_names
        }

    ],

    "rules": [
        "MATCH,Mobile-Fast❤"
    ]
}


# ============================================================
# OUTPUT
# ============================================================

try:

    with open(
        OUT_PATH,
        "w",
        encoding="utf-8"
    ) as f:

        yaml.dump(
            yaml_data,
            f,
            allow_unicode=True,
            sort_keys=False,
            default_flow_style=False
        )

except Exception as e:

    print(
        f"[ERROR] Failed to save YAML: {e}"
    )

    raise SystemExit(1)


# ============================================================
# FINAL REPORT
# ============================================================

print()
print("=" * 60)
print("[DONE] YAML created successfully.")
print("=" * 60)
print(f"Output : {OUT_PATH}")
print(f"Alive  : {len(alive_sorted)}")
print("Group  : Mobile-Fast❤")
print("Type   : select")
print("Groups : 1")
print("Live Ping after output : OFF")
print("URL-Test              : OFF")
print("Fallback              : OFF")
print("Load-Balance          : OFF")
print("=" * 60)
print()
