#!/data/data/com.termux/files/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import re
import json
import socket
import time
import subprocess
import base64
import yaml
import sys

from urllib.parse import urlparse, parse_qs, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed


# ============================================================
# PATHS
# استاندارد ثابت تمام اسکریپت‌ها
# ============================================================

BASE_DIR = "/storage/emulated/0/Download/Akbar98"
os.makedirs(BASE_DIR, exist_ok=True)

INPUT_PATH = os.path.join(BASE_DIR, "input_mobile.txt")


# ============================================================
# INPUT EDITOR
# هر بار اجرا -> فایل ورودی خالی -> باز شدن Nano
# ============================================================

with open(INPUT_PATH, "w", encoding="utf-8") as f:
    f.write("")

try:
    subprocess.call(["nano", INPUT_PATH])
except Exception:
    pass


# ============================================================
# OUTPUT PATH
# ============================================================

out_folder = input(
    "Enter output folder name in Download: "
).strip()

if not out_folder:
    print("Folder name required.")
    sys.exit(1)

OUT_DIR = os.path.join(
    "/storage/emulated/0/Download",
    out_folder
)

os.makedirs(OUT_DIR, exist_ok=True)


out_name = input(
    "Enter output file name (without extension): "
).strip()

if not out_name:
    print("File name required.")
    sys.exit(1)

if out_name.lower().endswith(".yaml"):
    out_name = out_name[:-5]

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
    s = s.replace("\r", "")
    s = s.replace(" ", "")
    s = s.replace("-", "+")
    s = s.replace("_", "/")

    return s + "=" * (-len(s) % 4)


def safe_int(x, default=0):

    try:
        return int(x)

    except Exception:

        try:
            return int(float(x))

        except Exception:
            return default


def sanitize(s):

    if not s:
        return ""

    return re.sub(
        r"[^A-Za-z0-9_\- .\u0600-\u06FF]",
        "",
        str(s)
    ).strip()


_used_names = set()


def uniq_name(base):

    base = sanitize(base)

    if not base:
        base = "Proxy"

    name = base
    i = 2

    while name in _used_names:

        name = f"{base} {i}"
        i += 1

    _used_names.add(name)

    return name


def tail(s, n=6):

    if not s:
        return ""

    s = str(s)
    s = re.sub(r"-", "", s)

    return s[-n:] if len(s) >= n else s


# ============================================================
# PING
# فقط یک بار قبل از ساخت YAML
# هیچ Live/Periodic Ping در YAML وجود ندارد
# ============================================================

def ping_proxy(
    host,
    port,
    attempts=4,
    timeout=2.0
):

    if not host or not port:
        return None

    try:
        host_ip = socket.gethostbyname(host)

    except Exception:
        return None

    results = []

    for _ in range(attempts):

        sock = None

        try:

            start = time.monotonic()

            sock = socket.create_connection(
                (host_ip, int(port)),
                timeout=timeout
            )

            elapsed = int(
                (time.monotonic() - start) * 1000
            )

            results.append(elapsed)

        except Exception:

            results.append(None)

        finally:

            try:

                if sock:
                    sock.close()

            except Exception:
                pass

        time.sleep(0.03)

    valid = [
        x for x in results
        if x is not None
    ]

    if not valid:
        return None

    return min(valid)


def attach_ping(proxy):

    try:

        host = proxy.get("server")
        port = proxy.get("port")

        latency = ping_proxy(
            host,
            port
        )

        proxy["_ping"] = latency

        proxy["_status"] = (
            "ok"
            if latency is not None
            else "dead"
        )

        return proxy

    except Exception:

        proxy["_ping"] = None
        proxy["_status"] = "dead"

        return proxy


# ============================================================
# VLESS
# ============================================================

def parse_vless(line):

    try:

        if not line.lower().startswith("vless://"):
            return None

        raw = line[8:]

        fragment = ""

        if "#" in raw:

            raw, fragment = raw.split(
                "#",
                1
            )

            fragment = unquote(fragment)

        if "?" in raw:

            main, query = raw.split(
                "?",
                1
            )

        else:

            main = raw
            query = ""

        if "@" not in main:
            return None

        uid, rest = main.split(
            "@",
            1
        )

        if ":" in rest:

            host, port = rest.rsplit(
                ":",
                1
            )

        else:

            host = rest
            port = "443"

        host = host.strip()

        if not host or not uid:
            return None

        params = {}

        if query:

            for item in query.split("&"):

                if "=" in item:

                    k, v = item.split(
                        "=",
                        1
                    )

                    params[
                        unquote(k)
                    ] = unquote(v)

        network = (
            params.get("type")
            or params.get("network")
            or "tcp"
        ).lower()

        name = (
            fragment
            or params.get("remark")
            or f"vless-{host}-{tail(uid)}"
        )

        proxy = {

            "name": uniq_name(name),

            "type": "vless",

            "server": host,

            "port": safe_int(
                port,
                443
            ),

            "uuid": uid,

            "encryption": params.get(
                "encryption",
                "none"
            ),

            "network": network,

            "udp": True

        }

        security = (
            params.get(
                "security",
                ""
            ).lower()
        )

        if (
            params.get("tls", "").lower() == "true"
            or security in ("tls", "reality")
        ):

            proxy["tls"] = True

            proxy["servername"] = (
                params.get("sni")
                or params.get("host")
                or host
            )

        if network == "ws":

            ws = {
                "path": params.get(
                    "path",
                    "/"
                )
            }

            ws_host = params.get(
                "host",
                ""
            )

            if ws_host:

                ws["headers"] = {
                    "Host": ws_host
                }

            proxy["ws-opts"] = ws

        if network == "grpc":

            service = (
                params.get("serviceName")
                or params.get("service")
                or ""
            )

            if service:

                proxy["grpc-opts"] = {
                    "grpc-service-name": service
                }

        if (
            security == "reality"
            or params.get("pbk")
            or params.get("sid")
        ):

            proxy["tls"] = True

            proxy["reality-opts"] = {

                "public-key": params.get(
                    "pbk",
                    ""
                ),

                "short-id": params.get(
                    "sid",
                    ""
                ),

                "server-name": params.get(
                    "sni",
                    host
                )

            }

        return proxy

    except Exception:

        return None


# ============================================================
# VMESS
# ============================================================

def parse_vmess(line):

    try:

        if not line.lower().startswith("vmess://"):
            return None

        raw = line[8:].strip()

        js = None

        try:

            decoded = base64.b64decode(
                b64fix(raw)
            ).decode(
                "utf-8",
                "ignore"
            )

            js = json.loads(decoded)

        except Exception:

            try:

                js = json.loads(
                    unquote(raw)
                )

            except Exception:

                return None

        if not isinstance(js, dict):
            return None

        host = (
            js.get("add")
            or js.get("address")
            or js.get("server")
        )

        port = safe_int(
            js.get("port")
            or 0
        )

        uid = (
            js.get("id")
            or js.get("uuid")
        )

        if not host or not port or not uid:
            return None

        network = (
            js.get("net")
            or "tcp"
        ).lower()

        name = (
            js.get("ps")
            or f"vmess-{host}-{tail(uid)}"
        )

        proxy = {

            "name": uniq_name(name),

            "type": "vmess",

            "server": host,

            "port": port,

            "uuid": uid,

            "alterId": safe_int(
                js.get(
                    "aid",
                    js.get(
                        "alterId",
                        0
                    )
                )
            ),

            "cipher": (
                js.get("cipher")
                or js.get("scy")
                or "auto"
            ),

            "network": network,

            "udp": True

        }

        tls_value = str(
            js.get(
                "tls",
                ""
            )
        ).lower()

        if tls_value in (
            "tls",
            "true",
            "1"
        ):

            proxy["tls"] = True

            proxy["servername"] = (
                js.get("sni")
                or js.get("host")
                or host
            )

        if network == "ws":

            ws = {

                "path": js.get(
                    "path",
                    "/"
                )

            }

            ws_host = js.get(
                "host",
                ""
            )

            if ws_host:

                ws["headers"] = {
                    "Host": ws_host
                }

            proxy["ws-opts"] = ws

        if network == "grpc":

            service = (
                js.get("serviceName")
                or ""
            )

            if service:

                proxy["grpc-opts"] = {
                    "grpc-service-name": service
                }

        return proxy

    except Exception:

        return None


# ============================================================
# TROJAN
# ============================================================

def parse_trojan(line):

    try:

        if not line.lower().startswith("trojan://"):
            return None

        parsed = urlparse(line)

        host = parsed.hostname

        if not host:
            return None

        port = (
            parsed.port
            or 443
        )

        password = (
            parsed.username
            or ""
        )

        fragment = unquote(
            parsed.fragment
            or ""
        )

        query = parse_qs(
            parsed.query
        )

        name = (
            fragment
            or f"trojan-{host}"
        )

        proxy = {

            "name": uniq_name(name),

            "type": "trojan",

            "server": host,

            "port": port,

            "password": password,

            "udp": True,

            "network": "tcp",

            "tls": True,

            "sni": (
                query.get(
                    "sni",
                    [host]
                )[0]
            )

        }

        network = query.get(
            "type",
            ["tcp"]
        )[0].lower()

        if network == "ws":

            proxy["network"] = "ws"

            proxy["ws-opts"] = {

                "path": query.get(
                    "path",
                    ["/"]
                )[0],

                "headers": {

                    "Host": query.get(
                        "host",
                        [host]
                    )[0]

                }

            }

        return proxy

    except Exception:

        return None


# ============================================================
# SHADOWSOCKS
# ============================================================

def parse_ss(line):

    try:

        if not line.lower().startswith("ss://"):
            return None

        body = line[5:]

        fragment = ""

        if "#" in body:

            body, fragment = body.split(
                "#",
                1
            )

            fragment = unquote(
                fragment
            )

        method = None
        password = None
        host = None
        port = None

        if "@" in body:

            creds, hostport = body.split(
                "@",
                1
            )

            try:

                decoded = base64.b64decode(
                    b64fix(creds)
                ).decode(
                    "utf-8",
                    "ignore"
                )

                if ":" in decoded:

                    method, password = decoded.split(
                        ":",
                        1
                    )

            except Exception:
                pass

            if not method:

                if ":" not in creds:
                    return None

                method, password = creds.split(
                    ":",
                    1
                )

            if ":" in hostport:

                host, port = hostport.rsplit(
                    ":",
                    1
                )

        else:

            decoded = base64.b64decode(
                b64fix(body)
            ).decode(
                "utf-8",
                "ignore"
            )

            pre, addr = decoded.split(
                "@",
                1
            )

            method, password = pre.split(
                ":",
                1
            )

            host, port = addr.rsplit(
                ":",
                1
            )

        if not host or not method or not password:
            return None

        proxy = {

            "name": uniq_name(
                fragment
                or f"ss-{host}-{port}"
            ),

            "type": "ss",

            "server": host,

            "port": safe_int(port),

            "cipher": method,

            "password": password,

            "udp": True

        }

        return proxy

    except Exception:

        return None


# ============================================================
# SSR
# ============================================================

def parse_ssr(line):

    try:

        if not line.lower().startswith("ssr://"):
            return None

        raw = line[6:]

        decoded = base64.b64decode(
            b64fix(raw)
        ).decode(
            "utf-8",
            "ignore"
        )

        main = decoded
        params = ""

        if "/?" in decoded:

            main, params = decoded.split(
                "/?",
                1
            )

        parts = main.split(":")

        if len(parts) < 6:
            return None

        host = parts[0]
        port = safe_int(parts[1])
        protocol = parts[2]
        method = parts[3]
        obfs = parts[4]
        password_encoded = parts[5]

        try:

            password = base64.b64decode(
                b64fix(
                    password_encoded
                )
            ).decode(
                "utf-8",
                "ignore"
            )

        except Exception:

            password = password_encoded

        if not host or not port or not password:
            return None

        remarks = ""

        if params:

            q = parse_qs(params)

            if "remarks" in q:

                try:

                    remarks = base64.b64decode(
                        b64fix(
                            q["remarks"][0]
                        )
                    ).decode(
                        "utf-8",
                        "ignore"
                    )

                except Exception:

                    remarks = q["remarks"][0]

        proxy = {

            "name": uniq_name(
                remarks
                or f"ssr-{host}-{port}"
            ),

            "type": "ssr",

            "server": host,

            "port": port,

            "protocol": protocol,

            "cipher": method,

            "obfs": obfs,

            "password": password,

            "udp": True

        }

        return proxy

    except Exception:

        return None


# ============================================================
# HYSTERIA
# ============================================================

def parse_hysteria1(line):

    try:

        if not line.lower().startswith(
            "hysteria://"
        ):
            return None

        raw = line[
            len("hysteria://"):
        ]

        fragment = ""

        if "#" in raw:

            raw, fragment = raw.split(
                "#",
                1
            )

            fragment = unquote(
                fragment
            )

        if "?" in raw:

            main, query = raw.split(
                "?",
                1
            )

        else:

            main = raw
            query = ""

        hostport = main

        if "@" in main:

            auth, hostport = main.split(
                "@",
                1
            )

        else:

            auth = ""

        if ":" in hostport:

            host, port = hostport.rsplit(
                ":",
                1
            )

        else:

            host = hostport
            port = "443"

        params = {}

        if query:

            for item in query.split("&"):

                if "=" in item:

                    k, v = item.split(
                        "=",
                        1
                    )

                    params[
                        unquote(k)
                    ] = unquote(v)

        proxy = {

            "name": uniq_name(
                fragment
                or f"hysteria-{host}-{port}"
            ),

            "type": "hysteria",

            "server": host,

            "port": safe_int(
                port,
                443
            ),

            "auth": auth,

            "protocol": params.get(
                "protocol",
                "udp"
            ),

            "obfs": params.get(
                "obfs",
                ""
            ),

            "tls": (
                params.get(
                    "tls",
                    "true"
                ).lower()
                == "true"
            ),

            "udp": True

        }

        return proxy

    except Exception:

        return None


def parse_hysteria2(line):

    try:

        if line.lower().startswith(
            "hysteria2://"
        ):

            raw = line[
                len("hysteria2://"):
            ]

        elif line.lower().startswith(
            "hy2://"
        ):

            raw = line[
                len("hy2://"):
            ]

        else:

            return None

        fragment = ""

        if "#" in raw:

            raw, fragment = raw.split(
                "#",
                1
            )

            fragment = unquote(
                fragment
            )

        if "?" in raw:

            main, query = raw.split(
                "?",
                1
            )

        else:

            main = raw
            query = ""

        if "@" in main:

            password, hostport = main.split(
                "@",
                1
            )

        else:

            password = ""
            hostport = main

        if ":" in hostport:

            host, port = hostport.rsplit(
                ":",
                1
            )

        else:

            host = hostport
            port = "443"

        params = {}

        if query:

            for item in query.split("&"):

                if "=" in item:

                    k, v = item.split(
                        "=",
                        1
                    )

                    params[
                        unquote(k)
                    ] = unquote(v)

        proxy = {

            "name": uniq_name(
                fragment
                or f"hysteria2-{host}-{port}"
            ),

            "type": "hysteria2",

            "server": host,

            "port": safe_int(
                port,
                443
            ),

            "password": password,

            "sni": params.get(
                "sni",
                host
            ),

            "udp": True

        }

        if params.get("alpn"):

            proxy["alpn"] = params[
                "alpn"
            ].split(",")

        return proxy

    except Exception:

        return None


# ============================================================
# TUIC
# ============================================================

def parse_tuic(line):

    try:

        if not line.lower().startswith(
            "tuic://"
        ):
            return None

        raw = line[
            len("tuic://"):
        ]

        fragment = ""

        if "#" in raw:

            raw, fragment = raw.split(
                "#",
                1
            )

            fragment = unquote(
                fragment
            )

        if "?" in raw:

            main, query = raw.split(
                "?",
                1
            )

        else:

            main = raw
            query = ""

        if "@" not in main:
            return None

        credentials, hostport = main.split(
            "@",
            1
        )

        if ":" in credentials:

            uuid, password = credentials.split(
                ":",
                1
            )

        else:

            uuid = credentials
            password = ""

        if ":" in hostport:

            host, port = hostport.rsplit(
                ":",
                1
            )

        else:

            host = hostport
            port = "443"

        params = {}

        if query:

            for item in query.split("&"):

                if "=" in item:

                    k, v = item.split(
                        "=",
                        1
                    )

                    params[
                        unquote(k)
                    ] = unquote(v)

        proxy = {

            "name": uniq_name(
                fragment
                or f"tuic-{host}-{port}"
            ),

            "type": "tuic",

            "server": host,

            "port": safe_int(
                port,
                443
            ),

            "uuid": uuid,

            "password": password,

            "congestion-controller": params.get(
                "congestion_control",
                params.get(
                    "congestion",
                    "bbr"
                )
            ),

            "udp": True

        }

        if params.get("alpn"):

            proxy["alpn"] = params[
                "alpn"
            ].split(",")

        if params.get("sni"):

            proxy["sni"] = params[
                "sni"
            ]

        return proxy

    except Exception:

        return None


# ============================================================
# WIREGUARD
# ============================================================

def parse_wireguard(line):

    try:

        if not line.lower().startswith(
            "wg://"
        ):
            return None

        parsed = urlparse(line)

        host = parsed.hostname

        if not host:
            return None

        port = (
            parsed.port
            or 51820
        )

        query = parse_qs(
            parsed.query
        )

        fragment = unquote(
            parsed.fragment
            or ""
        )

        public_key = (
            parsed.username
            or ""
        )

        private_key = query.get(
            "privateKey",
            [""]
        )[0]

        address = query.get(
            "address",
            [""]
        )[0]

        proxy = {

            "name": uniq_name(
                fragment
                or f"wireguard-{host}"
            ),

            "type": "wireguard",

            "server": host,

            "port": port,

            "public_key": public_key,

            "private_key": private_key,

            "address": address,

            "udp": True

        }

        return proxy

    except Exception:

        return None


# ============================================================
# HTTP
# ============================================================

def parse_http(line):

    try:

        if not (
            line.lower().startswith(
                "http://"
            )
            or line.lower().startswith(
                "https://"
            )
        ):
            return None

        parsed = urlparse(line)

        host = parsed.hostname

        if not host:
            return None

        port = (
            parsed.port
            or (
                443
                if parsed.scheme.lower() == "https"
                else 80
            )
        )

        username = (
            parsed.username
            or ""
        )

        password = (
            parsed.password
            or ""
        )

        fragment = unquote(
            parsed.fragment
            or ""
        )

        return {

            "name": uniq_name(
                fragment
                or f"http-{host}-{port}"
            ),

            "type": "http",

            "server": host,

            "port": port,

            "username": username,

            "password": password

        }

    except Exception:

        return None


# ============================================================
# SOCKS
# ============================================================

def parse_socks(line):

    try:

        if not (
            line.lower().startswith(
                "socks://"
            )
            or line.lower().startswith(
                "socks5://"
            )
        ):
            return None

        parsed = urlparse(line)

        host = parsed.hostname

        if not host:
            return None

        port = parsed.port

        if not port:
            return None

        username = (
            parsed.username
            or ""
        )

        password = (
            parsed.password
            or ""
        )

        fragment = unquote(
            parsed.fragment
            or ""
        )

        return {

            "name": uniq_name(
                fragment
                or f"socks-{host}-{port}"
            ),

            "type": "socks",

            "server": host,

            "port": port,

            "username": username,

            "password": password

        }

    except Exception:

        return None


# ============================================================
# LINE PARSER
# ============================================================

def parse_line_any(line):

    line = line.strip()

    if not line:
        return None

    parsers = [

        parse_vless,

        parse_vmess,

        parse_trojan,

        parse_ss,

        parse_ssr,

        parse_hysteria1,

        parse_hysteria2,

        parse_tuic,

        parse_wireguard,

        parse_http,

        parse_socks

    ]

    for parser in parsers:

        try:

            result = parser(line)

            if result:
                return result

        except Exception:
            continue

    return None


# ============================================================
# PARSE ALL INPUT
# ============================================================

def parse_any(input_data):

    proxies = []

    for line in input_data.splitlines():

        line = line.strip()

        if not line:
            continue

        if line.startswith("#"):
            continue

        proxy = parse_line_any(
            line
        )

        if proxy:

            proxies.append(
                proxy
            )

    return proxies


# ============================================================
# VALIDATE
# ============================================================

def validate_proxy(proxy):

    if not isinstance(
        proxy,
        dict
    ):
        return False

    proxy_type = str(
        proxy.get(
            "type",
            ""
        )
    ).lower()

    server = proxy.get(
        "server"
    )

    port = safe_int(
        proxy.get(
            "port",
            0
        )
    )

    if not proxy_type:
        return False

    if not server:
        return False

    if not (
        1 <= port <= 65535
    ):
        return False

    if proxy_type in (
        "vless",
        "vmess"
    ):

        if not proxy.get(
            "uuid"
        ):
            return False

    elif proxy_type == "trojan":

        if not proxy.get(
            "password"
        ):
            return False

    elif proxy_type == "ss":

        if not proxy.get(
            "cipher"
        ):
            return False

        if not proxy.get(
            "password"
        ):
            return False

    elif proxy_type == "ssr":

        if not proxy.get(
            "password"
        ):
            return False

    elif proxy_type == "tuic":

        if not proxy.get(
            "uuid"
        ):
            return False

        if not proxy.get(
            "password"
        ):
            return False

    return True


# ============================================================
# DEDUPE
# ============================================================

def dedupe_proxies(proxies):

    result = []
    seen = set()

    for proxy in proxies:

        if not isinstance(
            proxy,
            dict
        ):
            continue

        key = (

            proxy.get("type"),

            proxy.get("server"),

            safe_int(
                proxy.get("port")
            ),

            proxy.get("uuid")
            or proxy.get("password")
            or proxy.get("cipher")
            or ""

        )

        if key in seen:
            continue

        seen.add(key)

        result.append(
            proxy
        )

    return result


# ============================================================
# CLASH META CONVERSION
# ============================================================

def to_clash_meta(proxy):

    proxy_type = str(
        proxy.get(
            "type",
            ""
        )
    ).lower()

    meta = {

        "name": proxy.get(
            "name"
        ),

        "type": proxy_type,

        "server": proxy.get(
            "server"
        ),

        "port": safe_int(
            proxy.get(
                "port"
            )
        )

    }

    if proxy_type == "vless":

        meta["uuid"] = proxy.get(
            "uuid"
        )

        meta["encryption"] = proxy.get(
            "encryption",
            "none"
        )

        if proxy.get("network"):
            meta["network"] = proxy[
                "network"
            ]

        if proxy.get("tls"):
            meta["tls"] = True

        if proxy.get(
            "servername"
        ):
            meta["servername"] = proxy[
                "servername"
            ]

        if proxy.get(
            "ws-opts"
        ):
            meta["ws-opts"] = proxy[
                "ws-opts"
            ]

        if proxy.get(
            "grpc-opts"
        ):
            meta["grpc-opts"] = proxy[
                "grpc-opts"
            ]

        if proxy.get(
            "reality-opts"
        ):
            meta["reality-opts"] = proxy[
                "reality-opts"
            ]

        meta["udp"] = True

    elif proxy_type == "vmess":

        meta["uuid"] = proxy.get(
            "uuid"
        )

        meta["alterId"] = safe_int(
            proxy.get(
                "alterId",
                0
            )
        )

        meta["cipher"] = proxy.get(
            "cipher",
            "auto"
        )

        if proxy.get("network"):
            meta["network"] = proxy[
                "network"
            ]

        if proxy.get("tls"):
            meta["tls"] = True

        if proxy.get(
            "servername"
        ):
            meta["servername"] = proxy[
                "servername"
            ]

        if proxy.get(
            "ws-opts"
        ):
            meta["ws-opts"] = proxy[
                "ws-opts"
            ]

        if proxy.get(
            "grpc-opts"
        ):
            meta["grpc-opts"] = proxy[
                "grpc-opts"
            ]

        meta["udp"] = True

    elif proxy_type == "trojan":

        meta["password"] = proxy.get(
            "password"
        )

        meta["tls"] = True

        if proxy.get("sni"):
            meta["sni"] = proxy[
                "sni"
            ]

        if proxy.get("network"):
            meta["network"] = proxy[
                "network"
            ]

        if proxy.get(
            "ws-opts"
        ):
            meta["ws-opts"] = proxy[
                "ws-opts"
            ]

        meta["udp"] = True

    elif proxy_type == "ss":

        meta["cipher"] = proxy.get(
            "cipher"
        )

        meta["password"] = proxy.get(
            "password"
        )

        meta["udp"] = True

    elif proxy_type == "ssr":

        meta["cipher"] = proxy.get(
            "cipher"
        )

        meta["password"] = proxy.get(
            "password"
        )

        meta["protocol"] = proxy.get(
            "protocol"
        )

        meta["obfs"] = proxy.get(
            "obfs"
        )

        meta["udp"] = True

    elif proxy_type == "hysteria":

        if proxy.get("auth"):
            meta["auth"] = proxy[
                "auth"
            ]

        if proxy.get("protocol"):
            meta["protocol"] = proxy[
                "protocol"
            ]

        if proxy.get("obfs"):
            meta["obfs"] = proxy[
                "obfs"
            ]

        if proxy.get("tls") is not None:
            meta["tls"] = proxy[
                "tls"
            ]

        if proxy.get("sni"):
            meta["sni"] = proxy[
                "sni"
            ]

        meta["udp"] = True

    elif proxy_type == "hysteria2":

        if proxy.get("password"):
            meta["password"] = proxy[
                "password"
            ]

        if proxy.get("sni"):
            meta["sni"] = proxy[
                "sni"
            ]

        if proxy.get("alpn"):
            meta["alpn"] = proxy[
                "alpn"
            ]

        meta["udp"] = True

    elif proxy_type == "tuic":

        meta["uuid"] = proxy.get(
            "uuid"
        )

        meta["password"] = proxy.get(
            "password"
        )

        if proxy.get(
            "congestion-controller"
        ):
            meta[
                "congestion-controller"
            ] = proxy[
                "congestion-controller"
            ]

        if proxy.get("alpn"):
            meta["alpn"] = proxy[
                "alpn"
            ]

        if proxy.get("sni"):
            meta["sni"] = proxy[
                "sni"
            ]

        meta["udp"] = True

    elif proxy_type == "wireguard":

        if proxy.get(
            "public_key"
        ):
            meta["public-key"] = proxy[
                "public_key"
            ]

        if proxy.get(
            "private_key"
        ):
            meta["private-key"] = proxy[
                "private_key"
            ]

        if proxy.get("address"):
            meta["ip"] = proxy[
                "address"
            ]

    elif proxy_type == "http":

        if proxy.get("username"):
            meta["username"] = proxy[
                "username"
            ]

        if proxy.get("password"):
            meta["password"] = proxy[
                "password"
            ]

    elif proxy_type == "socks":

        meta["type"] = "socks5"

        if proxy.get("username"):
            meta["username"] = proxy[
                "username"
            ]

        if proxy.get("password"):
            meta["password"] = proxy[
                "password"
            ]

    else:

        return None

    return meta


# ============================================================
# GENERATE YAML
# ============================================================

def generate_clash_meta_yaml(
    input_text,
    out_path
):

    print()
    print("[INFO] Parsing input...")

    parsed = parse_any(
        input_text
    )

    if not parsed:

        print(
            "[ERROR] No proxies parsed."
        )

        return False

    print(
        f"[INFO] Parsed: {len(parsed)}"
    )

    parsed = dedupe_proxies(
        parsed
    )

    print(
        f"[INFO] Unique: {len(parsed)}"
    )

    parsed = [

        p for p in parsed

        if validate_proxy(p)

    ]

    if not parsed:

        print(
            "[ERROR] No valid proxies."
        )

        return False

    print(
        f"[INFO] Valid: {len(parsed)}"
    )

    # ========================================================
    # INITIAL PING ONLY
    # ========================================================

    print()
    print(
        "[INFO] Measuring initial TCP ping..."
    )

    workers = min(
        40,
        max(
            1,
            len(parsed)
        )
    )

    alive = []

    with ThreadPoolExecutor(
        max_workers=workers
    ) as executor:

        futures = [

            executor.submit(
                attach_ping,
                proxy
            )

            for proxy in parsed

        ]

        for future in as_completed(
            futures
        ):

            try:

                proxy = future.result()

                if (
                    proxy
                    and proxy.get(
                        "_status"
                    ) == "ok"
                ):

                    alive.append(
                        proxy
                    )

            except Exception:
                pass

    if not alive:

        print()
        print(
            "[ERROR] No alive proxies after initial ping."
        )

        return False

    # مرتب‌سازی بر اساس پینگ اولیه
    alive.sort(
        key=lambda x: (
            x.get(
                "_ping"
            )
            if x.get("_ping")
            is not None
            else 999999
        )
    )

    print(
        f"[INFO] Alive: {len(alive)}"
    )

    # ========================================================
    # CONVERT
    # ========================================================

    clash_proxies = []

    for proxy in alive:

        meta = to_clash_meta(
            proxy
        )

        if meta:

            clash_proxies.append(
                meta
            )

    if not clash_proxies:

        print(
            "[ERROR] No Clash Meta compatible proxies."
        )

        return False

    # ========================================================
    # FINAL DEDUPE
    # ========================================================

    final_proxies = []

    seen = set()

    for proxy in clash_proxies:

        key = (

            proxy.get("type"),

            proxy.get("server"),

            safe_int(
                proxy.get("port")
            ),

            proxy.get("uuid")
            or proxy.get("password")
            or ""

        )

        if key in seen:
            continue

        seen.add(key)

        final_proxies.append(
            proxy
        )

    clash_proxies = final_proxies

    if not clash_proxies:

        print(
            "[ERROR] Final proxy list is empty."
        )

        return False

    proxy_names = [

        proxy["name"]

        for proxy in clash_proxies

        if proxy.get("name")

    ]

    if not proxy_names:

        print(
            "[ERROR] No proxy names available."
        )

        return False

    # ========================================================
    # EXACTLY ONE GROUP
    #
    # بدون URL-TEST
    # بدون FALLBACK
    # بدون LOAD-BALANCE
    # بدون AUTO GROUP
    # بدون LIVE PING
    # بدون INTERVAL
    # بدون TOLERANCE
    # ========================================================

    GROUP_NAME = "Mobile-Fast❤"

    config = {

        "proxies": clash_proxies,

        "proxy-groups": [

            {

                "name": GROUP_NAME,

                "type": "select",

                "proxies": proxy_names

            }

        ],

        "rules": [

            f"MATCH,{GROUP_NAME}"

        ]

    }

    # ========================================================
    # SAVE YAML
    # همان OUT_PATH که در ابتدای برنامه ساخته شد
    # ========================================================

    try:

        with open(
            out_path,
            "w",
            encoding="utf-8"
        ) as f:

            yaml.safe_dump(
                config,
                f,
                allow_unicode=True,
                sort_keys=False
            )

    except Exception as e:

        print(
            f"[ERROR] Failed to save YAML: {e}"
        )

        return False

    # ========================================================
    # REPORT
    # ========================================================

    print()
    print("=" * 60)
    print(
        "[DONE] Clash Meta YAML saved successfully."
    )
    print("=" * 60)
    print(
        f"Input  : {INPUT_PATH}"
    )
    print(
        f"Output : {out_path}"
    )
    print(
        f"Alive  : {len(clash_proxies)}"
    )
    print(
        f"Group  : {GROUP_NAME}"
    )
    print(
        "Type   : select"
    )
    print(
        "Groups : 1"
    )
    print(
        "Initial Ping : ON"
    )
    print(
        "Live Ping    : OFF"
    )
    print(
        "URL-Test     : OFF"
    )
    print(
        "Fallback     : OFF"
    )
    print(
        "Load-Balance : OFF"
    )
    print("=" * 60)
    print()

    return True


# ============================================================
# MAIN
#
# فقط INPUT_PATH
# هیچ sys.stdin
# هیچ argv
# هیچ ورودی دوم
# ============================================================

if __name__ == "__main__":

    try:

        with open(
            INPUT_PATH,
            "r",
            encoding="utf-8"
        ) as f:

            text = f.read()

    except Exception as e:

        print(
            f"[ERROR] Cannot read input file: {e}"
        )

        sys.exit(1)

    if not text.strip():

        print()
        print(
            "[ERROR] No input found."
        )
        print(
            f"Input file: {INPUT_PATH}"
        )
        print()

        sys.exit(1)

    success = generate_clash_meta_yaml(
        text,
        OUT_PATH
    )

    if not success:

        print(
            "[ERROR] Script finished without creating YAML."
        )

        sys.exit(1)

    print(
        "[OK] Script completed successfully."
    )
