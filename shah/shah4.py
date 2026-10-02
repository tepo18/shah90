#!/data/data/com.termux/files/usr/bin/python3
# -*- coding: utf-8 -*-

"""
============================================================
Akbar98 - Advanced Xray/V2Ray -> Mihomo/Clash Meta Converter
============================================================

Supported:
    VLESS
    VMess
    Trojan
    Shadowsocks
    ShadowsocksR
    Hysteria
    Hysteria2
    TUIC
    WireGuard

Transports:
    TCP
    WS
    gRPC
    HTTP
    HTTPUpgrade where available

TLS:
    TLS
    Reality
    SNI
    ALPN
    client fingerprint
    Reality public-key
    Reality short-id
    flow

Features:
    URL decoding
    Base64 decoding
    remark decoding
    duplicate-safe names
    TCP reachability test
    sorted output
    Mihomo YAML
    select group
    url-test group
    DNS configuration
    profile persistence

IMPORTANT:
    TCP ping is NOT a real proxy health check.
    Mihomo url-test performs the real latency check after loading.
============================================================
"""

import os
import re
import json
import socket
import time
import base64
import subprocess
from urllib.parse import (
    urlparse,
    parse_qs,
    unquote,
    quote,
)

try:
    import yaml
except ImportError:
    print("[ERROR] PyYAML is not installed.")
    print("Install:")
    print("pip install pyyaml")
    raise SystemExit(1)


# ============================================================
# PATHS
# ============================================================

BASE_DIR = "/storage/emulated/0/Download/Akbar98"

os.makedirs(BASE_DIR, exist_ok=True)

INPUT_PATH = os.path.join(
    BASE_DIR,
    "input_mobile.txt"
)


# ============================================================
# CREATE / OPEN INPUT
# ============================================================

try:
    with open(
        INPUT_PATH,
        "w",
        encoding="utf-8"
    ) as f:
        f.write("")
except Exception as e:
    print(f"[ERROR] Cannot create input file: {e}")
    raise SystemExit(1)


try:
    subprocess.call(
        ["nano", INPUT_PATH]
    )
except Exception:
    print(
        "[WARN] nano unavailable. "
        "Edit input_mobile.txt manually."
    )


# ============================================================
# OUTPUT SETTINGS
# ============================================================

out_folder = input(
    "Enter output folder name in Download: "
).strip()

if not out_folder:
    print("Folder name required.")
    raise SystemExit(1)


OUT_DIR = os.path.join(
    "/storage/emulated/0/Download",
    out_folder
)

os.makedirs(
    OUT_DIR,
    exist_ok=True
)


out_name = input(
    "Enter output file name (without extension): "
).strip()

if not out_name:
    print("File name required.")
    raise SystemExit(1)


OUT_PATH = os.path.join(
    OUT_DIR,
    f"{out_name}.yaml"
)


# ============================================================
# OPTIONS
# ============================================================

print()
print("============================================================")
print("Converter options")
print("============================================================")

enable_tcp_test = input(
    "TCP reachability test? [Y/n]: "
).strip().lower()

enable_tcp_test = (
    enable_tcp_test != "n"
)

enable_auto_test = input(
    "Create Mihomo url-test group? [Y/n]: "
).strip().lower()

enable_auto_test = (
    enable_auto_test != "n"
)

enable_dns = input(
    "Add DNS configuration? [Y/n]: "
).strip().lower()

enable_dns = (
    enable_dns != "n"
)

print()


# ============================================================
# CONSTANTS
# ============================================================

TCP_TIMEOUT = 2.5
TCP_ATTEMPTS = 2

MAX_WORKERS = 20

HEALTH_URL = (
    "https://www.gstatic.com/generate_204"
)

HEALTH_INTERVAL = 300

HEALTH_TIMEOUT = 5000

GROUP_NAME = "Mobile-Fast❤"

AUTO_GROUP_NAME = "Mobile-Auto❤"


# ============================================================
# GLOBALS
# ============================================================

_used_names = set()


# ============================================================
# BASIC HELPERS
# ============================================================

def clean_text(value):
    if value is None:
        return ""

    return unquote(
        str(value)
    ).strip()


def first(q, key, default=""):
    try:
        values = q.get(key)

        if values:
            return clean_text(
                values[0]
            )
    except Exception:
        pass

    return default


def first_any(
    q,
    keys,
    default=""
):
    for key in keys:
        value = first(
            q,
            key,
            ""
        )

        if value:
            return value

    return default


def safe_int(
    value,
    default=0
):
    try:
        return int(
            str(value).strip()
        )
    except Exception:
        return default


def safe_float(
    value,
    default=0.0
):
    try:
        return float(value)
    except Exception:
        return default


def bool_value(
    value,
    default=False
):
    if value is None:
        return default

    s = str(value).strip().lower()

    if s in (
        "1",
        "true",
        "yes",
        "on",
    ):
        return True

    if s in (
        "0",
        "false",
        "no",
        "off",
    ):
        return False

    return default


# ============================================================
# BASE64
# ============================================================

def b64fix(value):
    if not value:
        return ""

    value = str(value).strip()

    value = re.sub(
        r"\s+",
        "",
        value
    )

    value = value.replace(
        "-",
        "+"
    )

    value = value.replace(
        "_",
        "/"
    )

    value += "=" * (
        (-len(value)) % 4
    )

    return value


def b64decode_text(value):
    try:
        return base64.b64decode(
            b64fix(value)
        ).decode(
            "utf-8",
            errors="ignore"
        )
    except Exception:
        return ""


def b64decode_urlsafe(value):
    try:
        return base64.urlsafe_b64decode(
            b64fix(value)
        ).decode(
            "utf-8",
            errors="ignore"
        )
    except Exception:
        return ""


# ============================================================
# NAME
# ============================================================

def sanitize_name(value):

    value = clean_text(
        value
    )

    value = re.sub(
        r"[\x00-\x1F\x7F]",
        "",
        value
    )

    value = re.sub(
        r"[\\/:*?\"<>|]",
        "",
        value
    )

    value = value.strip()

    if not value:
        value = "Proxy"

    return value[:100]


def uniq_name(value):

    base = sanitize_name(
        value
    )

    if not base:
        base = "Proxy"

    name = base

    counter = 2

    while name in _used_names:

        name = (
            f"{base} {counter}"
        )

        counter += 1

    _used_names.add(
        name
    )

    return name


def remark_from_url(parsed):

    try:
        fragment = parsed.fragment

        if fragment:
            return sanitize_name(
                unquote(fragment)
            )
    except Exception:
        pass

    return ""


def make_name(
    protocol,
    host,
    port,
    remark=""
):

    if remark:
        return uniq_name(
            remark
        )

    return uniq_name(
        f"{protocol}-{host}-{port}"
    )


# ============================================================
# QUERY NORMALIZATION
# ============================================================

def normalize_query(q):

    result = {}

    for key, values in q.items():

        if not values:
            continue

        result[key] = [
            clean_text(v)
            for v in values
        ]

    return result


# ============================================================
# ALPN
# ============================================================

def parse_alpn(value):

    if not value:
        return None

    value = clean_text(
        value
    )

    if not value:
        return None

    parts = re.split(
        r"[,|]",
        value
    )

    parts = [
        x.strip()
        for x in parts
        if x.strip()
    ]

    return parts or None


# ============================================================
# TLS COMMON
# ============================================================

def apply_tls_common(
    p,
    q,
    host,
    force_tls=False
):

    security = first_any(
        q,
        [
            "security",
            "tls"
        ],
        ""
    ).lower()

    tls_enabled = (
        force_tls
        or security == "tls"
        or security == "reality"
        or bool_value(
            first(
                q,
                "tls",
                ""
            )
        )
    )

    if tls_enabled:

        p["tls"] = True

        sni = first_any(
            q,
            [
                "sni",
                "servername",
                "serverName"
            ],
            host
        )

        if sni:
            p["servername"] = sni

    fp = first_any(
        q,
        [
            "fp",
            "fingerprint",
            "clientFingerprint"
        ],
        ""
    )

    if fp:
        p[
            "client-fingerprint"
        ] = fp

    alpn = first(
        q,
        "alpn",
        ""
    )

    parsed_alpn = parse_alpn(
        alpn
    )

    if parsed_alpn:
        p["alpn"] = parsed_alpn

    skip_verify = first_any(
        q,
        [
            "allowInsecure",
            "allowinsecure",
            "skip-cert-verify"
        ],
        ""
    )

    if skip_verify != "":
        p[
            "skip-cert-verify"
        ] = bool_value(
            skip_verify
        )


# ============================================================
# REALITY
# ============================================================

def apply_reality(
    p,
    q
):

    security = first(
        q,
        "security",
        ""
    ).lower()

    reality = (
        security == "reality"
        or bool_value(
            first(
                q,
                "reality",
                ""
            )
        )
    )

    if not reality:
        return

    p["tls"] = True

    public_key = first_any(
        q,
        [
            "pbk",
            "publicKey",
            "public-key"
        ],
        ""
    )

    short_id = first_any(
        q,
        [
            "sid",
            "shortId",
            "short-id"
        ],
        ""
    )

    reality_opts = {}

    if public_key:
        reality_opts[
            "public-key"
        ] = public_key

    if short_id:
        reality_opts[
            "short-id"
        ] = short_id

    # Mihomo supports reality-opts.
    if reality_opts:
        p[
            "reality-opts"
        ] = reality_opts


# ============================================================
# FLOW
# ============================================================

def apply_flow(
    p,
    q
):

    flow = first(
        q,
        "flow",
        ""
    )

    if flow:
        p["flow"] = flow


# ============================================================
# TRANSPORT
# ============================================================

def apply_transport(
    p,
    q,
    info=None
):

    info = info or {}

    network = (
        info.get("net")
        or info.get("network")
        or first(
            q,
            "type",
            ""
        )
        or first(
            q,
            "network",
            ""
        )
        or "tcp"
    ).lower()

    p["network"] = network

    # --------------------------------------------------------
    # WS
    # --------------------------------------------------------

    if network in (
        "ws",
        "websocket"
    ):

        path = (
            info.get("path")
            or first(
                q,
                "path",
                "/"
            )
            or "/"
        )

        host_header = (
            info.get("host")
            or first_any(
                q,
                [
                    "host",
                    "Host"
                ],
                ""
            )
        )

        ws_opts = {
            "path": path
        }

        if host_header:
            ws_opts[
                "headers"
            ] = {
                "Host": host_header
            }

        p[
            "ws-opts"
        ] = ws_opts

    # --------------------------------------------------------
    # gRPC
    # --------------------------------------------------------

    elif network == "grpc":

        service_name = (
            info.get("serviceName")
            or info.get("service_name")
            or first_any(
                q,
                [
                    "serviceName",
                    "service-name"
                ],
                ""
            )
        )

        grpc_opts = {}

        if service_name:
            grpc_opts[
                "grpc-service-name"
            ] = service_name

        mode = first(
            q,
            "mode",
            ""
        )

        if mode:
            grpc_opts[
                "grpc-mode"
            ] = mode

        if grpc_opts:
            p[
                "grpc-opts"
            ] = grpc_opts

    # --------------------------------------------------------
    # HTTP
    # --------------------------------------------------------

    elif network in (
        "http",
        "h2"
    ):

        path = (
            info.get("path")
            or first(
                q,
                "path",
                "/"
            )
            or "/"
        )

        host_header = (
            info.get("host")
            or first_any(
                q,
                [
                    "host",
                    "Host"
                ],
                ""
            )
        )

        http_opts = {
            "path": [
                path
            ]
        }

        if host_header:

            http_opts[
                "headers"
            ] = {
                "Host": [
                    host_header
                ]
            }

        p[
            "h2-opts"
        ] = http_opts


# ============================================================
# VLESS
# ============================================================

def parse_vless(
    line
):

    try:

        parsed = urlparse(
            line
        )

        uid = (
            parsed.username
            or ""
        )

        host = (
            parsed.hostname
            or ""
        )

        port = (
            parsed.port
            or 443
        )

        q = normalize_query(
            parse_qs(
                parsed.query,
                keep_blank_values=True
            )
        )

        if not (
            uid
            and host
            and port
        ):
            return None

        remark = remark_from_url(
            parsed
        )

        p = {
            "name": make_name(
                "vless",
                host,
                port,
                remark
            ),
            "type": "vless",
            "server": host,
            "port": port,
            "uuid": uid,
            "encryption": "none",
            "udp": True
        }

        apply_transport(
            p,
            q
        )

        apply_tls_common(
            p,
            q,
            host
        )

        apply_reality(
            p,
            q
        )

        apply_flow(
            p,
            q
        )

        packet_encoding = first(
            q,
            "packetEncoding",
            ""
        )

        if packet_encoding:
            p[
                "packet-encoding"
            ] = packet_encoding

        return p

    except Exception:
        return None


# ============================================================
# VMESS
# ============================================================

def parse_vmess(
    line
):

    try:

        payload = line[
            len("vmess://"):
        ]

        decoded = b64decode_text(
            payload
        )

        if not decoded:
            return None

        info = json.loads(
            decoded
        )

        host = (
            info.get("add")
            or info.get("server")
            or ""
        )

        port = safe_int(
            info.get("port"),
            0
        )

        uid = (
            info.get("id")
            or ""
        )

        if not (
            host
            and port
            and uid
        ):
            return None

        remark = (
            info.get("ps")
            or ""
        )

        p = {
            "name": make_name(
                "vmess",
                host,
                port,
                remark
            ),
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
            "cipher": (
                info.get(
                    "scy"
                )
                or "auto"
            ),
            "udp": True
        }

        # Transport
        network = (
            info.get("net")
            or "tcp"
        ).lower()

        transport_query = {}

        for key in (
            "path",
            "host",
            "serviceName",
            "type",
            "mode"
        ):
            if key in info:
                transport_query[key] = [
                    str(
                        info[key]
                    )
                ]

        apply_transport(
            p,
            transport_query,
            info=info
        )

        # TLS
        tls_value = str(
            info.get(
                "tls",
                ""
            )
        ).lower()

        if tls_value in (
            "tls",
            "1",
            "true"
        ):

            p["tls"] = True

            sni = (
                info.get("sni")
                or info.get("host")
                or host
            )

            p[
                "servername"
            ] = sni

        # ALPN
        alpn = info.get(
            "alpn"
        )

        if alpn:

            if isinstance(
                alpn,
                list
            ):
                p["alpn"] = alpn

            else:

                parsed_alpn = parse_alpn(
                    str(alpn)
                )

                if parsed_alpn:
                    p[
                        "alpn"
                    ] = parsed_alpn

        # Fingerprint
        fp = (
            info.get("fp")
            or info.get(
                "fingerprint"
            )
        )

        if fp:
            p[
                "client-fingerprint"
            ] = fp

        # Packet encoding
        packet_encoding = (
            info.get(
                "packetEncoding"
            )
        )

        if packet_encoding:
            p[
                "packet-encoding"
            ] = packet_encoding

        return p

    except Exception:
        return None


# ============================================================
# TROJAN
# ============================================================

def parse_trojan(
    line
):

    try:

        parsed = urlparse(
            line
        )

        password = (
            parsed.username
            or ""
        )

        host = (
            parsed.hostname
            or ""
        )

        port = (
            parsed.port
            or 443
        )

        q = normalize_query(
            parse_qs(
                parsed.query,
                keep_blank_values=True
            )
        )

        if not (
            password
            and host
            and port
        ):
            return None

        remark = remark_from_url(
            parsed
        )

        p = {
            "name": make_name(
                "trojan",
                host,
                port,
                remark
            ),
            "type": "trojan",
            "server": host,
            "port": port,
            "password": password,
            "udp": True
        }

        apply_transport(
            p,
            q
        )

        apply_tls_common(
            p,
            q,
            host,
            force_tls=True
        )

        return p

    except Exception:
        return None


# ============================================================
# SHADOWSOCKS
# ============================================================

def parse_ss(
    line
):

    try:

        parsed = urlparse(
            line
        )

        fragment = remark_from_url(
            parsed
        )

        raw = line[
            len("ss://"):
        ]

        if "@" not in raw:
            return None

        credentials, server_part = (
            raw.split(
                "@",
                1
            )
        )

        # Remove fragment
        server_part = server_part.split(
            "#",
            1
        )[0]

        # Remove query
        server_part = server_part.split(
            "?",
            1
        )[0]

        if ":" not in server_part:
            return None

        host, port = (
            server_part.rsplit(
                ":",
                1
            )
        )

        port = safe_int(
            port,
            0
        )

        if not port:
            return None

        # Plain method:password
        if ":" in credentials:

            method, password = (
                credentials.split(
                    ":",
                    1
                )
            )

        else:

            decoded = (
                b64decode_urlsafe(
                    credentials
                )
            )

            if ":" not in decoded:
                return None

            method, password = (
                decoded.split(
                    ":",
                    1
                )
            )

        if not (
            method
            and password
        ):
            return None

        p = {
            "name": make_name(
                "ss",
                host,
                port,
                fragment
            ),
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


# ============================================================
# SSR
# ============================================================

def parse_ssr(
    line
):

    try:

        raw = line[
            len("ssr://"):
        ]

        decoded = b64decode_urlsafe(
            raw
        )

        if not decoded:
            return None

        # server:port:protocol:method:obfs:password_base64
        parts = decoded.split(
            "/",
            1
        )

        main = parts[0]

        fields = main.split(
            ":"
        )

        if len(fields) < 6:
            return None

        host = fields[0]

        port = safe_int(
            fields[1],
            0
        )

        protocol = fields[2]

        method = fields[3]

        obfs = fields[4]

        password_b64 = fields[5]

        password = b64decode_urlsafe(
            password_b64
        )

        if not (
            host
            and port
            and method
            and password
        ):
            return None

        p = {
            "name": make_name(
                "ssr",
                host,
                port
            ),
            "type": "ssr",
            "server": host,
            "port": port,
            "cipher": method,
            "password": password,
            "protocol": protocol,
            "obfs": obfs,
            "udp": True
        }

        return p

    except Exception:
        return None


# ============================================================
# HYSTERIA
# ============================================================

def parse_hysteria(
    line
):

    try:

        parsed = urlparse(
            line
        )

        host = (
            parsed.hostname
            or ""
        )

        port = (
            parsed.port
            or 443
        )

        password = (
            parsed.password
            or ""
        )

        q = normalize_query(
            parse_qs(
                parsed.query,
                keep_blank_values=True
            )
        )

        if not host:
            return None

        # Some hysteria URLs use auth instead
        auth = first(
            q,
            "auth",
            ""
        )

        if not password:
            password = auth

        if not password:
            return None

        p = {
            "name": make_name(
                "hysteria",
                host,
                port,
                remark_from_url(
                    parsed
                )
            ),
            "type": "hysteria",
            "server": host,
            "port": port,
            "password": password,
            "udp": True
        }

        protocol = first(
            q,
            "protocol",
            ""
        )

        if protocol:
            p[
                "protocol"
            ] = protocol

        obfs = first(
            q,
            "obfs",
            ""
        )

        if obfs:
            p[
                "obfs"
            ] = obfs

        sni = first_any(
            q,
            [
                "sni",
                "peer"
            ],
            ""
        )

        if sni:
            p[
                "sni"
            ] = sni

        up = first(
            q,
            "up",
            ""
        )

        down = first(
            q,
            "down",
            ""
        )

        if up:
            p["up"] = up

        if down:
            p["down"] = down

        return p

    except Exception:
        return None


# ============================================================
# HYSTERIA2
# ============================================================

def parse_hysteria2(
    line
):

    try:

        parsed = urlparse(
            line
        )

        host = (
            parsed.hostname
            or ""
        )

        port = (
            parsed.port
            or 443
        )

        password = (
            parsed.username
            or ""
        )

        q = normalize_query(
            parse_qs(
                parsed.query,
                keep_blank_values=True
            )
        )

        if not (
            host
            and password
        ):
            return None

        p = {
            "name": make_name(
                "hysteria2",
                host,
                port,
                remark_from_url(
                    parsed
                )
            ),
            "type": "hysteria2",
            "server": host,
            "port": port,
            "password": password,
            "udp": True
        }

        sni = first(
            q,
            "sni",
            ""
        )

        if sni:
            p["sni"] = sni

        obfs = first(
            q,
            "obfs",
            ""
        )

        if obfs:
            p["obfs"] = obfs

        obfs_password = first(
            q,
            "obfs-password",
            ""
        )

        if not obfs_password:
            obfs_password = first(
                q,
                "obfs-password",
                ""
            )

        if obfs_password:
            p[
                "obfs-password"
            ] = obfs_password

        up = first(
            q,
            "up",
            ""
        )

        down = first(
            q,
            "down",
            ""
        )

        if up:
            p["up"] = up

        if down:
            p["down"] = down

        alpn = parse_alpn(
            first(
                q,
                "alpn",
                ""
            )
        )

        if alpn:
            p["alpn"] = alpn

        fp = first(
            q,
            "fingerprint",
            ""
        )

        if fp:
            p[
                "fingerprint"
            ] = fp

        skip = first(
            q,
            "insecure",
            ""
        )

        if skip != "":
            p[
                "skip-cert-verify"
            ] = bool_value(
                skip
            )

        return p

    except Exception:
        return None


# ============================================================
# TUIC
# ============================================================

def parse_tuic(
    line
):

    try:

        parsed = urlparse(
            line
        )

        host = (
            parsed.hostname
            or ""
        )

        port = (
            parsed.port
            or 443
        )

        username = (
            parsed.username
            or ""
        )

        password = (
            parsed.password
            or ""
        )

        q = normalize_query(
            parse_qs(
                parsed.query,
                keep_blank_values=True
            )
        )

        if not (
            host
            and username
            and password
        ):
            return None

        p = {
            "name": make_name(
                "tuic",
                host,
                port,
                remark_from_url(
                    parsed
                )
            ),
            "type": "tuic",
            "server": host,
            "port": port,
            "uuid": username,
            "password": password,
            "udp": True
        }

        congestion = first(
            q,
            "congestion_control",
            ""
        )

        if not congestion:
            congestion = first(
                q,
                "congestion-control",
                ""
            )

        if congestion:
            p[
                "congestion-controller"
            ] = congestion

        sni = first(
            q,
            "sni",
            ""
        )

        if sni:
            p["sni"] = sni

        alpn = parse_alpn(
            first(
                q,
                "alpn",
                ""
            )
        )

        if alpn:
            p["alpn"] = alpn

        udp_relay = first(
            q,
            "udp_relay_mode",
            ""
        )

        if udp_relay:
            p[
                "udp-relay-mode"
            ] = udp_relay

        disable_sni = first(
            q,
            "disable_sni",
            ""
        )

        if disable_sni:
            p[
                "disable-sni"
            ] = bool_value(
                disable_sni
            )

        return p

    except Exception:
        return None


# ============================================================
# WIREGUARD
# ============================================================

def parse_wireguard(
    line
):

    try:

        parsed = urlparse(
            line
        )

        host = (
            parsed.hostname
            or ""
        )

        port = (
            parsed.port
            or 51820
        )

        private_key = (
            parsed.username
            or ""
        )

        q = normalize_query(
            parse_qs(
                parsed.query,
                keep_blank_values=True
            )
        )

        if not host:
            return None

        public_key = first(
            q,
            "publickey",
            ""
        )

        if not public_key:
            public_key = first(
                q,
                "public-key",
                ""
            )

        if not private_key:
            private_key = first(
                q,
                "privatekey",
                ""
            )

        if not private_key:
            return None

        p = {
            "name": make_name(
                "wireguard",
                host,
                port,
                remark_from_url(
                    parsed
                )
            ),
            "type": "wireguard",
            "server": host,
            "port": port,
            "private-key": private_key,
            "udp": True
        }

        if public_key:
            p[
                "public-key"
            ] = public_key

        ip = first(
            q,
            "ip",
            ""
        )

        if ip:
            p["ip"] = [
                x.strip()
                for x in ip.split(",")
                if x.strip()
            ]

        ip6 = first(
            q,
            "ipv6",
            ""
        )

        if ip6:
            p[
                "ipv6"
            ] = [
                x.strip()
                for x in ip6.split(",")
                if x.strip()
            ]

        mtu = safe_int(
            first(
                q,
                "mtu",
                ""
            ),
            0
        )

        if mtu:
            p[
                "mtu"
            ] = mtu

        reserved = first(
            q,
            "reserved",
            ""
        )

        if reserved:

            try:
                p[
                    "reserved"
                ] = [
                    int(x)
                    for x in reserved.split(",")
                    if x.strip()
                ]
            except Exception:
                pass

        return p

    except Exception:
        return None


# ============================================================
# MASTER PARSER
# ============================================================

def parse_link(
    line
):

    line = line.strip()

    if not line:
        return None

    # Remove BOM
    line = line.lstrip(
        "\ufeff"
    )

    lower = line.lower()

    try:

        if lower.startswith(
            "vless://"
        ):
            return parse_vless(
                line
            )

        if lower.startswith(
            "vmess://"
        ):
            return parse_vmess(
                line
            )

        if lower.startswith(
            "trojan://"
        ):
            return parse_trojan(
                line
            )

        if lower.startswith(
            "ss://"
        ):
            return parse_ss(
                line
            )

        if lower.startswith(
            "ssr://"
        ):
            return parse_ssr(
                line
            )

        if lower.startswith(
            "hysteria2://"
        ):

            return parse_hysteria2(
                line
            )

        if lower.startswith(
            "hy2://"
        ):

            return parse_hysteria2(
                "hysteria2://"
                + line[
                    len("hy2://"):
                ]
            )

        if lower.startswith(
            "hysteria://"
        ):
            return parse_hysteria(
                line
            )

        if lower.startswith(
            "tuic://"
        ):
            return parse_tuic(
                line
            )

        if lower.startswith(
            "wireguard://"
        ):
            return parse_wireguard(
                line
            )

    except Exception:
        return None

    return None


# ============================================================
# VALIDATION
# ============================================================

def validate_proxy(
    p
):

    if not isinstance(
        p,
        dict
    ):
        return False

    required = (
        "name",
        "type",
        "server",
        "port"
    )

    for key in required:

        if key not in p:
            return False

        if p[key] in (
            None,
            ""
        ):
            return False

    if not isinstance(
        p["port"],
        int
    ):
        return False

    if not (
        1 <= p["port"] <= 65535
    ):
        return False

    return True


# ============================================================
# TCP TEST
# ============================================================

def tcp_test(
    host,
    port,
    attempts=TCP_ATTEMPTS,
    timeout=TCP_TIMEOUT
):

    try:

        # Direct IP
        try:
            host_ip = socket.gethostbyname(
                host
            )
        except Exception:
            host_ip = host

        best = None

        for _ in range(
            attempts
        ):

            sock = None

            try:

                start = time.monotonic()

                sock = socket.create_connection(
                    (
                        host_ip,
                        int(port)
                    ),
                    timeout=timeout
                )

                elapsed = (
                    time.monotonic()
                    - start
                )

                ms = int(
                    elapsed * 1000
                )

                if (
                    best is None
                    or ms < best
                ):
                    best = ms

            except Exception:
                pass

            finally:

                try:

                    if sock:
                        sock.close()

                except Exception:
                    pass

        return best

    except Exception:
        return None


def attach_test(
    p
):

    result = tcp_test(
        p["server"],
        p["port"]
    )

    p[
        "_tcp_ms"
    ] = result

    p[
        "_tcp_reachable"
    ] = (
        result is not None
    )

    return p


# ============================================================
# READ INPUT
# ============================================================

try:

    with open(
        INPUT_PATH,
        "r",
        encoding="utf-8"
    ) as f:

        content = f.read()

except Exception as e:

    print(
        f"[ERROR] Cannot read input: {e}"
    )

    raise SystemExit(1)


# ============================================================
# EXTRACT LINES
# ============================================================

raw_lines = [
    line.strip()
    for line in content.splitlines()
    if line.strip()
]


# ============================================================
# PARSE
# ============================================================

proxies = []

failed_lines = []

seen_signatures = set()


for line in raw_lines:

    p = parse_link(
        line
    )

    if not validate_proxy(
        p
    ):

        failed_lines.append(
            line
        )

        continue

    signature = (
        p.get("type"),
        p.get("server"),
        p.get("port"),
        p.get("uuid"),
        p.get("password")
    )

    if signature in seen_signatures:
        continue

    seen_signatures.add(
        signature
    )

    proxies.append(
        p
    )


# ============================================================
# PARSE REPORT
# ============================================================

print()
print("=" * 65)
print("[PARSER]")
print("=" * 65)

print(
    f"Input lines      : {len(raw_lines)}"
)

print(
    f"Parsed proxies   : {len(proxies)}"
)

print(
    f"Failed lines     : {len(failed_lines)}"
)

print("=" * 65)
print()


if not proxies:

    print(
        "[ERROR] No valid proxies found."
    )

    raise SystemExit(1)


# ============================================================
# TCP TEST
# ============================================================

if enable_tcp_test:

    print(
        "[INFO] Testing TCP reachability..."
    )

    from concurrent.futures import (
        ThreadPoolExecutor,
        as_completed
    )

    tested = []

    with ThreadPoolExecutor(
        max_workers=MAX_WORKERS
    ) as executor:

        futures = [
            executor.submit(
                attach_test,
                p
            )
            for p in proxies
        ]

        for future in as_completed(
            futures
        ):

            try:

                tested.append(
                    future.result()
                )

            except Exception:
                pass

    proxies = tested

else:

    for p in proxies:

        p[
            "_tcp_ms"
        ] = None

        p[
            "_tcp_reachable"
        ] = True


# ============================================================
# SORT
# ============================================================

def sort_key(
    p
):

    ms = p.get(
        "_tcp_ms"
    )

    if ms is None:
        return 999999

    return ms


proxies.sort(
    key=sort_key
)


# ============================================================
# DISPLAY
# ============================================================

print(
    "[RESULT]"
)

reachable_count = sum(
    1
    for p in proxies
    if p.get(
        "_tcp_reachable"
    )
)

print(
    f"TCP reachable : {reachable_count}"
)

print(
    f"Total parsed  : {len(proxies)}"
)

print()


for index, p in enumerate(
    proxies,
    1
):

    ms = p.get(
        "_tcp_ms"
    )

    if ms is None:
        latency = "FAIL"

    else:
        latency = (
            f"{ms} ms"
        )

    print(
        f"{index:03d}. "
        f"{p['type']:12} "
        f"{p['server']}:"
        f"{p['port']} "
        f"{latency}"
    )


# ============================================================
# IMPORTANT:
# KEEP ALL PARSED PROXIES
#
# A TCP test failure does NOT automatically mean
# that the proxy is unusable.
# ============================================================

# Remove internal fields
for p in proxies:

    p.pop(
        "_tcp_ms",
        None
    )

    p.pop(
        "_tcp_reachable",
        None
    )


# ============================================================
# PROXY NAMES
# ============================================================

proxy_names = [
    p["name"]
    for p in proxies
]


# ============================================================
# GROUPS
# ============================================================

proxy_groups = []


# ------------------------------------------------------------
# MANUAL SELECT
# ------------------------------------------------------------

select_group = {
    "name": GROUP_NAME,
    "type": "select",
    "proxies": proxy_names
}

proxy_groups.append(
    select_group
)


# ------------------------------------------------------------
# AUTO URL-TEST
# ------------------------------------------------------------

if (
    enable_auto_test
    and proxy_names
):

    auto_group = {
        "name": AUTO_GROUP_NAME,
        "type": "url-test",
        "proxies": proxy_names,
        "url": HEALTH_URL,
        "interval": HEALTH_INTERVAL,
        "timeout": HEALTH_TIMEOUT,
        "lazy": False,
        "expected-status": 204
    }

    proxy_groups.append(
        auto_group
)


# ============================================================
# DNS
# ============================================================

dns_config = None

if enable_dns:

    dns_config = {

        "enable": True,

        "ipv6": True,

        "enhanced-mode": "fake-ip",

        "fake-ip-range": (
            "198.18.0.1/16"
        ),

        "nameserver": [
            "1.1.1.1",
            "8.8.8.8"
        ],

        "fallback": [
            "1.0.0.1",
            "8.8.4.4"
        ],

        "fallback-filter": {
            "geoip": True,
            "geoip-code": "IR"
        }
    }


# ============================================================
# FINAL YAML
# ============================================================

yaml_data = {

    # --------------------------------------------------------
    # Basic runtime
    # --------------------------------------------------------

    "mixed-port": 7890,

    "allow-lan": False,

    "mode": "rule",

    "log-level": "info",

    "ipv6": True,

    "unified-delay": True,

    "tcp-concurrent": True,

    # --------------------------------------------------------
    # Profile
    # --------------------------------------------------------

    "profile": {

        "store-selected": True,

        "store-fake-ip": True
    },

    # --------------------------------------------------------
    # Proxies
    # --------------------------------------------------------

    "proxies": proxies,

    # --------------------------------------------------------
    # Groups
    # --------------------------------------------------------

    "proxy-groups": proxy_groups,

    # --------------------------------------------------------
    # Rules
    # --------------------------------------------------------

    "rules": [
        "MATCH," + GROUP_NAME
    ]
}


if dns_config:

    yaml_data[
        "dns"
    ] = dns_config


# ============================================================
# WRITE YAML
# ============================================================

try:

    with open(
        OUT_PATH,
        "w",
        encoding="utf-8"
    ) as f:

        yaml.safe_dump(
            yaml_data,
            f,
            allow_unicode=True,
            sort_keys=False,
            default_flow_style=False,
            width=160
        )

except Exception as e:

    print(
        f"[ERROR] YAML save failed: {e}"
    )

    raise SystemExit(1)


# ============================================================
# VALIDATE GENERATED YAML
# ============================================================

try:

    with open(
        OUT_PATH,
        "r",
        encoding="utf-8"
    ) as f:

        check = yaml.safe_load(
            f
        )

    if not isinstance(
        check,
        dict
    ):
        raise ValueError(
            "Generated YAML is not a mapping."
        )

except Exception as e:

    print(
        f"[ERROR] Generated YAML validation failed: {e}"
    )

    raise SystemExit(1)


# ============================================================
# FINAL REPORT
# ============================================================

type_count = {}

for p in proxies:

    ptype = p.get(
        "type",
        "unknown"
    )

    type_count[
        ptype
    ] = (
        type_count.get(
            ptype,
            0
        ) + 1
    )


print()
print("=" * 70)
print("[DONE] Mihomo / Clash Meta YAML created")
print("=" * 70)

print(
    f"Output       : {OUT_PATH}"
)

print(
    f"Proxies      : {len(proxies)}"
)

print(
    f"Groups       : {len(proxy_groups)}"
)

print(
    f"TCP test     : "
    f"{'ON' if enable_tcp_test else 'OFF'}"
)

print(
    f"Auto URL-test: "
    f"{'ON' if enable_auto_test else 'OFF'}"
)

print(
    f"DNS          : "
    f"{'ON' if enable_dns else 'OFF'}"
)

print()
print("Proxy types:")

for ptype in sorted(
    type_count
):

    print(
        f"  {ptype:15} "
        f"{type_count[ptype]}"
    )

print()
print(
    "IMPORTANT:"
)

print(
    "TCP reachability is NOT the same as proxy health."
)

print(
    "Mihomo URL-Test will perform the actual latency test."
)

print()
print(
    "Groups:"
)

print(
    f"  {GROUP_NAME}"
)

if enable_auto_test:

    print(
        f"  {AUTO_GROUP_NAME}"
    )

print("=" * 70)
print()


# ============================================================
# OPTIONAL FAILED LINES REPORT
# ============================================================

if failed_lines:

    failed_path = os.path.join(
        OUT_DIR,
        f"{out_name}_failed.txt"
    )

    try:

        with open(
            failed_path,
            "w",
            encoding="utf-8"
        ) as f:

            for line in failed_lines:

                f.write(
                    line
                    + "\n"
                )

        print(
            f"[INFO] Failed/unsupported "
            f"links saved to:"
        )

        print(
            failed_path
        )

    except Exception:
        pass


# ============================================================
# PERMISSION
# ============================================================

try:

    os.chmod(
        OUT_PATH,
        0o644
    )

except Exception:
    pass


print()
print("[READY]")
print()
