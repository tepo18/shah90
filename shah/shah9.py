#!/data/data/com.termux/files/usr/bin/python3
# -*- coding: utf-8 -*-

"""
AKBAR98 FINAL ADVANCED PROXY CONVERTER
VLESS / VMess / Trojan / SS / SSR / Hysteria / Hysteria2 / TUIC / WireGuard
-> Mihomo / Clash Meta YAML

IMPORTANT:
- PRIMARY OUTPUT IS ALWAYS YAML.
- *_report.txt and *_failed.txt are auxiliary reports only.
- Input path remains:
    /storage/emulated/0/Download/Akbar98/input_mobile.txt
- Output remains user-selected folder/file under:
    /storage/emulated/0/Download/
- Default test mode: LIGHT
    DNS -> TCP -> finish
  No HTTP download/probe is performed by the converter.
- NORMAL / DEEP are internal modes selectable with AKBAR98_TEST_MODE.
- Batch testing, adaptive workers, DNS cache, result cache/TTL,
  IPv4/IPv6 fallback, two-stage deduplication, scoring,
  unknown-parameter reporting, Mihomo compatibility checks and
  atomic final YAML validation are included.
"""

import base64
import hashlib
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

try:
    import yaml
except ImportError:
    print("[ERROR] PyYAML is not installed.")
    print("Install with: pip install pyyaml")
    raise SystemExit(1)


# ============================================================
# PATHS / SETTINGS
# ============================================================

BASE_DIR = Path("/storage/emulated/0/Download/Akbar98")
INPUT_PATH = BASE_DIR / "input_mobile.txt"

# PRIMARY YAML is created from the user's chosen output folder/name.
DOWNLOAD_DIR = Path("/storage/emulated/0/Download")

CACHE_PATH = BASE_DIR / ".akbar98_cache.json"

DEFAULT_MODE = "LIGHT"
TEST_MODE = os.environ.get("AKBAR98_TEST_MODE", DEFAULT_MODE).upper()
if TEST_MODE not in {"LIGHT", "NORMAL", "DEEP"}:
    TEST_MODE = DEFAULT_MODE

BATCH_SIZE = 100
MAX_WORKERS_CAP = 32

# TTL requested by the design.
DNS_TTL = 300          # 5 minutes
TCP_TTL = 600          # 10 minutes
CACHE_MAX_AGE = 7 * 86400

HEALTH_URL = "https://www.gstatic.com/generate_204"
URL_TEST_INTERVAL = 300
URL_TEST_TIMEOUT = 5000

GROUP_MANUAL = "Mobile-Fast❤"
GROUP_AUTO = "Mobile-Auto❤"

# Test behavior. No HTTP body/download test exists.
MODE_SETTINGS = {
    "LIGHT": {
        "timeout": 2.5,
        "attempts": 1,
        "batch": 100,
    },
    "NORMAL": {
        "timeout": 3.0,
        "attempts": 2,
        "batch": 100,
    },
    "DEEP": {
        "timeout": 4.0,
        "attempts": 3,
        "batch": 100,
    },
}

SETTINGS = MODE_SETTINGS[TEST_MODE]

BASE_DIR.mkdir(parents=True, exist_ok=True)
DOWNLOAD_DIR.mkdir(parents=True, exist_ok=True)


# ============================================================
# DATA
# ============================================================

@dataclass
class TestResult:
    dns_ok: bool = False
    tcp_ok: bool = False
    dns_ms: int | None = None
    tcp_ms: int | None = None
    addresses: list = field(default_factory=list)
    selected_family: str = ""
    error: str = ""
    cached_dns: bool = False
    cached_tcp: bool = False


@dataclass
class Stats:
    input_lines: int = 0
    extracted_links: int = 0
    parsed: int = 0
    duplicates_exact: int = 0
    duplicates_smart: int = 0
    invalid: int = 0
    unsupported: int = 0
    tcp_ok: int = 0
    tcp_failed: int = 0
    cache_hits: int = 0
    dns_cache_hits: int = 0
    tested: int = 0
    final: int = 0
    by_type: dict = field(default_factory=dict)


USED_NAMES = set()


# ============================================================
# BASIC HELPERS
# ============================================================

def clean_text(value):
    if value is None:
        return ""
    return unquote(str(value)).strip()


def safe_int(value, default=0):
    try:
        return int(str(value).strip())
    except Exception:
        return default


def bool_value(value, default=False):
    if value is None:
        return default
    s = str(value).strip().lower()
    if s in {"1", "true", "yes", "on"}:
        return True
    if s in {"0", "false", "no", "off"}:
        return False
    return default


def first(q, key, default=""):
    values = q.get(key)
    if values:
        return clean_text(values[0])
    return default


def first_any(q, keys, default=""):
    for key in keys:
        value = first(q, key, "")
        if value:
            return value
    return default


def normalize_query(q):
    return {
        str(key): [clean_text(v) for v in values]
        for key, values in q.items()
    }


def parse_alpn(value):
    if not value:
        return None
    parts = re.split(r"[,|]", clean_text(value))
    parts = [x.strip() for x in parts if x.strip()]
    return parts or None


def normalize_network(value):
    value = clean_text(value).lower()
    aliases = {
        "websocket": "ws",
        "httpupgrade": "httpupgrade",
        "http-upgrade": "httpupgrade",
        "splithttp": "splithttp",
        "split-http": "splithttp",
        "xhttp": "xhttp",
    }
    return aliases.get(value, value or "tcp")


def b64fix(value):
    if not value:
        return ""
    s = re.sub(r"\s+", "", str(value).strip())
    s = s.replace("-", "+").replace("_", "/")
    s += "=" * ((-len(s)) % 4)
    return s


def b64decode_text(value):
    try:
        return base64.b64decode(
            b64fix(value),
            validate=False,
        ).decode("utf-8", errors="ignore")
    except Exception:
        return ""


def b64decode_urlsafe(value):
    try:
        return base64.urlsafe_b64decode(
            b64fix(value)
        ).decode("utf-8", errors="ignore")
    except Exception:
        return ""


def canonical_json(value):
    return json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    )


def sha256_text(value):
    return hashlib.sha256(
        value.encode("utf-8", errors="ignore")
    ).hexdigest()


def sanitize_name(value):
    value = clean_text(value)
    value = re.sub(r"[\x00-\x1F\x7F]", "", value)
    value = re.sub(r'[\\/:*?"<>|]', "", value).strip()
    return value[:100] if value else "Proxy"


def uniq_name(value):
    base = sanitize_name(value)
    name = base
    n = 2
    while name in USED_NAMES:
        name = f"{base} {n}"
        n += 1
    USED_NAMES.add(name)
    return name


def remark_from_url(parsed):
    try:
        return sanitize_name(parsed.fragment)
    except Exception:
        return ""


def make_name(protocol, host, port, remark=""):
    return uniq_name(remark or f"{protocol}-{host}-{port}")


def add_if(proxy, key, value):
    if value is not None and value != "":
        proxy[key] = value


# ============================================================
# CACHE
# ============================================================

def load_cache():
    if not CACHE_PATH.exists():
        return {
            "version": 2,
            "dns": {},
            "tcp": {},
            "fingerprints": {},
        }

    try:
        data = json.loads(CACHE_PATH.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("invalid cache")
        data.setdefault("version", 2)
        data.setdefault("dns", {})
        data.setdefault("tcp", {})
        data.setdefault("fingerprints", {})
        return data
    except Exception:
        return {
            "version": 2,
            "dns": {},
            "tcp": {},
            "fingerprints": {},
        }


CACHE = load_cache()


def cache_get(bucket, key, ttl):
    item = CACHE.get(bucket, {}).get(key)
    if not isinstance(item, dict):
        return None
    ts = safe_int(item.get("ts"), 0)
    if ts <= 0 or time.time() - ts > ttl:
        return None
    return item.get("data")


def cache_put(bucket, key, data):
    CACHE.setdefault(bucket, {})[key] = {
        "ts": int(time.time()),
        "data": data,
    }


def prune_cache():
    now = time.time()
    for bucket in ("dns", "tcp", "fingerprints"):
        source = CACHE.get(bucket, {})
        if not isinstance(source, dict):
            CACHE[bucket] = {}
            continue
        dead = []
        for key, item in source.items():
            if not isinstance(item, dict):
                dead.append(key)
                continue
            ts = safe_int(item.get("ts"), 0)
            if ts <= 0 or now - ts > CACHE_MAX_AGE:
                dead.append(key)
        for key in dead:
            source.pop(key, None)


def save_cache():
    try:
        prune_cache()
        tmp = CACHE_PATH.with_suffix(".tmp")
        tmp.write_text(
            json.dumps(
                CACHE,
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        os.replace(tmp, CACHE_PATH)
    except Exception as exc:
        print(f"[WARNING] Cache save failed: {exc}")


# ============================================================
# TRANSPORT / TLS
# ============================================================

def apply_tls_common(proxy, q, host, force_tls=False):
    security = first(q, "security", "").lower()
    tls = (
        force_tls
        or security in {"tls", "reality"}
        or bool_value(first(q, "tls", ""), False)
    )

    if tls:
        proxy["tls"] = True
        sni = first_any(
            q,
            ("sni", "servername", "serverName"),
            host,
        )
        if sni:
            proxy["servername"] = sni

    fp = first_any(
        q,
        ("fp", "fingerprint", "clientFingerprint"),
        "",
    )
    if fp:
        proxy["client-fingerprint"] = fp

    alpn = parse_alpn(first(q, "alpn", ""))
    if alpn:
        proxy["alpn"] = alpn

    insecure = first_any(
        q,
        ("allowInsecure", "allowinsecure", "skip-cert-verify"),
        "",
    )
    if insecure != "":
        proxy["skip-cert-verify"] = bool_value(insecure)


def apply_reality(proxy, q):
    security = first(q, "security", "").lower()
    if security != "reality" and not bool_value(
        first(q, "reality", ""),
        False,
    ):
        return

    proxy["tls"] = True
    opts = {}

    public_key = first_any(
        q,
        ("pbk", "publicKey", "public-key"),
        "",
    )
    short_id = first_any(
        q,
        ("sid", "shortId", "short-id"),
        "",
    )

    if public_key:
        opts["public-key"] = public_key
    if short_id:
        opts["short-id"] = short_id

    if opts:
        proxy["reality-opts"] = opts


def apply_flow(proxy, q):
    flow = first(q, "flow", "")
    if flow:
        proxy["flow"] = flow


def apply_transport(proxy, q, info=None):
    info = info or {}

    network = normalize_network(
        info.get("net")
        or info.get("network")
        or first(q, "type", "")
        or first(q, "network", "")
        or "tcp"
    )

    proxy["network"] = network

    if network == "ws":
        path = info.get("path") or first(q, "path", "/") or "/"
        host_header = (
            info.get("host")
            or first_any(q, ("host", "Host"), "")
        )

        ws = {"path": path}
        if host_header:
            ws["headers"] = {"Host": host_header}

        ed = first_any(
            q,
            ("ed", "maxEarlyData", "max-early-data"),
            "",
        )
        eh = first_any(
            q,
            ("eh", "earlyDataHeaderName"),
            "",
        )
        if ed:
            ws["max-early-data"] = safe_int(ed, 0)
        if eh:
            ws["early-data-header-name"] = eh

        proxy["ws-opts"] = ws

    elif network == "grpc":
        service = (
            info.get("serviceName")
            or info.get("service_name")
            or first_any(
                q,
                ("serviceName", "service-name"),
                "",
            )
        )
        grpc = {}
        if service:
            grpc["grpc-service-name"] = service

        mode = first(q, "mode", "")
        if mode:
            grpc["grpc-mode"] = mode

        authority = first_any(
            q,
            ("authority", "grpc-authority"),
            "",
        )
        if authority:
            grpc["grpc-authority"] = authority

        if grpc:
            proxy["grpc-opts"] = grpc

    elif network in ("http", "h2"):
        path = info.get("path") or first(q, "path", "/") or "/"
        host_header = (
            info.get("host")
            or first_any(q, ("host", "Host"), "")
        )
        opts = {"path": [path]}
        if host_header:
            opts["headers"] = {"Host": [host_header]}
        proxy["h2-opts"] = opts

    elif network == "httpupgrade":
        path = first(q, "path", "/") or "/"
        host_header = first_any(q, ("host", "Host"), "")
        opts = {"path": path}
        if host_header:
            opts["headers"] = {"Host": host_header}
        proxy["http-upgrade-opts"] = opts

    elif network in ("xhttp", "splithttp"):
        path = first(q, "path", "/") or "/"
        host_header = first_any(q, ("host", "Host"), "")
        opts = {"path": path}
        if host_header:
            opts["headers"] = {"Host": host_header}
        proxy[
            "xhttp-opts"
            if network == "xhttp"
            else "split-http-opts"
        ] = opts


# ============================================================
# UNKNOWN PARAMETER TRACKING
# ============================================================

def unknown_query_params(q, known):
    unknown = []
    known_lower = {str(x).lower() for x in known}

    for key in q:
        if str(key).lower() not in known_lower:
            unknown.append(str(key))

    return sorted(set(unknown))


def set_unknown(proxy, params):
    if params:
        proxy["_unknown"] = sorted(set(params))


# ============================================================
# PARSERS
# ============================================================

def parse_vless(line):
    parsed = urlparse(line)
    host = parsed.hostname or ""
    port = parsed.port or 443
    uid = parsed.username or ""

    q = normalize_query(
        parse_qs(parsed.query, keep_blank_values=True)
    )

    if not uid or not host:
        return None

    proxy = {
        "name": make_name(
            "vless",
            host,
            port,
            remark_from_url(parsed),
        ),
        "type": "vless",
        "server": host,
        "port": port,
        "uuid": uid,
        "encryption": "none",
        "udp": True,
    }

    apply_transport(proxy, q)
    apply_tls_common(proxy, q, host)
    apply_reality(proxy, q)
    apply_flow(proxy, q)

    pe = first(q, "packetEncoding", "")
    if pe:
        proxy["packet-encoding"] = pe

    xudp = first_any(
        q,
        ("xudp", "xudpProxyUDP443"),
        "",
    )
    if xudp != "":
        proxy["xudp"] = bool_value(xudp)

    known = {
        "type", "network", "security", "tls", "sni", "servername",
        "serverName", "fp", "fingerprint", "clientFingerprint",
        "alpn", "allowInsecure", "allowinsecure", "skip-cert-verify",
        "pbk", "publicKey", "public-key", "sid", "shortId", "short-id",
        "reality", "flow", "path", "host", "Host", "serviceName",
        "service-name", "mode", "authority", "grpc-authority",
        "ed", "maxEarlyData", "max-early-data", "eh",
        "earlyDataHeaderName", "packetEncoding", "xudp",
        "xudpProxyUDP443",
    }
    set_unknown(proxy, unknown_query_params(q, known))
    return proxy


def parse_vmess(line):
    decoded = b64decode_text(line[len("vmess://"):])
    if not decoded:
        return None

    info = json.loads(decoded)

    host = str(info.get("add") or info.get("server") or "")
    port = safe_int(info.get("port"), 0)
    uid = str(info.get("id") or "")

    if not host or not port or not uid:
        return None

    proxy = {
        "name": make_name(
            "vmess",
            host,
            port,
            info.get("ps", ""),
        ),
        "type": "vmess",
        "server": host,
        "port": port,
        "uuid": uid,
        "alterId": safe_int(
            info.get("aid", info.get("alterId", 0))
        ),
        "cipher": info.get("scy") or "auto",
        "udp": True,
    }

    q = {
        str(k): [str(v)]
        for k, v in info.items()
        if v is not None
    }
    apply_transport(proxy, q, info=info)

    tls_value = str(info.get("tls", "")).lower()
    if tls_value in {"tls", "1", "true"}:
        proxy["tls"] = True
        proxy["servername"] = (
            info.get("sni")
            or info.get("host")
            or host
        )

    alpn = info.get("alpn")
    if alpn:
        proxy["alpn"] = (
            alpn if isinstance(alpn, list)
            else parse_alpn(str(alpn))
        )

    fp = info.get("fp") or info.get("fingerprint")
    if fp:
        proxy["client-fingerprint"] = fp

    if info.get("packetEncoding"):
        proxy["packet-encoding"] = info["packetEncoding"]

    known = {
        "v", "ps", "add", "server", "port", "id", "aid", "alterId",
        "scy", "net", "network", "type", "host", "path", "tls", "sni",
        "alpn", "fp", "fingerprint", "serviceName", "service_name",
        "mode", "authority", "packetEncoding", "security",
    }
    set_unknown(
        proxy,
        [k for k in info if str(k) not in known],
    )
    return proxy


def parse_trojan(line):
    parsed = urlparse(line)
    password = parsed.username or ""
    host = parsed.hostname or ""
    port = parsed.port or 443

    q = normalize_query(
        parse_qs(parsed.query, keep_blank_values=True)
    )

    if not password or not host:
        return None

    proxy = {
        "name": make_name(
            "trojan",
            host,
            port,
            remark_from_url(parsed),
        ),
        "type": "trojan",
        "server": host,
        "port": port,
        "password": password,
        "udp": True,
    }

    apply_transport(proxy, q)
    apply_tls_common(proxy, q, host, force_tls=True)

    known = {
        "type", "network", "security", "tls", "sni", "servername",
        "serverName", "fp", "fingerprint", "clientFingerprint", "alpn",
        "allowInsecure", "allowinsecure", "skip-cert-verify", "path",
        "host", "Host", "serviceName", "service-name", "mode", "authority",
        "grpc-authority", "ed", "maxEarlyData", "max-early-data", "eh",
        "earlyDataHeaderName",
    }
    set_unknown(proxy, unknown_query_params(q, known))
    return proxy


def parse_ss(line):
    raw = line[len("ss://"):]
    remark = ""

    if "#" in raw:
        raw, fragment = raw.split("#", 1)
        remark = sanitize_name(fragment)

    raw = raw.split("?", 1)[0]

    if "@" not in raw:
        return None

    credentials, server_part = raw.rsplit("@", 1)

    if ":" not in server_part:
        return None

    host, port_text = server_part.rsplit(":", 1)
    port = safe_int(port_text, 0)
    if not port:
        return None

    if ":" in credentials:
        method, password = credentials.split(":", 1)
    else:
        decoded = b64decode_urlsafe(credentials)
        if ":" not in decoded:
            return None
        method, password = decoded.split(":", 1)

    if not method or not password:
        return None

    return {
        "name": make_name("ss", host, port, remark),
        "type": "ss",
        "server": host,
        "port": port,
        "cipher": method,
        "password": password,
        "udp": True,
    }


def parse_ssr(line):
    decoded = b64decode_urlsafe(line[len("ssr://"):])
    if not decoded:
        return None

    main, _, query = decoded.partition("/")
    fields = main.split(":")
    if len(fields) < 6:
        return None

    host = fields[0]
    port = safe_int(fields[1], 0)
    protocol = fields[2]
    method = fields[3]
    obfs = fields[4]
    password = b64decode_urlsafe(fields[5])

    if not host or not port or not password:
        return None

    proxy = {
        "name": make_name("ssr", host, port),
        "type": "ssr",
        "server": host,
        "port": port,
        "cipher": method,
        "password": password,
        "protocol": protocol,
        "obfs": obfs,
        "udp": True,
    }

    if query:
        q = normalize_query(
            parse_qs(query, keep_blank_values=True)
        )
        if first(q, "remarks", ""):
            proxy["name"] = uniq_name(
                b64decode_urlsafe(first(q, "remarks", ""))
            )

    return proxy


def parse_hysteria(line):
    parsed = urlparse(line)
    host = parsed.hostname or ""
    port = parsed.port or 443
    password = parsed.password or ""

    q = normalize_query(
        parse_qs(parsed.query, keep_blank_values=True)
    )

    if not host:
        return None

    password = password or first(q, "auth", "")
    if not password:
        return None

    proxy = {
        "name": make_name(
            "hysteria",
            host,
            port,
            remark_from_url(parsed),
        ),
        "type": "hysteria",
        "server": host,
        "port": port,
        "password": password,
        "udp": True,
    }

    for source, target in (
        ("protocol", "protocol"),
        ("obfs", "obfs"),
        ("sni", "sni"),
        ("peer", "sni"),
        ("up", "up"),
        ("down", "down"),
    ):
        value = first(q, source, "")
        if value:
            proxy[target] = value

    known = {
        "auth", "protocol", "obfs", "sni", "peer", "up", "down",
    }
    set_unknown(proxy, unknown_query_params(q, known))
    return proxy


def parse_hysteria2(line):
    parsed = urlparse(line)
    host = parsed.hostname or ""
    port = parsed.port or 443
    password = parsed.username or ""

    q = normalize_query(
        parse_qs(parsed.query, keep_blank_values=True)
    )

    if not host or not password:
        return None

    proxy = {
        "name": make_name(
            "hysteria2",
            host,
            port,
            remark_from_url(parsed),
        ),
        "type": "hysteria2",
        "server": host,
        "port": port,
        "password": password,
        "udp": True,
    }

    for source, target in (
        ("sni", "sni"),
        ("obfs", "obfs"),
        ("obfs-password", "obfs-password"),
        ("up", "up"),
        ("down", "down"),
    ):
        value = first(q, source, "")
        if value:
            proxy[target] = value

    alpn = parse_alpn(first(q, "alpn", ""))
    if alpn:
        proxy["alpn"] = alpn

    fp = first(q, "fingerprint", "")
    if fp:
        proxy["fingerprint"] = fp

    insecure = first(q, "insecure", "")
    if insecure != "":
        proxy["skip-cert-verify"] = bool_value(insecure)

    known = {
        "sni", "obfs", "obfs-password", "up", "down",
        "alpn", "fingerprint", "insecure",
    }
    set_unknown(proxy, unknown_query_params(q, known))
    return proxy


def parse_tuic(line):
    parsed = urlparse(line)
    host = parsed.hostname or ""
    port = parsed.port or 443
    username = parsed.username or ""
    password = parsed.password or ""

    q = normalize_query(
        parse_qs(parsed.query, keep_blank_values=True)
    )

    if not host or not username or not password:
        return None

    proxy = {
        "name": make_name(
            "tuic",
            host,
            port,
            remark_from_url(parsed),
        ),
        "type": "tuic",
        "server": host,
        "port": port,
        "uuid": username,
        "password": password,
        "udp": True,
    }

    congestion = first_any(
        q,
        ("congestion_control", "congestion-control"),
        "",
    )
    if congestion:
        proxy["congestion-controller"] = congestion

    for key in ("sni", "udp_relay_mode", "udp-relay-mode"):
        value = first(q, key, "")
        if value:
            proxy[
                "udp-relay-mode"
                if key == "udp_relay_mode"
                else key
            ] = value

    alpn = parse_alpn(first(q, "alpn", ""))
    if alpn:
        proxy["alpn"] = alpn

    disable_sni = first(q, "disable_sni", "")
    if disable_sni != "":
        proxy["disable-sni"] = bool_value(disable_sni)

    known = {
        "congestion_control", "congestion-control", "sni",
        "udp_relay_mode", "udp-relay-mode", "alpn", "disable_sni",
    }
    set_unknown(proxy, unknown_query_params(q, known))
    return proxy


def parse_wireguard(line):
    parsed = urlparse(line)
    host = parsed.hostname or ""
    port = parsed.port or 51820
    private_key = parsed.username or ""

    q = normalize_query(
        parse_qs(parsed.query, keep_blank_values=True)
    )

    private_key = private_key or first(q, "privatekey", "")
    public_key = first_any(
        q,
        ("publickey", "public-key"),
        "",
    )

    if not host or not private_key:
        return None

    proxy = {
        "name": make_name(
            "wireguard",
            host,
            port,
            remark_from_url(parsed),
        ),
        "type": "wireguard",
        "server": host,
        "port": port,
        "private-key": private_key,
        "udp": True,
    }

    if public_key:
        proxy["public-key"] = public_key

    ip_value = first(q, "ip", "")
    if ip_value:
        proxy["ip"] = [
            x.strip() for x in ip_value.split(",") if x.strip()
        ]

    ipv6_value = first(q, "ipv6", "")
    if ipv6_value:
        proxy["ipv6"] = [
            x.strip() for x in ipv6_value.split(",") if x.strip()
        ]

    mtu = safe_int(first(q, "mtu", ""), 0)
    if mtu:
        proxy["mtu"] = mtu

    reserved = first(q, "reserved", "")
    if reserved:
        try:
            proxy["reserved"] = [
                int(x) for x in reserved.split(",") if x.strip()
            ]
        except Exception:
            pass

    known = {
        "privatekey", "publickey", "public-key", "ip", "ipv6",
        "mtu", "reserved",
    }
    set_unknown(proxy, unknown_query_params(q, known))
    return proxy


PARSERS = {
    "vless://": parse_vless,
    "vmess://": parse_vmess,
    "trojan://": parse_trojan,
    "ss://": parse_ss,
    "ssr://": parse_ssr,
    "hysteria2://": parse_hysteria2,
    "hy2://": parse_hysteria2,
    "hysteria://": parse_hysteria,
    "tuic://": parse_tuic,
    "wireguard://": parse_wireguard,
}


# ============================================================
# INPUT / SUBSCRIPTION INTELLIGENCE
# ============================================================

def looks_like_base64(line):
    if "://" in line:
        return False
    if len(line) < 16:
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9+/=_\-]+", line))


def expand_input_lines(content):
    links = []
    unsupported = []

    for raw in content.splitlines():
        line = raw.strip().lstrip("\ufeff")
        if not line or line.startswith("#"):
            continue

        if "://" in line:
            links.append(line)
            continue

        if looks_like_base64(line):
            decoded = (
                b64decode_text(line)
                or b64decode_urlsafe(line)
            )
            if decoded and "://" in decoded:
                found = False
                for item in decoded.splitlines():
                    item = item.strip()
                    if item and "://" in item:
                        links.append(item)
                        found = True
                if found:
                    continue

        unsupported.append(line)

    return links, unsupported


def parse_link(line):
    line = line.strip().lstrip("\ufeff")
    lower = line.lower()

    if lower.startswith("hy2://"):
        line = "hysteria2://" + line[len("hy2://"):]
        lower = line.lower()

    for prefix, parser in PARSERS.items():
        if lower.startswith(prefix):
            try:
                return parser(line)
            except Exception:
                return None

    return None


# ============================================================
# VALIDATION / NORMALIZATION
# ============================================================

def valid_hostname(host):
    if not host:
        return False

    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass

    if len(host) > 253:
        return False

    return bool(
        re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9.\-_]*",
            host,
        )
    )


def validate_proxy(proxy):
    if not isinstance(proxy, dict):
        return False, "not-object"

    for key in ("name", "type", "server", "port"):
        if not proxy.get(key):
            return False, f"missing-{key}"

    if not isinstance(proxy["port"], int):
        return False, "invalid-port"

    if not 1 <= proxy["port"] <= 65535:
        return False, "port-range"

    if not valid_hostname(str(proxy["server"])):
        return False, "invalid-server"

    required = {
        "vless": ("uuid",),
        "vmess": ("uuid",),
        "trojan": ("password",),
        "ss": ("cipher", "password"),
        "ssr": ("cipher", "password"),
        "hysteria": ("password",),
        "hysteria2": ("password",),
        "tuic": ("uuid", "password"),
        "wireguard": ("private-key",),
    }

    ptype = proxy["type"]
    if ptype not in required:
        return False, f"unsupported-type:{ptype}"

    for key in required[ptype]:
        if not proxy.get(key):
            return False, f"missing-{key}"

    return True, ""


def normalize_proxy(proxy):
    proxy["name"] = sanitize_name(proxy.get("name"))
    proxy["server"] = clean_text(proxy.get("server"))
    proxy["port"] = safe_int(proxy.get("port"), 0)

    if "udp" not in proxy:
        proxy["udp"] = True

    if proxy.get("network") == "tcp":
        # TCP is Mihomo's normal default; keeping the field is harmless.
        pass

    return proxy


# ============================================================
# DEDUPLICATION
# ============================================================

def exact_signature(proxy):
    data = {
        "type": proxy.get("type"),
        "server": proxy.get("server"),
        "port": proxy.get("port"),
        "uuid": proxy.get("uuid"),
        "password": proxy.get("password"),
        "cipher": proxy.get("cipher"),
        "private-key": proxy.get("private-key"),
        "public-key": proxy.get("public-key"),
        "network": proxy.get("network"),
        "servername": proxy.get("servername"),
        "flow": proxy.get("flow"),
        "tls": proxy.get("tls"),
        "skip-cert-verify": proxy.get("skip-cert-verify"),
        "reality-opts": proxy.get("reality-opts"),
        "ws-opts": proxy.get("ws-opts"),
        "grpc-opts": proxy.get("grpc-opts"),
        "h2-opts": proxy.get("h2-opts"),
        "http-upgrade-opts": proxy.get("http-upgrade-opts"),
        "xhttp-opts": proxy.get("xhttp-opts"),
        "split-http-opts": proxy.get("split-http-opts"),
        "alpn": proxy.get("alpn"),
    }
    return sha256_text(canonical_json(data))


def smart_signature(proxy):
    """
    Endpoint/config identity without the display name.
    UUID/password/private-key and security parameters remain part
    of the identity. This deliberately avoids merging distinct
    Reality/SNI credentials.
    """
    identity = {
        "type": proxy.get("type"),
        "server": proxy.get("server"),
        "port": proxy.get("port"),
        "uuid": proxy.get("uuid"),
        "password": proxy.get("password"),
        "private-key": proxy.get("private-key"),
        "public-key": proxy.get("public-key"),
        "network": proxy.get("network"),
        "tls": proxy.get("tls"),
        "servername": proxy.get("servername"),
        "flow": proxy.get("flow"),
        "reality-opts": proxy.get("reality-opts"),
        "ws-opts": proxy.get("ws-opts"),
        "grpc-opts": proxy.get("grpc-opts"),
        "h2-opts": proxy.get("h2-opts"),
        "http-upgrade-opts": proxy.get("http-upgrade-opts"),
        "xhttp-opts": proxy.get("xhttp-opts"),
        "split-http-opts": proxy.get("split-http-opts"),
        "cipher": proxy.get("cipher"),
        "obfs": proxy.get("obfs"),
        "protocol": proxy.get("protocol"),
    }
    return sha256_text(canonical_json(identity))


# ============================================================
# DNS / TCP INTELLIGENCE
# ============================================================

def resolve_host(host):
    """
    One cached DNS operation per hostname.
    IPv4 and IPv6 addresses are retained separately.
    """
    key = host.lower().strip()

    cached = cache_get(
        "dns",
        key,
        DNS_TTL,
    )
    if cached is not None:
        return (
            bool(cached.get("ok")),
            cached.get("ms"),
            cached.get("addresses", []),
            cached.get("error", ""),
            True,
        )

    start = time.monotonic()
    addresses = []

    try:
        infos = socket.getaddrinfo(
            host,
            None,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM,
        )

        for family, _, _, _, sockaddr in infos:
            if not sockaddr:
                continue
            address = sockaddr[0]
            family_name = (
                "IPv6" if family == socket.AF_INET6 else "IPv4"
            )
            addresses.append({
                "address": address,
                "family": family_name,
            })

        # Preserve order but remove duplicates.
        seen = set()
        unique = []
        for item in addresses:
            key2 = (item["address"], item["family"])
            if key2 not in seen:
                seen.add(key2)
                unique.append(item)
        addresses = unique

        elapsed = int(
            (time.monotonic() - start) * 1000
        )

        data = {
            "ok": bool(addresses),
            "ms": elapsed,
            "addresses": addresses,
            "error": "" if addresses else "DNS returned no addresses",
        }
        cache_put("dns", key, data)

        return (
            data["ok"],
            elapsed,
            addresses,
            data["error"],
            False,
        )

    except Exception as exc:
        elapsed = int(
            (time.monotonic() - start) * 1000
        )
        data = {
            "ok": False,
            "ms": elapsed,
            "addresses": [],
            "error": str(exc),
        }
        cache_put("dns", key, data)
        return False, elapsed, [], str(exc), False


def connect_one(address, family, port, timeout):
    sock = None
    try:
        family_code = (
            socket.AF_INET6
            if family == "IPv6"
            else socket.AF_INET
        )
        start = time.monotonic()
        sock = socket.socket(
            family_code,
            socket.SOCK_STREAM,
        )
        sock.settimeout(timeout)

        target = (
            (address, int(port), 0, 0)
            if family_code == socket.AF_INET6
            else (address, int(port))
        )

        sock.connect(target)
        elapsed = int(
            (time.monotonic() - start) * 1000
        )
        return True, elapsed, ""
    except Exception as exc:
        return False, None, str(exc)
    finally:
        try:
            if sock:
                sock.close()
        except Exception:
            pass


def tcp_probe(proxy, stats=None):
    host = str(proxy["server"])
    port = int(proxy["port"])

    dns_ok, dns_ms, addresses, dns_error, dns_cached = (
        resolve_host(host)
    )

    if dns_cached and stats is not None:
        stats.dns_cache_hits += 1

    if not dns_ok:
        return TestResult(
            dns_ok=False,
            tcp_ok=False,
            dns_ms=dns_ms,
            error=f"DNS: {dns_error}",
            cached_dns=dns_cached,
        )

    # Prefer IPv4 first for mobile stability, but IPv6 is attempted.
    ordered = sorted(
        addresses,
        key=lambda x: 0 if x["family"] == "IPv4" else 1,
    )

    best_ms = None
    best_family = ""
    last_error = ""

    for item in ordered:
        for _ in range(SETTINGS["attempts"]):
            ok, elapsed, error = connect_one(
                item["address"],
                item["family"],
                port,
                SETTINGS["timeout"],
            )
            if ok:
                if best_ms is None or elapsed < best_ms:
                    best_ms = elapsed
                    best_family = item["family"]
                break
            last_error = error

        if best_ms is not None and best_ms <= 120:
            break

    return TestResult(
        dns_ok=True,
        tcp_ok=best_ms is not None,
        dns_ms=dns_ms,
        tcp_ms=best_ms,
        addresses=addresses,
        selected_family=best_family,
        error="" if best_ms is not None else last_error,
        cached_dns=dns_cached,
    )


# ============================================================
# RESULT CACHE
# ============================================================

def test_fingerprint(proxy):
    data = {
        "type": proxy.get("type"),
        "server": proxy.get("server"),
        "port": proxy.get("port"),
        "uuid": proxy.get("uuid"),
        "password": proxy.get("password"),
        "private-key": proxy.get("private-key"),
        "network": proxy.get("network"),
        "tls": proxy.get("tls"),
        "servername": proxy.get("servername"),
        "flow": proxy.get("flow"),
        "reality-opts": proxy.get("reality-opts"),
        "ws-opts": proxy.get("ws-opts"),
        "grpc-opts": proxy.get("grpc-opts"),
        "h2-opts": proxy.get("h2-opts"),
    }
    return sha256_text(canonical_json(data))


def cached_test(proxy, stats):
    fp = test_fingerprint(proxy)
    item = cache_get(
        "fingerprints",
        fp,
        TCP_TTL,
    )
    if item is None:
        return None

    stats.cache_hits += 1
    return item


def store_test(proxy, result):
    fp = test_fingerprint(proxy)
    cache_put(
        "fingerprints",
        fp,
        {
            "dns_ok": result.dns_ok,
            "tcp_ok": result.tcp_ok,
            "dns_ms": result.dns_ms,
            "tcp_ms": result.tcp_ms,
            "addresses": result.addresses,
            "selected_family": result.selected_family,
            "error": result.error,
            "mode": TEST_MODE,
        },
    )


def test_proxy(proxy):
    # Thread-safe enough for independent dict reads/writes in CPython;
    # cache writes are serialized later in the main process.
    result = tcp_probe(proxy)

    proxy["_test"] = {
        "dns_ok": result.dns_ok,
        "tcp_ok": result.tcp_ok,
        "dns_ms": result.dns_ms,
        "tcp_ms": result.tcp_ms,
        "addresses": result.addresses,
        "selected_family": result.selected_family,
        "error": result.error,
        "cached_dns": result.cached_dns,
        "cached_tcp": False,
    }
    return proxy, result


# ============================================================
# SCORING 100 POINTS
# DNS 10 / TCP 30 / LATENCY 30 / PROTOCOL 20 / CONFIG 10
# ============================================================

KNOWN_PROTOCOLS = {
    "vless", "vmess", "trojan", "ss", "ssr",
    "hysteria", "hysteria2", "tuic", "wireguard",
}


def latency_score(ms):
    if ms is None:
        return 0
    if ms <= 50:
        return 30
    if ms <= 100:
        return 27
    if ms <= 150:
        return 24
    if ms <= 200:
        return 21
    if ms <= 300:
        return 17
    if ms <= 500:
        return 12
    if ms <= 800:
        return 7
    if ms <= 1200:
        return 3
    return 1


def protocol_score(proxy):
    return 20 if proxy.get("type") in KNOWN_PROTOCOLS else 0


def config_score(proxy):
    ptype = proxy.get("type")
    required = {
        "vless": ("uuid",),
        "vmess": ("uuid",),
        "trojan": ("password",),
        "ss": ("cipher", "password"),
        "ssr": ("cipher", "password"),
        "hysteria": ("password",),
        "hysteria2": ("password",),
        "tuic": ("uuid", "password"),
        "wireguard": ("private-key",),
    }
    req = required.get(ptype, ())
    if not req:
        return 0
    present = sum(bool(proxy.get(k)) for k in req)
    return round(10 * present / len(req))


def score_proxy(proxy):
    test = proxy.get("_test", {})
    dns = 10 if test.get("dns_ok") else 0
    tcp = 30 if test.get("tcp_ok") else 0
    lat = latency_score(test.get("tcp_ms"))
    proto = protocol_score(proxy)
    conf = config_score(proxy)
    return max(0, min(100, dns + tcp + lat + proto + conf))


# ============================================================
# MIHOMO COMPATIBILITY CHECKER
# ============================================================

# These are the keys emitted by this converter for the supported
# protocol families. The checker is deliberately conservative:
# it rejects structurally dangerous fields but does not throw away
# unknown SOURCE parameters that were already recorded in the report.

COMMON_PROXY_KEYS = {
    "name", "type", "server", "port", "udp", "tls", "servername",
    "skip-cert-verify", "alpn", "client-fingerprint", "network",
    "ws-opts", "grpc-opts", "h2-opts", "http-upgrade-opts",
    "xhttp-opts", "split-http-opts", "flow", "reality-opts",
    "packet-encoding", "xudp", "sni", "password", "uuid",
    "encryption", "alterId", "cipher", "protocol", "obfs",
    "up", "down", "obfs-password", "fingerprint",
    "congestion-controller", "udp-relay-mode", "disable-sni",
    "private-key", "public-key", "ip", "ipv6", "mtu", "reserved",
}


def mihomo_check_proxy(proxy):
    ok, reason = validate_proxy(proxy)
    if not ok:
        return False, reason

    if not isinstance(proxy.get("name"), str):
        return False, "name-not-string"

    if len(proxy["name"]) > 100:
        return False, "name-too-long"

    ptype = proxy["type"]

    if ptype == "vless":
        if proxy.get("encryption") not in (None, "none"):
            return False, "vless-encryption"

    if ptype in {"vless", "vmess", "trojan"}:
        network = proxy.get("network", "tcp")
        if network not in {
            "tcp", "ws", "grpc", "http", "h2",
            "httpupgrade", "splithttp", "xhttp",
        }:
            return False, f"unsupported-network:{network}"

    reality = proxy.get("reality-opts")
    if reality is not None and not isinstance(reality, dict):
        return False, "reality-opts-not-map"

    for key in ("ws-opts", "grpc-opts", "h2-opts",
                "http-upgrade-opts", "xhttp-opts",
                "split-http-opts"):
        if key in proxy and not isinstance(proxy[key], dict):
            return False, f"{key}-not-map"

    return True, ""


def mihomo_check_config(config):
    if not isinstance(config, dict):
        return False, ["root-not-map"]

    errors = []

    proxies = config.get("proxies")
    groups = config.get("proxy-groups")
    rules = config.get("rules")

    if not isinstance(proxies, list) or not proxies:
        errors.append("proxies-missing-or-empty")

    if not isinstance(groups, list) or not groups:
        errors.append("proxy-groups-missing-or-empty")

    if not isinstance(rules, list) or not rules:
        errors.append("rules-missing-or-empty")

    names = []
    if isinstance(proxies, list):
        for proxy in proxies:
            ok, reason = mihomo_check_proxy(proxy)
            if not ok:
                errors.append(
                    f"proxy:{proxy.get('name', '?')}:{reason}"
                )
            names.append(proxy.get("name"))

    if len(names) != len(set(names)):
        errors.append("proxy-names-not-unique")

    name_set = set(names)

    if isinstance(groups, list):
        group_names = set()
        for group in groups:
            if not isinstance(group, dict):
                errors.append("group-not-map")
                continue

            gname = group.get("name")
            gtype = group.get("type")
            refs = group.get("proxies", [])

            if not gname:
                errors.append("group-name-missing")
            if gname in group_names:
                errors.append(f"duplicate-group:{gname}")
            group_names.add(gname)

            if gtype not in {"select", "url-test"}:
                errors.append(
                    f"group:{gname}:unsupported-type:{gtype}"
                )

            if not isinstance(refs, list) or not refs:
                errors.append(
                    f"group:{gname}:empty-proxies"
                )
            else:
                for ref in refs:
                    if ref not in name_set:
                        errors.append(
                            f"group:{gname}:missing-ref:{ref}"
                        )

            if gtype == "url-test":
                if not group.get("url"):
                    errors.append(f"group:{gname}:missing-url")
                if not safe_int(group.get("interval"), 0):
                    errors.append(
                        f"group:{gname}:missing-interval"
                    )

    if isinstance(rules, list):
        for rule in rules:
            if not isinstance(rule, str):
                errors.append("rule-not-string")
                continue
            parts = [x.strip() for x in rule.split(",")]
            if not parts or not parts[0]:
                errors.append("rule-empty")
                continue
            if parts[0] == "MATCH":
                if len(parts) != 2:
                    errors.append("MATCH-rule-invalid")
                elif parts[1] not in name_set and parts[1] not in {
                    g.get("name")
                    for g in groups
                    if isinstance(g, dict)
                }:
                    errors.append(
                        f"rule-target-missing:{parts[1]}"
                    )

    return not errors, errors


# ============================================================
# YAML OUTPUT
# ============================================================

def remove_internal(proxy):
    return {
        k: v
        for k, v in proxy.items()
        if not str(k).startswith("_")
    }


def build_dns():
    return {
        "enable": True,
        "ipv6": True,
        "enhanced-mode": "fake-ip",
        "fake-ip-range": "198.18.0.1/16",
        "nameserver": [
            "1.1.1.1",
            "8.8.8.8",
        ],
        "fallback": [
            "1.0.0.1",
            "8.8.4.4",
        ],
        "fallback-filter": {
            "geoip": True,
            "geoip-code": "IR",
        },
    }


def build_groups(names):
    return [
        {
            "name": GROUP_MANUAL,
            "type": "select",
            "proxies": names,
        },
        {
            "name": GROUP_AUTO,
            "type": "url-test",
            "proxies": names,
            "url": HEALTH_URL,
            "interval": URL_TEST_INTERVAL,
            "timeout": URL_TEST_TIMEOUT,
            "lazy": False,
        },
    ]


def build_config(proxies):
    clean = [remove_internal(p) for p in proxies]
    names = [p["name"] for p in clean]

    # IMPORTANT:
    # GROUP TARGETS ARE ACTUAL GROUP NAMES.
    # This avoids the previous rule-target-missing:PROXY failure.
    return {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "ipv6": True,
        "unified-delay": True,
        "tcp-concurrent": True,
        "profile": {
            "store-selected": True,
            "store-fake-ip": True,
        },
        "proxies": clean,
        "proxy-groups": build_groups(names),
        "rules": [
            f"MATCH,{GROUP_MANUAL}",
        ],
        "dns": build_dns(),
    }


def dump_yaml_atomic(config, out_path):
    tmp = out_path.with_suffix(".yaml.tmp")
    try:
        with tmp.open("w", encoding="utf-8") as f:
            yaml.safe_dump(
                config,
                f,
                allow_unicode=True,
                sort_keys=False,
                default_flow_style=False,
                width=160,
            )
        return tmp
    except Exception:
        try:
            tmp.unlink()
        except Exception:
            pass
        raise


# ============================================================
# TESTING PIPELINE
# ============================================================

def adaptive_workers(count):
    if count <= 100:
        return 8
    if count <= 500:
        return 16
    if count <= 2000:
        return 24
    return min(32, MAX_WORKERS_CAP)


def apply_cached_or_test(proxy, stats):
    cached = cached_test(proxy, stats)
    if cached is not None:
        proxy["_test"] = {
            **cached,
            "cached_tcp": True,
        }
        return proxy, None

    return None, proxy


def test_in_batches(proxies, stats):
    workers = adaptive_workers(len(proxies))
    batch_size = SETTINGS["batch"]

    print(
        f"[TEST] mode={TEST_MODE} batch={batch_size} "
        f"workers={workers} timeout={SETTINGS['timeout']}s "
        f"attempts={SETTINGS['attempts']}"
    )

    output = []

    for start in range(0, len(proxies), batch_size):
        batch = proxies[start:start + batch_size]

        batch_ready = []
        batch_new = []

        for proxy in batch:
            ready, pending = apply_cached_or_test(
                proxy,
                stats,
            )
            if ready is not None:
                output.append(ready)
            else:
                batch_new.append(pending)

        if batch_new:
            with ThreadPoolExecutor(
                max_workers=min(workers, len(batch_new))
            ) as executor:
                futures = {
                    executor.submit(
                        test_proxy,
                        p,
                    ): p
                    for p in batch_new
                }

                for future in as_completed(futures):
                    original = futures[future]
                    try:
                        tested, result = future.result()
                        output.append(tested)
                        store_test(original, result)
                        stats.tested += 1
                    except Exception as exc:
                        original["_test"] = {
                            "dns_ok": False,
                            "tcp_ok": False,
                            "dns_ms": None,
                            "tcp_ms": None,
                            "addresses": [],
                            "selected_family": "",
                            "error": str(exc),
                            "cached_tcp": False,
                        }
                        output.append(original)
                        stats.tested += 1

        end = min(start + batch_size, len(proxies))
        print(
            f"[TEST] {start + 1}-{end}/{len(proxies)} "
            f"| cache={stats.cache_hits} "
            f"| dns-cache={stats.dns_cache_hits}"
        )

    return output


# ============================================================
# REPORTS
# ============================================================

def write_report(path, proxies, stats, unsupported):
    with path.open("w", encoding="utf-8") as f:
        f.write("AKBAR98 ADVANCED PROXY CONVERTER REPORT\n")
        f.write("=" * 78 + "\n")
        f.write(
            f"Generated: "
            f"{datetime.now().isoformat(timespec='seconds')}\n"
        )
        f.write(f"Mode: {TEST_MODE}\n")
        f.write("Test: DNS + TCP connection-only; NO HTTP DOWNLOAD\n")
        f.write("\nSUMMARY\n")
        f.write("-" * 78 + "\n")
        f.write(f"Input lines           : {stats.input_lines}\n")
        f.write(f"Extracted links       : {stats.extracted_links}\n")
        f.write(f"Parsed                : {stats.parsed}\n")
        f.write(f"Exact duplicate       : {stats.duplicates_exact}\n")
        f.write(f"Smart duplicate       : {stats.duplicates_smart}\n")
        f.write(f"Invalid               : {stats.invalid}\n")
        f.write(f"Unsupported           : {stats.unsupported}\n")
        f.write(f"TCP reachable         : {stats.tcp_ok}\n")
        f.write(f"TCP unreachable       : {stats.tcp_failed}\n")
        f.write(f"Result-cache hits     : {stats.cache_hits}\n")
        f.write(f"DNS-cache hits        : {stats.dns_cache_hits}\n")
        f.write(f"Final YAML proxies    : {stats.final}\n")

        f.write("\nBY TYPE\n")
        f.write("-" * 78 + "\n")
        for key in sorted(stats.by_type):
            f.write(
                f"{key:18} {stats.by_type[key]}\n"
            )

        f.write("\nPROXY DETAILS\n")
        f.write("-" * 78 + "\n")

        for proxy in proxies:
            test = proxy.get("_test", {})
            status = (
                "TCP_OK"
                if test.get("tcp_ok")
                else "TCP_FAIL"
            )

            unknown = ",".join(
                proxy.get("_unknown", [])
            ) or "-"

            f.write(
                f"{proxy.get('name')} | "
                f"{proxy.get('type')} | "
                f"{proxy.get('server')}:{proxy.get('port')} | "
                f"DNS_OK={test.get('dns_ok')} | "
                f"TCP_OK={test.get('tcp_ok')} | "
                f"FAMILY={test.get('selected_family') or '-'} | "
                f"DNS_MS={test.get('dns_ms')} | "
                f"TCP_MS={test.get('tcp_ms')} | "
                f"STATUS={status} | "
                f"PROTOCOL_UNKNOWN=YES | "
                f"SCORE={score_proxy(proxy)} | "
                f"UNKNOWN={unknown}\n"
            )

        if unsupported:
            f.write("\nUNSUPPORTED / UNDECODABLE INPUT\n")
            f.write("-" * 78 + "\n")
            for item in unsupported:
                f.write(item + "\n")


def write_failed(path, failed, unsupported):
    with path.open("w", encoding="utf-8") as f:
        for item in failed:
            f.write(item + "\n")
        for item in unsupported:
            f.write("[UNSUPPORTED_OR_UNDECODED] " + item + "\n")


# ============================================================
# INPUT EDITOR
# ============================================================

def prepare_input():
    """
    Keeps the original input workflow:
    input_mobile.txt is emptied before nano opens.
    """
    try:
        BASE_DIR.mkdir(parents=True, exist_ok=True)
        INPUT_PATH.write_text("", encoding="utf-8")
        subprocess.call(["nano", str(INPUT_PATH)])
        return True
    except Exception as exc:
        print(f"[ERROR] Cannot open nano: {exc}")
        print(f"[INFO] Input: {INPUT_PATH}")
        return False


def clear_input():
    try:
        INPUT_PATH.write_text("", encoding="utf-8")
    except Exception:
        pass


# ============================================================
# MAIN
# ============================================================

def main():
    print()
    print("=" * 78)
    print("AKBAR98 ADVANCED PROXY CONVERTER - FINAL ENGINE")
    print("=" * 78)
    print(f"[MODE] {TEST_MODE}")
    print("[TEST] DNS -> TCP -> END")
    print("[TEST] HTTP/download probe: OFF")
    print("[CACHE] DNS TTL=5m | TCP result TTL=10m")
    print("[OUTPUT] YAML is the primary output")
    print("=" * 78)

    if not prepare_input():
        return 1

    # Preserve the base-code output workflow exactly:
    out_folder = input(
        "Enter output folder name in Download: "
    ).strip()

    if not out_folder:
        print("[ERROR] Folder name required.")
        clear_input()
        return 1

    out_name = input(
        "Enter output file name (without extension): "
    ).strip()

    if not out_name:
        print("[ERROR] File name required.")
        clear_input()
        return 1

    # Prevent path traversal while still allowing ordinary folder names.
    out_folder = os.path.basename(out_folder)
    out_name = os.path.basename(out_name)

    out_dir = DOWNLOAD_DIR / out_folder
    out_dir.mkdir(parents=True, exist_ok=True)

    out_path = out_dir / f"{out_name}.yaml"
    report_path = out_dir / f"{out_name}_report.txt"
    failed_path = out_dir / f"{out_name}_failed.txt"

    try:
        content = INPUT_PATH.read_text(
            encoding="utf-8"
        )
    except Exception as exc:
        print(f"[ERROR] Cannot read input: {exc}")
        clear_input()
        return 1

    # Input is cleared immediately after reading.
    clear_input()

    raw_lines = [
        x for x in content.splitlines()
        if x.strip() and not x.strip().startswith("#")
    ]

    stats = Stats(input_lines=len(raw_lines))

    links, unsupported = expand_input_lines(content)
    stats.extracted_links = len(links)
    stats.unsupported = len(unsupported)

    print()
    print("[1/8] Input decoder / subscription extraction...")
    print(f"[INPUT] lines={stats.input_lines} links={len(links)}")
    print(f"[INPUT] unsupported/undecoded={len(unsupported)}")

    # --------------------------------------------------------
    # PARSE
    # --------------------------------------------------------

    print("[2/8] Smart parsers + normalization...")

    proxies = []
    failed = []

    for line in links:
        proxy = parse_link(line)

        if proxy is None:
            failed.append(line)
            continue

        valid, reason = validate_proxy(proxy)
        if not valid:
            failed.append(
                f"[{reason}] {line}"
            )
            continue

        proxy = normalize_proxy(proxy)
        proxies.append(proxy)

    stats.parsed = len(proxies)
    stats.invalid = len(failed)

    # --------------------------------------------------------
    # DEDUP EXACT
    # --------------------------------------------------------

    print("[3/8] Exact deduplication...")

    exact_seen = set()
    exact_unique = []

    for proxy in proxies:
        sig = exact_signature(proxy)
        if sig in exact_seen:
            stats.duplicates_exact += 1
            continue
        exact_seen.add(sig)
        exact_unique.append(proxy)

    # --------------------------------------------------------
    # DEDUP SMART
    # --------------------------------------------------------

    print("[4/8] Smart deduplication...")

    smart_seen = set()
    unique = []

    for proxy in exact_unique:
        sig = smart_signature(proxy)
        if sig in smart_seen:
            stats.duplicates_smart += 1
            continue
        smart_seen.add(sig)
        unique.append(proxy)

    proxies = unique

    for proxy in proxies:
        ptype = proxy["type"]
        stats.by_type[ptype] = (
            stats.by_type.get(ptype, 0) + 1
        )

    print(
        f"[PARSE] valid={stats.parsed} "
        f"exact-dup={stats.duplicates_exact} "
        f"smart-dup={stats.duplicates_smart} "
        f"remaining={len(proxies)}"
    )

    if not proxies:
        write_failed(
            failed_path,
            failed,
            unsupported,
        )
        print("[ERROR] No valid proxy found.")
        return 1

    # --------------------------------------------------------
    # TEST
    # --------------------------------------------------------

    print("[5/8] DNS cache + IPv4/IPv6 + TCP Lite...")

    proxies = test_in_batches(
        proxies,
        stats,
    )

    stats.tcp_ok = sum(
        1 for p in proxies
        if p.get("_test", {}).get("tcp_ok")
    )
    stats.tcp_failed = len(proxies) - stats.tcp_ok

    # Score all parsed proxies. TCP result is metadata only.
    proxies.sort(
        key=lambda p: (
            -score_proxy(p),
            p.get("_test", {}).get("tcp_ms")
            if p.get("_test", {}).get("tcp_ms") is not None
            else 999999,
            p.get("name", ""),
        )
    )

    # --------------------------------------------------------
    # COMPATIBILITY
    # --------------------------------------------------------

    print("[6/8] Mihomo compatibility/schema checker...")

    compatible = []
    compatibility_failed = []

    for proxy in proxies:
        ok, reason = mihomo_check_proxy(proxy)
        if ok:
            compatible.append(proxy)
        else:
            compatibility_failed.append(
                f"[MIHOMO:{reason}] {proxy.get('name')}"
            )

    # Do NOT silently delete compatibility failures.
    # They are written to failed report and are excluded from YAML
    # because an invalid Mihomo proxy would make the final config bad.
    failed.extend(compatibility_failed)

    proxies = compatible

    if not proxies:
        print("[ERROR] No Mihomo-compatible proxy remains.")
        write_failed(
            failed_path,
            failed,
            unsupported,
        )
        return 1

    # --------------------------------------------------------
    # BUILD
    # --------------------------------------------------------

    print("[7/8] Building FINAL YAML...")

    config = build_config(proxies)

    # --------------------------------------------------------
    # FINAL VALIDATION BEFORE REPLACEMENT
    # --------------------------------------------------------

    print("[8/8] Final YAML validation...")

    ok, errors = mihomo_check_config(config)

    if not ok:
        print("[ERROR] Final YAML validation failed.")
        for error in errors:
            print(f"  - {error}")

        write_failed(
            failed_path,
            failed,
            unsupported,
        )
        return 1

    # Validate serialization itself before replacing any old YAML.
    tmp_path = out_path.with_suffix(".yaml.tmp")

    try:
        yaml.safe_dump(
            config,
            tmp_path.open("w", encoding="utf-8"),
            allow_unicode=True,
            sort_keys=False,
            default_flow_style=False,
            width=160,
        )

        parsed_back = yaml.safe_load(
            tmp_path.read_text(encoding="utf-8")
        )

        ok2, errors2 = mihomo_check_config(parsed_back)
        if not ok2:
            print("[ERROR] Serialized YAML validation failed.")
            for error in errors2:
                print(f"  - {error}")
            tmp_path.unlink(missing_ok=True)
            write_failed(
                failed_path,
                failed,
                unsupported,
            )
            return 1

    except Exception as exc:
        try:
            tmp_path.unlink()
        except Exception:
            pass
        print(f"[ERROR] YAML serialization failed: {exc}")
        return 1

    # --------------------------------------------------------
    # ATOMIC OUTPUT REPLACEMENT
    # --------------------------------------------------------

    if out_path.exists():
        backup = out_dir / (
            f"{out_path.stem}_backup_"
            f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.yaml"
        )
        try:
            shutil.copy2(out_path, backup)
            print(f"[BACKUP] {backup}")
        except Exception as exc:
            print(f"[WARNING] Backup failed: {exc}")

    try:
        os.replace(tmp_path, out_path)
    except Exception as exc:
        try:
            tmp_path.unlink()
        except Exception:
            pass
        print(f"[ERROR] Cannot replace final YAML: {exc}")
        return 1

    try:
        os.chmod(out_path, 0o644)
    except Exception:
        pass

    # --------------------------------------------------------
    # AUXILIARY REPORTS
    # --------------------------------------------------------

    stats.final = len(proxies)

    write_report(
        report_path,
        proxies,
        stats,
        unsupported,
    )

    write_failed(
        failed_path,
        failed,
        unsupported,
    )

    save_cache()

    print()
    print("=" * 78)
    print("DONE - FINAL OUTPUT")
    print("=" * 78)
    print(f"YAML       : {out_path}")
    print(f"Report     : {report_path}")
    print(f"Failed     : {failed_path}")
    print(f"Input      : {INPUT_PATH} (cleared)")
    print()
    print(f"Input lines       : {stats.input_lines}")
    print(f"Extracted links   : {stats.extracted_links}")
    print(f"Parsed            : {stats.parsed}")
    print(f"Exact duplicates  : {stats.duplicates_exact}")
    print(f"Smart duplicates  : {stats.duplicates_smart}")
    print(f"Invalid           : {stats.invalid}")
    print(f"Unsupported       : {stats.unsupported}")
    print(f"TCP reachable     : {stats.tcp_ok}")
    print(f"TCP unreachable   : {stats.tcp_failed}")
    print(f"Cache hits        : {stats.cache_hits}")
    print(f"DNS cache hits    : {stats.dns_cache_hits}")
    print(f"FINAL YAML        : {stats.final}")
    print()
    print("YAML contains:")
    print("  - proxies")
    print("  - Mobile-Fast❤ select group")
    print("  - Mobile-Auto❤ url-test group")
    print("  - DNS")
    print("  - MATCH -> Mobile-Fast❤")
    print()
    print("TCP_OK means TCP endpoint reachable only.")
    print("PROTOCOL_UNKNOWN remains separate; no HTTP download test was used.")
    print("=" * 78)

    clear_input()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\n[STOP] Cancelled by user.")
        raise SystemExit(130)
