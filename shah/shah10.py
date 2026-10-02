#!/data/data/com.termux/files/usr/bin/python3
# -*- coding: utf-8 -*-

"""
Akbar98 Advanced Proxy Converter
VLESS / VMess / Trojan / SS / SSR / Hysteria / Hysteria2 / TUIC / WireGuard
-> Mihomo / Clash Meta YAML

Design goals:
- Preserve supported source parameters instead of silently dropping them.
- Separate parsing, normalization, validation, testing, scoring and YAML output.
- Never treat a simple TCP connection as proof that a proxy protocol works.
- Keep all successfully parsed proxies by default; test results are metadata only.
- Generate a clean, validated Mihomo YAML.
- Designed for Termux / Android.
"""

import base64
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from copy import deepcopy
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
# CONFIG
# ============================================================

BASE_DIR = Path("/storage/emulated/0/Download/Akbar98")
INPUT_PATH = BASE_DIR / "input_mobile.txt"

DEFAULT_HEALTH_URL = "https://www.gstatic.com/generate_204"

# Automatic production settings — no questions asked.
MAX_WORKERS = 20
TCP_TIMEOUT = 2.5
TCP_ATTEMPTS = 2
URL_TEST_INTERVAL = 300
URL_TEST_TIMEOUT = 5000
ACTIVE_DATA_HEALTH_CHECK = False

# Keep the generated configuration conservative. The converter never
# claims that TCP reachability proves a proxy protocol is usable.

GROUP_MANUAL = "Mobile-Fast❤"
GROUP_AUTO = "Mobile-Auto❤"

BASE_DIR.mkdir(parents=True, exist_ok=True)


# ============================================================
# DATA
# ============================================================

@dataclass
class TestResult:
    dns_ok: bool = False
    tcp_ok: bool = False
    dns_ms: int | None = None
    tcp_ms: int | None = None
    error: str = ""


@dataclass
class Stats:
    input_lines: int = 0
    parsed: int = 0
    duplicates: int = 0
    failed: int = 0
    tcp_ok: int = 0
    tcp_failed: int = 0
    by_type: dict = field(default_factory=dict)


# ============================================================
# GLOBAL NAME STATE
# ============================================================

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

    if s in ("1", "true", "yes", "on"):
        return True

    if s in ("0", "false", "no", "off"):
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
    result = {}

    for key, values in q.items():
        normalized = []

        for value in values:
            value = clean_text(value)

            # Some subscription/link generators encode comma-separated
            # lists or use repeated parameters. Preserve both forms.
            normalized.append(value)

        result[str(key)] = normalized

    return result


def parse_bool_query(q, *keys, default=None):
    value = first_any(q, keys, "")
    if value == "":
        return default
    return bool_value(value, default=bool(default))


def add_if(proxy, key, value):
    if value is not None and value != "":
        proxy[key] = value


def normalize_network(value):
    value = clean_text(value).lower()

    aliases = {
        "websocket": "ws",
        "httpupgrade": "httpupgrade",
        "http-upgrade": "httpupgrade",
        "splithttp": "splithttp",
        "xhttp": "xhttp",
    }

    return aliases.get(value, value or "tcp")


def parse_alpn(value):
    if not value:
        return None

    parts = re.split(r"[,|]", clean_text(value))
    parts = [x.strip() for x in parts if x.strip()]
    return parts or None


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
            b64fix(value)
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


# ============================================================
# NAME MANAGEMENT
# ============================================================

def sanitize_name(value):
    value = clean_text(value)
    value = re.sub(r"[\x00-\x1F\x7F]", "", value)
    value = re.sub(r'[\\/:*?"<>|]', "", value)
    value = value.strip()

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
        if parsed.fragment:
            return sanitize_name(parsed.fragment)
    except Exception:
        pass
    return ""


def make_name(protocol, host, port, remark=""):
    if remark:
        return uniq_name(remark)
    return uniq_name(f"{protocol}-{host}-{port}")


# ============================================================
# COMMON MIHOMO OPTIONS
# ============================================================

def apply_tls_common(proxy, q, host, force_tls=False):
    security = first(q, "security", "").lower()

    tls = (
        force_tls
        or security in ("tls", "reality")
        or bool_value(first(q, "tls", ""))
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

    if security != "reality" and not bool_value(first(q, "reality", "")):
        return

    proxy["tls"] = True

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

    opts = {}

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
        path = (
            info.get("path")
            or first(q, "path", "/")
            or "/"
        )

        host_header = (
            info.get("host")
            or first_any(q, ("host", "Host"), "")
        )

        ws = {"path": path}

        if host_header:
            ws["headers"] = {"Host": host_header}

        max_early_data = first_any(
            q,
            ("ed", "maxEarlyData", "max-early-data"),
            "",
        )
        early_header = first_any(
            q,
            ("eh", "earlyDataHeaderName"),
            "",
        )

        if max_early_data:
            ws["max-early-data"] = safe_int(
                max_early_data,
                0,
            )

        if early_header:
            ws["early-data-header-name"] = early_header

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
        path = (
            info.get("path")
            or first(q, "path", "/")
            or "/"
        )

        host_header = (
            info.get("host")
            or first_any(q, ("host", "Host"), "")
        )

        h2 = {"path": [path]}

        if host_header:
            h2["headers"] = {"Host": [host_header]}

        proxy["h2-opts"] = h2

    elif network == "httpupgrade":
        path = first(q, "path", "/") or "/"
        host_header = first_any(q, ("host", "Host"), "")

        opts = {"path": path}

        if host_header:
            opts["headers"] = {"Host": host_header}

        proxy["http-upgrade-opts"] = opts

    # Preserve XHTTP/SplitHTTP style information where the target
    # Mihomo build understands it. Unknown parameters are not guessed.
    elif network in ("xhttp", "splithttp"):
        path = first(q, "path", "/") or "/"
        host_header = first_any(q, ("host", "Host"), "")

        opts = {"path": path}

        if host_header:
            opts["headers"] = {"Host": host_header}

        proxy[
            "xhttp-opts" if network == "xhttp" else "split-http-opts"
        ] = opts


# ============================================================
# PROTOCOL PARSERS
# ============================================================

def parse_vless(line):
    try:
        parsed = urlparse(line)

        uid = parsed.username or ""
        host = parsed.hostname or ""
        port = parsed.port or 443

        q = normalize_query(
            parse_qs(
                parsed.query,
                keep_blank_values=True,
            )
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

        packet_encoding = first(q, "packetEncoding", "")
        if packet_encoding:
            proxy["packet-encoding"] = packet_encoding

        # Additional VLESS/Mihomo fields commonly emitted by modern
        # link generators.
        for source, target in (
            ("authority", "authority"),
            ("mode", "mode"),
        ):
            value = first(q, source, "")
            if value:
                proxy[target] = value

        xudp = first_any(
            q,
            ("xudp", "xudpProxyUDP443"),
            "",
        )
        if xudp != "":
            proxy["xudp"] = bool_value(xudp)

        return proxy

    except Exception:
        return None


def parse_vmess(line):
    try:
        payload = line[len("vmess://"):]
        decoded = b64decode_text(payload)

        if not decoded:
            return None

        info = json.loads(decoded)

        host = info.get("add") or info.get("server") or ""
        port = safe_int(info.get("port"), 0)
        uid = info.get("id") or ""

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

        info_query = {}

        for key in (
            "path",
            "host",
            "serviceName",
            "type",
            "mode",
            "authority",
        ):
            if key in info:
                info_query[key] = [str(info[key])]

        apply_transport(
            proxy,
            info_query,
            info=info,
        )

        tls_value = str(
            info.get("tls", "")
        ).lower()

        if tls_value in ("tls", "1", "true"):
            proxy["tls"] = True
            proxy["servername"] = (
                info.get("sni")
                or info.get("host")
                or host
            )

        alpn = info.get("alpn")
        if alpn:
            if isinstance(alpn, list):
                proxy["alpn"] = alpn
            else:
                parsed_alpn = parse_alpn(str(alpn))
                if parsed_alpn:
                    proxy["alpn"] = parsed_alpn

        fp = (
            info.get("fp")
            or info.get("fingerprint")
        )
        if fp:
            proxy["client-fingerprint"] = fp

        packet_encoding = info.get("packetEncoding")
        if packet_encoding:
            proxy["packet-encoding"] = packet_encoding

        security = info.get("security")
        if security:
            proxy["security"] = security

        return proxy

    except Exception:
        return None


def parse_trojan(line):
    try:
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

        return proxy

    except Exception:
        return None


def parse_ss(line):
    try:
        parsed = urlparse(line)
        remark = remark_from_url(parsed)

        raw = line[len("ss://"):]

        if "@" not in raw:
            return None

        credentials, server_part = raw.split("@", 1)

        server_part = server_part.split("#", 1)[0]
        server_part = server_part.split("?", 1)[0]

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
            "name": make_name(
                "ss",
                host,
                port,
                remark,
            ),
            "type": "ss",
            "server": host,
            "port": port,
            "cipher": method,
            "password": password,
            "udp": True,
        }

    except Exception:
        return None


def parse_ssr(line):
    try:
        raw = line[len("ssr://"):]
        decoded = b64decode_urlsafe(raw)

        if not decoded:
            return None

        main = decoded.split("/", 1)[0]
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

        return {
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

    except Exception:
        return None


def parse_hysteria(line):
    try:
        parsed = urlparse(line)

        host = parsed.hostname or ""
        port = parsed.port or 443
        password = parsed.password or ""

        q = normalize_query(
            parse_qs(parsed.query, keep_blank_values=True)
        )

        if not host:
            return None

        if not password:
            password = first(q, "auth", "")

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

        return proxy

    except Exception:
        return None


def parse_hysteria2(line):
    try:
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

        mappings = (
            ("sni", "sni"),
            ("obfs", "obfs"),
            ("obfs-password", "obfs-password"),
            ("up", "up"),
            ("down", "down"),
        )

        for source, target in mappings:
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

        return proxy

    except Exception:
        return None


def parse_tuic(line):
    try:
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

        for key in (
            "sni",
            "udp_relay_mode",
            "udp-relay-mode",
        ):
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

        return proxy

    except Exception:
        return None


def parse_wireguard(line):
    try:
        parsed = urlparse(line)

        host = parsed.hostname or ""
        port = parsed.port or 51820
        private_key = parsed.username or ""

        q = normalize_query(
            parse_qs(parsed.query, keep_blank_values=True)
        )

        private_key = (
            private_key
            or first(q, "privatekey", "")
        )

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
                x.strip()
                for x in ip_value.split(",")
                if x.strip()
            ]

        ipv6_value = first(q, "ipv6", "")
        if ipv6_value:
            proxy["ipv6"] = [
                x.strip()
                for x in ipv6_value.split(",")
                if x.strip()
            ]

        mtu = safe_int(first(q, "mtu", ""), 0)
        if mtu:
            proxy["mtu"] = mtu

        reserved = first(q, "reserved", "")
        if reserved:
            try:
                proxy["reserved"] = [
                    int(x)
                    for x in reserved.split(",")
                    if x.strip()
                ]
            except Exception:
                pass

        return proxy

    except Exception:
        return None


# ============================================================
# INPUT EXPANSION
# ============================================================

def expand_input_lines(content):
    """
    Accept normal links, blank/comment lines, and Base64 subscription
    payloads containing one or more proxy links.
    """
    result = []

    for raw in content.splitlines():
        line = raw.strip().lstrip("\ufeff")

        if not line:
            continue

        if line.startswith("#"):
            continue

        if "://" in line:
            result.append(line)
            continue

        # Try a Base64 subscription payload.
        decoded = b64decode_text(line)

        if decoded and "://" in decoded:
            for item in decoded.splitlines():
                item = item.strip()

                if item and "://" in item:
                    result.append(item)

    return result


# ============================================================
# MASTER PARSER
# ============================================================

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
# VALIDATION
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

    port = proxy.get("port")

    if not isinstance(port, int):
        return False, "invalid-port"

    if not 1 <= port <= 65535:
        return False, "port-range"

    if not valid_hostname(str(proxy["server"])):
        return False, "invalid-server"

    ptype = proxy["type"]

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

    for key in required.get(ptype, ()):
        if not proxy.get(key):
            return False, f"missing-{key}"

    return True, ""


# ============================================================
# DEDUPLICATION
# ============================================================

def proxy_signature(proxy):
    important = (
        "type",
        "server",
        "port",
        "uuid",
        "password",
        "cipher",
        "network",
        "servername",
        "flow",
    )

    data = []

    for key in important:
        data.append(
            f"{key}={proxy.get(key, '')}"
        )

    reality = proxy.get("reality-opts")
    if reality:
        data.append(
            json.dumps(
                reality,
                sort_keys=True,
                ensure_ascii=False,
            )
        )

    return "|".join(data)


# ============================================================
# CONNECTIVITY TEST
# ============================================================

def resolve_host(host):
    start = time.monotonic()

    try:
        infos = socket.getaddrinfo(
            host,
            None,
            type=socket.SOCK_STREAM,
        )

        elapsed = int(
            (time.monotonic() - start) * 1000
        )

        addresses = []

        for item in infos:
            sockaddr = item[4]
            if sockaddr:
                addresses.append(sockaddr[0])

        return True, elapsed, list(dict.fromkeys(addresses))

    except Exception as exc:
        return False, None, [], str(exc)


def tcp_probe(host, port):
    dns_ok, dns_ms, addresses, dns_error = (
        resolve_host(host)
    )

    if not dns_ok:
        return TestResult(
            dns_ok=False,
            tcp_ok=False,
            dns_ms=None,
            tcp_ms=None,
            error=f"DNS: {dns_error}",
        )

    best = None

    for address in addresses:
        for _ in range(TCP_ATTEMPTS):
            sock = None

            try:
                start = time.monotonic()

                sock = socket.create_connection(
                    (address, int(port)),
                    timeout=TCP_TIMEOUT,
                )

                elapsed = int(
                    (time.monotonic() - start) * 1000
                )

                if best is None or elapsed < best:
                    best = elapsed

            except Exception:
                pass

            finally:
                try:
                    if sock:
                        sock.close()
                except Exception:
                    pass

    return TestResult(
        dns_ok=True,
        tcp_ok=best is not None,
        dns_ms=dns_ms,
        tcp_ms=best,
        error="" if best is not None else "TCP connection failed",
    )


def test_proxy(proxy):
    result = tcp_probe(
        proxy["server"],
        proxy["port"],
    )

    proxy["_test"] = {
        "dns_ok": result.dns_ok,
        "tcp_ok": result.tcp_ok,
        "dns_ms": result.dns_ms,
        "tcp_ms": result.tcp_ms,
        "error": result.error,
    }

    return proxy


# ============================================================
# SCORE
# ============================================================

def score_proxy(proxy):
    result = proxy.get("_test", {})

    score = 50

    if result.get("dns_ok"):
        score += 15
    else:
        score -= 30

    if result.get("tcp_ok"):
        score += 25
    else:
        score -= 35

    tcp_ms = result.get("tcp_ms")

    if tcp_ms is not None:
        if tcp_ms <= 100:
            score += 10
        elif tcp_ms <= 200:
            score += 7
        elif tcp_ms <= 400:
            score += 4
        elif tcp_ms <= 800:
            score += 1
        else:
            score -= 5

    return max(0, min(100, score))


# ============================================================
# YAML CLEANING
# ============================================================

def remove_internal_fields(proxy):
    clean = {}

    for key, value in proxy.items():
        if not str(key).startswith("_"):
            clean[key] = value

    return clean


# ============================================================
# CONFIG BUILDER
# ============================================================

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


def build_groups(names, auto_test=True, health_url=DEFAULT_HEALTH_URL):
    groups = [
        {
            "name": GROUP_MANUAL,
            "type": "select",
            "proxies": names,
        }
    ]

    if auto_test and names:
        groups.append(
            {
                "name": GROUP_AUTO,
                "type": "url-test",
                "proxies": names,
                "url": health_url,
                "interval": URL_TEST_INTERVAL,
                "timeout": URL_TEST_TIMEOUT,
                "lazy": False,
                "expected-status": 204,
            }
        )

    return groups


def build_config(proxies, enable_dns=True, auto_test=True):
    names = [p["name"] for p in proxies]

    config = {
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

        "proxies": [
            remove_internal_fields(p)
            for p in proxies
        ],

        "proxy-groups": build_groups(
            names,
            auto_test=auto_test,
        ),

        "rules": [
            f"MATCH,{GROUP_MANUAL}",
        ],
    }

    if enable_dns:
        config["dns"] = build_dns()

    return config


# ============================================================
# YAML VALIDATION
# ============================================================

def validate_yaml_file(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if not isinstance(data, dict):
            return False, "YAML root is not an object"

        if "proxies" not in data:
            return False, "proxies section missing"

        if "proxy-groups" not in data:
            return False, "proxy-groups section missing"

        if "rules" not in data:
            return False, "rules section missing"

        return True, ""

    except Exception as exc:
        return False, str(exc)


# ============================================================
# REPORT
# ============================================================

def write_report(path, proxies, stats):
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write("Akbar98 Converter Report\n")
            f.write("=" * 70 + "\n")
            f.write(
                f"Generated: {datetime.now().isoformat(timespec='seconds')}\n"
            )
            f.write(f"Input lines: {stats.input_lines}\n")
            f.write(f"Parsed: {stats.parsed}\n")
            f.write(f"Duplicates: {stats.duplicates}\n")
            f.write(f"Failed: {stats.failed}\n")
            f.write(f"TCP OK: {stats.tcp_ok}\n")
            f.write(f"TCP Failed: {stats.tcp_failed}\n")
            f.write("\nTypes:\n")

            for key in sorted(stats.by_type):
                f.write(
                    f"  {key}: {stats.by_type[key]}\n"
                )

            f.write("\nProxies:\n")
            f.write("-" * 70 + "\n")

            for p in proxies:
                test = p.get("_test", {})

                f.write(
                    f"{p['name']} | "
                    f"{p['type']} | "
                    f"{p['server']}:{p['port']} | "
                    f"DNS={test.get('dns_ok')} | "
                    f"TCP={test.get('tcp_ok')} | "
                    f"TCPms={test.get('tcp_ms')} | "
                    f"Score={score_proxy(p)}\n"
                )

    except Exception:
        pass


# ============================================================
# INPUT
# ============================================================

def prepare_input():
    """
    Input lifecycle:
    - Always starts with a completely empty input file.
    - User enters/pastes links in nano.
    - After nano closes, the caller reads the file.
    - main() clears the file immediately after reading, so the next
      execution always opens a blank nano.
    """
    try:
        BASE_DIR.mkdir(parents=True, exist_ok=True)

        # IMPORTANT: truncate on every execution.
        # This prevents old links from appearing in nano.
        with open(INPUT_PATH, "w", encoding="utf-8"):
            pass

        subprocess.call(["nano", str(INPUT_PATH)])
        return True

    except Exception as exc:
        print(f"[ERROR] Cannot open nano: {exc}")
        print(f"[INFO] Input file: {INPUT_PATH}")
        return False


def clear_input_file():
    """Always leave input_mobile.txt empty for the next run."""
    try:
        with open(INPUT_PATH, "w", encoding="utf-8"):
            pass
        return True
    except Exception as exc:
        print(f"[WARNING] Could not clear input file: {exc}")
        return False


# ============================================================
# MAIN
# ============================================================

def main():
    print()
    print("=" * 70)
    print("Akbar98 Advanced Proxy Converter")
    print("Xray/V2Ray -> Mihomo / Clash Meta")
    print("=" * 70)
    print()

    if not prepare_input():
        return 1

    out_folder = input(
        "Enter output folder name in Download: "
    ).strip()

    if not out_folder:
        print("[ERROR] Folder name required.")
        return 1

    out_name = input(
        "Enter output file name (without extension): "
    ).strip()

    if not out_name:
        print("[ERROR] File name required.")
        return 1

    out_dir = Path(
        "/storage/emulated/0/Download"
    ) / out_folder

    out_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    out_path = out_dir / f"{out_name}.yaml"
    report_path = out_dir / f"{out_name}_report.txt"
    failed_path = out_dir / f"{out_name}_failed.txt"

    # Automatic production settings:
    # DNS/TCP test = ON
    # Mihomo URL-Test group = ON
    # DNS section = ON
    enable_test = True
    enable_auto = True
    enable_dns = True

    try:
        content = INPUT_PATH.read_text(
            encoding="utf-8"
        )
    except Exception as exc:
        print(f"[ERROR] Cannot read input: {exc}")
        clear_input_file()
        return 1

    # Clear immediately after loading into memory.
    # Therefore, even if parsing/output later fails, the next run
    # will still start with an empty nano file.
    clear_input_file()

    lines = expand_input_lines(content)

    stats = Stats(
        input_lines=len(lines)
    )

    proxies = []
    failed = []
    signatures = set()

    for line in lines:
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

        signature = proxy_signature(proxy)

        if signature in signatures:
            stats.duplicates += 1
            continue

        signatures.add(signature)
        proxies.append(proxy)

        ptype = proxy["type"]
        stats.by_type[ptype] = (
            stats.by_type.get(ptype, 0) + 1
        )

    stats.parsed = len(proxies)
    stats.failed = len(failed)

    print()
    print("=" * 70)
    print("PARSER RESULT")
    print("=" * 70)
    print(f"Input lines : {stats.input_lines}")
    print(f"Parsed      : {stats.parsed}")
    print(f"Duplicates  : {stats.duplicates}")
    print(f"Failed      : {stats.failed}")
    print("=" * 70)

    if not proxies:
        print("[ERROR] No valid proxy found.")

        try:
            failed_path.write_text(
                "\n".join(failed),
                encoding="utf-8",
            )
        except Exception:
            pass

        return 1

    # --------------------------------------------------------
    # TEST
    # --------------------------------------------------------

    if enable_test:
        print()
        print("[TEST] DNS + TCP reachability")
        print(
            "NOTE: TCP success does NOT prove proxy protocol success."
        )
        print()

        tested = []

        with ThreadPoolExecutor(
            max_workers=MAX_WORKERS
        ) as executor:

            futures = {
                executor.submit(
                    test_proxy,
                    p,
                ): p
                for p in proxies
            }

            for future in as_completed(futures):
                try:
                    tested.append(
                        future.result()
                    )
                except Exception as exc:
                    proxy = futures[future]
                    proxy["_test"] = {
                        "dns_ok": False,
                        "tcp_ok": False,
                        "dns_ms": None,
                        "tcp_ms": None,
                        "error": str(exc),
                    }
                    tested.append(proxy)

        proxies = tested

        stats.tcp_ok = sum(
            1
            for p in proxies
            if p.get("_test", {}).get("tcp_ok")
        )

        stats.tcp_failed = (
            len(proxies) - stats.tcp_ok
        )

        proxies.sort(
            key=lambda p: (
                -score_proxy(p),
                p.get("_test", {}).get("tcp_ms")
                if p.get("_test", {}).get("tcp_ms") is not None
                else 999999,
            )
        )

    else:
        for p in proxies:
            p["_test"] = {
                "dns_ok": None,
                "tcp_ok": None,
                "dns_ms": None,
                "tcp_ms": None,
                "error": "Test disabled",
            }

    # --------------------------------------------------------
    # REPORT
    # --------------------------------------------------------

    write_report(
        report_path,
        proxies,
        stats,
    )

    if failed:
        try:
            failed_path.write_text(
                "\n".join(failed),
                encoding="utf-8",
            )
        except Exception:
            pass

    # --------------------------------------------------------
    # BUILD
    # --------------------------------------------------------

    config = build_config(
        proxies,
        enable_dns=enable_dns,
        auto_test=enable_auto,
    )

    # --------------------------------------------------------
    # BACKUP
    # --------------------------------------------------------

    if out_path.exists():
        backup_name = (
            f"{out_path.stem}_backup_"
            f"{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            f"{out_path.suffix}"
        )

        backup_path = out_dir / backup_name

        try:
            shutil.copy2(
                out_path,
                backup_path,
            )
            print(
                f"[BACKUP] {backup_path}"
            )
        except Exception:
            pass

    # --------------------------------------------------------
    # WRITE
    # --------------------------------------------------------

    tmp_path = out_path.with_suffix(".yaml.tmp")

    try:
        with open(
            tmp_path,
            "w",
            encoding="utf-8",
        ) as f:
            yaml.safe_dump(
                config,
                f,
                allow_unicode=True,
                sort_keys=False,
                default_flow_style=False,
                width=160,
            )

        # Replace only after the complete YAML was written.
        os.replace(tmp_path, out_path)

    except Exception as exc:
        try:
            if tmp_path.exists():
                tmp_path.unlink()
        except Exception:
            pass

        print(
            f"[ERROR] Failed to write YAML: {exc}"
        )
        return 1

    # --------------------------------------------------------
    # VALIDATE
    # --------------------------------------------------------

    valid_yaml, error = validate_yaml_file(
        out_path
    )

    if not valid_yaml:
        print(
            f"[ERROR] YAML validation failed: {error}"
        )
        return 1

    try:
        os.chmod(
            out_path,
            0o644,
        )
    except Exception:
        pass

    # --------------------------------------------------------
    # FINAL REPORT
    # --------------------------------------------------------

    print()
    print("=" * 70)
    print("DONE")
    print("=" * 70)
    print(f"YAML        : {out_path}")
    print(f"Report      : {report_path}")

    if failed:
        print(f"Failed list : {failed_path}")

    print(f"Proxies     : {len(proxies)}")
    print("DNS/TCP test: ON (automatic)")
    print("Auto group  : ON (automatic)")
    print("DNS section : ON (automatic)")

    if enable_test:
        print(f"TCP OK      : {stats.tcp_ok}")
        print(f"TCP Failed  : {stats.tcp_failed}")

    print()
    print("Types:")

    for ptype in sorted(stats.by_type):
        print(
            f"  {ptype:15} {stats.by_type[ptype]}"
        )

    print()
    print("IMPORTANT:")
    print(
        "TCP reachability is not proof of VLESS/Reality/TLS/proxy health."
    )
    print(
        "The generated Auto group uses Mihomo's own URL-Test."
    )
    print("Data download by converter: OFF")
    print("HTTP health requests by converter: OFF")
    print("TCP test: connection-only")

    # Final safety cleanup: input_mobile.txt must be empty after every run.
    clear_input_file()

    print("=" * 70)
    print()

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\n[STOP] Cancelled by user.")
        raise SystemExit(130)

