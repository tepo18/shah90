#!/data/data/com.termux/files/usr/bin/python3
# -*- coding: utf-8 -*-

"""
Akbar98 Final Low-Data Mihomo Converter

Design goals:
- Same Akbar98 base paths and Nano input workflow.
- LIGHT is the default test mode: DNS -> TCP connect -> close.
- NORMAL/DEEP never download application data; they only repeat TCP checks.
- No HTTP health checks and no URL downloads are performed by this script.
- Mihomo URL-Test is emitted into YAML for Mihomo itself.
- Batch processing + adaptive workers for large lists.
- DNS cache + result cache with TTL.
- IPv4/IPv6-aware reachability.
- Exact + semantic deduplication without collapsing meaningful parameters.
- Score and status are separated from actual protocol usability.
- Unknown query parameters are reported, not silently lost.
- Subscription/Base64 input decoding.
- Basic Mihomo compatibility validation and final YAML validation.
- Atomic YAML write and auxiliary report/failed files.
"""

import os
import re
import json
import time
import socket
import base64
import hashlib
import tempfile
import subprocess
from urllib.parse import urlparse, parse_qs, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import yaml
except ImportError:
    print("[ERROR] PyYAML is required. Install with: pip install pyyaml")
    raise SystemExit(1)


# ============================================================
# PATHS / CONSTANTS
# ============================================================

BASE_DIR = "/storage/emulated/0/Download/Akbar98"
INPUT_PATH = os.path.join(BASE_DIR, "input_mobile.txt")
CACHE_PATH = os.path.join(BASE_DIR, "akbar98_cache.json")

os.makedirs(BASE_DIR, exist_ok=True)

# Requested behavior: no questions for DNS/TCP, URL-Test or DNS section.
DEFAULT_TEST_MODE = "LIGHT"
DNS_CACHE_TTL = 300                 # 5 minutes
TCP_CACHE_TTL = 600                 # 10 minutes
MAX_WORKERS = 32
MIN_WORKERS = 4
BATCH_SIZE = 100
SOCKET_TIMEOUT = 1.8
TCP_ATTEMPTS = 1

TEST_PROFILES = {
    "LIGHT": {"attempts": 1, "timeout": 1.8},
    "NORMAL": {"attempts": 2, "timeout": 2.0},
    "DEEP": {"attempts": 3, "timeout": 2.5},
}

# Only protocol families whose syntax is explicitly recognized are exported.
SUPPORTED_SCHEMES = {
    "vless", "vmess", "trojan", "ss", "ssr",
    "hysteria", "hysteria2", "hy2", "tuic", "wireguard"
}


# ============================================================
# INPUT FILE LIFECYCLE
# ============================================================

def clear_input_file():
    """Always make Nano open an empty input file."""
    with open(INPUT_PATH, "w", encoding="utf-8"):
        pass


def open_nano_for_input():
    clear_input_file()
    try:
        subprocess.call(["nano", INPUT_PATH])
    except FileNotFoundError:
        print("[WARN] nano not found. Fill the input file manually:")
        print(INPUT_PATH)
        input("Press Enter when finished...")
    except Exception as exc:
        print(f"[WARN] Could not launch nano: {exc}")


def read_and_clear_input():
    try:
        with open(INPUT_PATH, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    finally:
        # Clear immediately after reading so the next run is clean.
        clear_input_file()
    return content


# ============================================================
# GENERIC HELPERS
# ============================================================

def b64decode_text(value):
    if value is None:
        return ""
    s = str(value).strip().replace("\n", "").replace("\r", "")
    s = s.replace(" ", "")
    s = s.replace("-", "+").replace("_", "/")
    if not s:
        return ""
    s += "=" * ((4 - len(s) % 4) % 4)
    try:
        return base64.b64decode(s, validate=False).decode("utf-8", errors="ignore")
    except Exception:
        return ""


def b64decode_bytes(value):
    if value is None:
        return b""
    s = str(value).strip().replace("\n", "").replace("\r", "").replace(" ", "")
    s = s.replace("-", "+").replace("_", "/")
    if not s:
        return b""
    s += "=" * ((4 - len(s) % 4) % 4)
    try:
        return base64.b64decode(s, validate=False)
    except Exception:
        return b""


def safe_int(value, default=0):
    try:
        return int(str(value).strip())
    except Exception:
        return default


def clean_name(value):
    value = unquote(str(value or "")).strip()
    value = re.sub(r"[^A-Za-z0-9_\-. \u0600-\u06FF]", "", value)
    value = re.sub(r"\s+", " ", value).strip()
    return value[:120] or "Proxy"


def tail(value, n=6):
    return re.sub(r"[^A-Za-z0-9]", "", str(value or ""))[-n:] or "node"


def normalize_host(host):
    host = str(host or "").strip().strip("[]").lower().rstrip(".")
    return host


def valid_port(port):
    return 1 <= safe_int(port, 0) <= 65535


def unique_name(base, used):
    base = clean_name(base)
    name = base
    i = 2
    while name in used:
        name = f"{base} {i}"
        i += 1
    used.add(name)
    return name


def parse_query(query):
    return {k: v[0] if v else "" for k, v in parse_qs(query, keep_blank_values=True).items()}


def first(q, *keys, default=""):
    for key in keys:
        if key in q and q[key] != "":
            return q[key]
    return default


def stable_json(obj):
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def fingerprint_proxy(p):
    """Meaningful configuration fingerprint; name is intentionally excluded."""
    identity = dict(p)
    identity.pop("name", None)
    return hashlib.sha256(stable_json(identity).encode("utf-8")).hexdigest()


def semantic_fingerprint(p):
    """Semantic identity; keeps credentials/security/transport differences."""
    keys = [
        "type", "server", "port", "uuid", "password", "cipher",
        "alterId", "tls", "servername", "sni", "flow", "network",
        "ws-opts", "grpc-opts", "h2-opts", "reality-opts", "alpn",
        "fingerprint", "client-fingerprint", "skip-cert-verify",
        "obfs", "protocol", "auth", "private-key", "public-key",
        "ip", "peers", "mtu", "remote", "uuid", "token",
    ]
    data = {k: p.get(k) for k in keys if k in p}
    return hashlib.sha256(stable_json(data).encode("utf-8")).hexdigest()


# ============================================================
# UNKNOWN PARAMETER REPORTING
# ============================================================

KNOWN_QUERY_KEYS = {
    "type", "security", "encryption", "sni", "servername", "fp",
    "fingerprint", "flow", "pbk", "publickey", "sid", "spx", "path",
    "host", "serviceName", "servicename", "mode", "authority", "alpn",
    "allowInsecure", "insecure", "packetEncoding", "ed", "headerType",
    "seed", "quicSecurity", "key", "obfs", "obfs-password", "obfsParam",
    "protocol", "auth", "upmbps", "downmbps", "congestion_control",
    "udp_relay_mode", "sni", "peer", "privatekey", "publickey", "mtu",
}


def collect_unknown(q):
    return sorted(k for k in q.keys() if k.lower() not in {x.lower() for x in KNOWN_QUERY_KEYS})


# ============================================================
# PARSER CORE
# ============================================================

def parse_vless(line, used):
    u = urlparse(line)
    host = normalize_host(u.hostname)
    port = u.port or 443
    uuid = unquote(u.username or "")
    q = parse_query(u.query)
    if not host or not uuid or not valid_port(port):
        return None, "invalid-vless", []

    net = first(q, "type", default="tcp").lower() or "tcp"
    security = first(q, "security", default="none").lower()
    name = unique_name(f"vless-{host}-{tail(uuid)}", used)
    p = {
        "name": name, "type": "vless", "server": host, "port": port,
        "uuid": uuid, "encryption": "none", "udp": True, "network": net,
    }

    if security in ("tls", "reality"):
        p["tls"] = True
        p["servername"] = first(q, "sni", "servername", default=host)
    if first(q, "fp", "fingerprint"):
        p["client-fingerprint"] = first(q, "fp", "fingerprint")
    if first(q, "flow"):
        p["flow"] = q["flow"]
    if security == "reality" or first(q, "pbk", "publickey") or first(q, "sid"):
        ro = {}
        if first(q, "pbk", "publickey"):
            ro["public-key"] = first(q, "pbk", "publickey")
        if first(q, "sid"):
            ro["short-id"] = q["sid"]
        if first(q, "spx"):
            ro["spider-x"] = q["spx"]
        if ro:
            p["reality-opts"] = ro
    if first(q, "alpn"):
        p["alpn"] = [x for x in q["alpn"].split(",") if x]
    if net == "ws":
        wo = {"path": first(q, "path", default="/") or "/"}
        h = first(q, "host")
        if h:
            wo["headers"] = {"Host": h}
        p["ws-opts"] = wo
    elif net == "grpc":
        svc = first(q, "serviceName", "servicename")
        if svc:
            p["grpc-opts"] = {"grpc-service-name": svc}
    elif net in ("h2", "http"):
        ho = {"path": first(q, "path", default="/") or "/"}
        h = first(q, "host")
        if h:
            ho["host"] = [h]
        p["h2-opts"] = ho
    return p, None, collect_unknown(q)


def parse_vmess(line, used):
    raw = line[8:]
    text = b64decode_text(raw)
    if not text:
        return None, "invalid-vmess-base64", []
    try:
        info = json.loads(text)
    except Exception:
        return None, "invalid-vmess-json", []
    host = normalize_host(info.get("add") or info.get("server"))
    port = safe_int(info.get("port"), 0)
    uuid = info.get("id") or ""
    if not host or not uuid or not valid_port(port):
        return None, "invalid-vmess-fields", []
    net = str(info.get("net") or "tcp").lower()
    tls = str(info.get("tls") or "").lower() in ("tls", "true", "1")
    name = unique_name(f"vmess-{host}-{tail(uuid)}", used)
    p = {
        "name": name, "type": "vmess", "server": host, "port": port,
        "uuid": uuid, "alterId": safe_int(info.get("aid", info.get("alterId", 0))),
        "cipher": info.get("scy", "auto"), "udp": True, "network": net,
    }
    if tls:
        p["tls"] = True
        p["servername"] = info.get("sni") or info.get("host") or host
    if info.get("fp"):
        p["client-fingerprint"] = info["fp"]
    if info.get("alpn"):
        alpn = info["alpn"]
        p["alpn"] = alpn if isinstance(alpn, list) else [x for x in str(alpn).split(",") if x]
    if net == "ws":
        wo = {"path": info.get("path") or "/"}
        if info.get("host"):
            wo["headers"] = {"Host": info["host"]}
        p["ws-opts"] = wo
    elif net == "grpc" and info.get("path"):
        p["grpc-opts"] = {"grpc-service-name": info["path"]}
    known_info = {"v", "ps", "add", "port", "id", "aid", "scy", "net", "type", "host", "path", "tls", "sni", "alpn", "fp", "server", "alterId"}
    unknown = sorted(k for k in info.keys() if k not in known_info)
    return p, None, unknown


def parse_trojan(line, used):
    u = urlparse(line)
    host = normalize_host(u.hostname)
    port = u.port or 443
    password = unquote(u.username or "")
    q = parse_query(u.query)
    if not host or not password or not valid_port(port):
        return None, "invalid-trojan", []
    name = unique_name(f"trojan-{host}-{tail(password)}", used)
    p = {
        "name": name, "type": "trojan", "server": host, "port": port,
        "password": password, "udp": True, "network": "tcp", "tls": True,
        "sni": first(q, "sni", "servername", default=host),
    }
    if first(q, "alpn"):
        p["alpn"] = [x for x in q["alpn"].split(",") if x]
    if first(q, "type") == "ws":
        p["network"] = "ws"
        wo = {"path": first(q, "path", default="/") or "/"}
        if first(q, "host"):
            wo["headers"] = {"Host": q["host"]}
        p["ws-opts"] = wo
    return p, None, collect_unknown(q)


def parse_ss(line, used):
    u = urlparse(line)
    host = normalize_host(u.hostname)
    port = u.port or 0
    q = parse_query(u.query)
    user = unquote(u.username or "")
    password = unquote(u.password or "")

    if not host or not valid_port(port):
        # Legacy ss://BASE64(method:password@host:port)#name format.
        payload = line[5:]
        if "@" not in payload:
            decoded = b64decode_text(payload.split("#", 1)[0])
            if decoded:
                payload = decoded
        if "@" not in payload:
            return None, "invalid-ss", []
        creds, endpoint = payload.split("@", 1)
        if ":" not in creds:
            return None, "invalid-ss-credentials", []
        method, password = creds.split(":", 1)
        endpoint = endpoint.split("#", 1)[0]
        if ":" not in endpoint:
            return None, "invalid-ss-endpoint", []
        host, port_s = endpoint.rsplit(":", 1)
        host, port = normalize_host(host), safe_int(port_s, 0)
    else:
        # Modern URL may put method/password in userinfo.
        method = user or ""
        if not method and "@" in line[5:]:
            left = line[5:].split("@", 1)[0]
            decoded = b64decode_text(left)
            if ":" in decoded:
                method, password = decoded.split(":", 1)
    if not method or not password or not valid_port(port):
        return None, "invalid-ss-fields", []
    name = unique_name(f"ss-{host}-{port}", used)
    p = {"name": name, "type": "ss", "server": host, "port": port,
         "cipher": method, "password": password, "udp": True}
    return p, None, collect_unknown(q)


def parse_ssr(line, used):
    payload = b64decode_text(line[6:])
    if not payload:
        return None, "invalid-ssr-base64", []
    try:
        main, fragment = (payload.split("/", 1) + [""])[:2]
        parts = main.split(":")
        if len(parts) < 6:
            return None, "invalid-ssr-fields", []
        host = normalize_host(parts[0])
        port = safe_int(parts[1], 0)
        protocol = parts[2]
        method = parts[3]
        obfs = parts[4]
        password = b64decode_text(parts[5]) or parts[5]
        if not host or not valid_port(port) or not password:
            return None, "invalid-ssr-fields", []
        name = unique_name(f"ssr-{host}-{port}", used)
        p = {"name": name, "type": "ssr", "server": host, "port": port,
             "protocol": protocol, "cipher": method, "obfs": obfs,
             "password": password, "udp": True}
        return p, None, []
    except Exception:
        return None, "invalid-ssr", []


def parse_hysteria(line, used, version):
    u = urlparse(line)
    host = normalize_host(u.hostname)
    port = u.port or 443
    q = parse_query(u.query)
    password = unquote(u.password or u.username or first(q, "auth", default=""))
    if not host or not valid_port(port) or not password:
        return None, f"invalid-{version}", []
    typ = "hysteria2" if version == "hysteria2" else "hysteria"
    name = unique_name(f"{typ}-{host}-{tail(password)}", used)
    if typ == "hysteria2":
        p = {"name": name, "type": "hysteria2", "server": host,
             "port": port, "password": password, "udp": True}
        obfs = first(q, "obfs")
        if obfs:
            p["obfs"] = {"type": obfs}
            if first(q, "obfs-password"):
                p["obfs"]["password"] = q["obfs-password"]
    else:
        p = {"name": name, "type": "hysteria", "server": host,
             "port": port, "password": password, "protocol": first(q, "protocol", default="udp"),
             "udp": True}
        if first(q, "obfs"):
            p["obfs"] = q["obfs"]
    return p, None, collect_unknown(q)


def parse_tuic(line, used):
    u = urlparse(line)
    host = normalize_host(u.hostname)
    port = u.port or 443
    user = unquote(u.username or "")
    password = unquote(u.password or "")
    q = parse_query(u.query)
    if not host or not valid_port(port) or not user or not password:
        return None, "invalid-tuic", []
    name = unique_name(f"tuic-{host}-{tail(user)}", used)
    p = {"name": name, "type": "tuic", "server": host, "port": port,
         "uuid": user, "password": password, "udp": True}
    if first(q, "sni", "servername"):
        p["sni"] = first(q, "sni", "servername")
    if first(q, "alpn"):
        p["alpn"] = [x for x in q["alpn"].split(",") if x]
    if first(q, "congestion_control"):
        p["congestion-controller"] = q["congestion_control"]
    return p, None, collect_unknown(q)


def parse_wireguard(line, used):
    u = urlparse(line)
    host = normalize_host(u.hostname)
    port = u.port or 51820
    q = parse_query(u.query)
    private_key = unquote(u.username or first(q, "privatekey", "private-key"))
    public_key = first(q, "publickey", "public-key", "peer")
    if not host or not valid_port(port) or not private_key:
        return None, "invalid-wireguard", []
    name = unique_name(f"wireguard-{host}-{port}", used)
    p = {"name": name, "type": "wireguard", "server": host, "port": port,
         "private-key": private_key, "udp": True}
    if public_key:
        p["public-key"] = public_key
    if first(q, "mtu"):
        p["mtu"] = safe_int(q["mtu"], 1420)
    return p, None, collect_unknown(q)


def parse_link(line, used):
    line = line.strip()
    if not line or line.startswith("#"):
        return None, "empty", []
    scheme = line.split(":", 1)[0].lower() if ":" in line else ""
    try:
        if scheme == "vless":
            return parse_vless(line, used)
        if scheme == "vmess":
            return parse_vmess(line, used)
        if scheme == "trojan":
            return parse_trojan(line, used)
        if scheme == "ss":
            return parse_ss(line, used)
        if scheme == "ssr":
            return parse_ssr(line, used)
        if scheme == "hysteria":
            return parse_hysteria(line, used, "hysteria")
        if scheme in ("hysteria2", "hy2"):
            return parse_hysteria(line, used, "hysteria2")
        if scheme == "tuic":
            return parse_tuic(line, used)
        if scheme == "wireguard":
            return parse_wireguard(line, used)
        return None, f"unsupported-scheme:{scheme or 'unknown'}", []
    except Exception as exc:
        return None, f"parser-error:{type(exc).__name__}", []


# ============================================================
# SUBSCRIPTION / INPUT DECODER
# ============================================================

def looks_like_proxy_line(line):
    low = line.strip().lower()
    return any(low.startswith(s + "://") for s in SUPPORTED_SCHEMES)


def expand_input(content):
    """Extract direct links and Base64 subscription payloads recursively."""
    queue = [content]
    discovered = []
    unsupported_lines = []
    seen_text = set()

    while queue:
        text = queue.pop(0)
        if not text or text in seen_text:
            continue
        seen_text.add(text)

        found_direct = False
        for raw in re.split(r"[\r\n]+", text):
            line = raw.strip().strip('"\'')
            if not line:
                continue
            # Pull direct links from a line that may contain surrounding text.
            matches = re.findall(
                r"(?:vless|vmess|trojan|ssr|ss|hysteria2|hysteria|hy2|tuic|wireguard)://[^\s]+",
                line,
                flags=re.I,
            )
            if matches:
                discovered.extend(matches)
                found_direct = True
            elif looks_like_proxy_line(line):
                discovered.append(line)
                found_direct = True

        # If the whole content looks Base64, decode once and process again.
        compact = re.sub(r"\s+", "", text)
        if not found_direct and len(compact) >= 16 and re.fullmatch(r"[A-Za-z0-9+/_=-]+", compact):
            decoded = b64decode_text(compact)
            if decoded and decoded != text and (
                "://" in decoded or "vless" in decoded.lower() or "vmess" in decoded.lower()
            ):
                queue.append(decoded)

    return discovered, unsupported_lines


# ============================================================
# CACHE
# ============================================================

class CacheStore:
    def __init__(self, path):
        self.path = path
        self.data = {"dns": {}, "tcp": {}}
        self.load()

    def load(self):
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                obj = json.load(f)
            if isinstance(obj, dict):
                self.data["dns"] = obj.get("dns", {}) if isinstance(obj.get("dns", {}), dict) else {}
                self.data["tcp"] = obj.get("tcp", {}) if isinstance(obj.get("tcp", {}), dict) else {}
        except Exception:
            pass

    def get(self, section, key, ttl):
        item = self.data.get(section, {}).get(key)
        if not isinstance(item, dict):
            return None
        if time.time() - float(item.get("ts", 0)) > ttl:
            return None
        return item.get("value")

    def put(self, section, key, value):
        self.data.setdefault(section, {})[key] = {"ts": time.time(), "value": value}

    def prune(self):
        now = time.time()
        for section, ttl in (("dns", DNS_CACHE_TTL), ("tcp", TCP_CACHE_TTL)):
            fresh = {}
            for k, v in self.data.get(section, {}).items():
                if isinstance(v, dict) and now - float(v.get("ts", 0)) <= ttl:
                    fresh[k] = v
            self.data[section] = fresh

    def save(self):
        self.prune()
        tmp = self.path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.data, f, ensure_ascii=False, indent=2)
            os.replace(tmp, self.path)
        except Exception:
            try:
                if os.path.exists(tmp):
                    os.remove(tmp)
            except Exception:
                pass


# ============================================================
# DNS / TCP LOW-DATA TEST ENGINE
# ============================================================

_DNS_MEM = {}
_DNS_LOCK = __import__("threading").Lock()
_CACHE_LOCK = __import__("threading").Lock()


def resolve_host(host, cache):
    host = normalize_host(host)
    if not host:
        return {"ok": False, "addresses": [], "error": "empty-host", "cached": False}

    with _DNS_LOCK:
        if host in _DNS_MEM:
            return dict(_DNS_MEM[host], cached=True)

    cached = cache.get("dns", host, DNS_CACHE_TTL)
    if cached is not None:
        result = dict(cached)
        result["cached"] = True
        with _DNS_LOCK:
            _DNS_MEM[host] = dict(result)
        return result

    addresses = []
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        for family, _, _, _, sockaddr in infos:
            ip = sockaddr[0]
            fam = "IPv6" if family == socket.AF_INET6 else "IPv4"
            item = {"ip": ip, "family": fam}
            if item not in addresses:
                addresses.append(item)
    except Exception as exc:
        result = {"ok": False, "addresses": [], "error": type(exc).__name__, "cached": False}
        with _CACHE_LOCK:
            cache.put("dns", host, result)
        return result

    result = {"ok": bool(addresses), "addresses": addresses, "error": "", "cached": False}
    with _DNS_LOCK:
        _DNS_MEM[host] = dict(result)
    with _CACHE_LOCK:
        cache.put("dns", host, result)
    return result


def tcp_connect(ip, port, timeout, family):
    sock = None
    try:
        t0 = time.monotonic()
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        return int((time.monotonic() - t0) * 1000)
    except Exception:
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


def tcp_test(proxy, cache, mode):
    host = proxy["server"]
    port = proxy["port"]
    fp = fingerprint_proxy(proxy)
    cache_key = f"{fp}:{mode}"
    cached = cache.get("tcp", cache_key, TCP_CACHE_TTL)
    if cached is not None:
        result = dict(cached)
        result["cached"] = True
        return result

    dns = resolve_host(host, cache)
    if not dns["ok"]:
        result = {
            "dns_status": "DNS_FAIL", "tcp_status": "TCP_NOT_TESTED",
            "reachable": False, "latency_ms": None,
            "family": None, "address": None, "cached": False,
        }
        with _CACHE_LOCK:
            cache.put("tcp", cache_key, result)
        return result

    profile = TEST_PROFILES[mode]
    attempts = profile["attempts"]
    timeout = profile["timeout"]
    best = None
    best_family = None
    best_ip = None

    # IPv4 and IPv6 are tested independently. A failure of one family does not
    # kill a proxy when the other family succeeds.
    for item in dns["addresses"]:
        family = socket.AF_INET6 if item["family"] == "IPv6" else socket.AF_INET
        for _ in range(attempts):
            ms = tcp_connect(item["ip"], port, timeout, family)
            if ms is not None and (best is None or ms < best):
                best = ms
                best_family = item["family"]
                best_ip = item["ip"]

    if best is None:
        status = "TCP_FAIL"
    else:
        status = "TCP_OK"

    result = {
        "dns_status": "DNS_OK",
        "tcp_status": status,
        "reachable": best is not None,
        "latency_ms": best,
        "family": best_family,
        "address": best_ip,
        "cached": False,
    }
    with _CACHE_LOCK:
        cache.put("tcp", cache_key, result)
    return result


# ============================================================
# SCORE ENGINE
# ============================================================

def protocol_score(p):
    # This is a syntax/configuration score, NOT proof of protocol usability.
    required = {
        "vless": ("uuid", "server", "port"),
        "vmess": ("uuid", "server", "port"),
        "trojan": ("password", "server", "port"),
        "ss": ("password", "cipher", "server", "port"),
        "ssr": ("password", "cipher", "server", "port"),
        "hysteria": ("password", "server", "port"),
        "hysteria2": ("password", "server", "port"),
        "tuic": ("uuid", "password", "server", "port"),
        "wireguard": ("private-key", "server", "port"),
    }
    fields = required.get(p.get("type"), ("server", "port"))
    good = sum(bool(p.get(k)) for k in fields)
    return int(20 * good / max(1, len(fields)))


def config_score(p):
    score = 0
    if p.get("server"):
        score += 2
    if valid_port(p.get("port")):
        score += 2
    if p.get("type") in SUPPORTED_SCHEMES:
        score += 2
    if p.get("network"):
        score += 1
    if p.get("tls") or p.get("type") in ("ss", "ssr"):
        score += 1
    if p.get("udp"):
        score += 1
    if p.get("reality-opts") or p.get("ws-opts") or p.get("grpc-opts") or p.get("h2-opts"):
        score += 1
    return min(10, score)


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
    return 3


def score_proxy(p, test):
    dns = 10 if test.get("dns_status") == "DNS_OK" else 0
    tcp = 30 if test.get("tcp_status") == "TCP_OK" else 0
    lat = latency_score(test.get("latency_ms"))
    proto = protocol_score(p)
    cfg = config_score(p)
    return dns + tcp + lat + proto + cfg


# ============================================================
# MIHOMO COMPATIBILITY CHECKER
# ============================================================

def mihomo_validate_proxy(p):
    errors = []
    warnings = []
    typ = p.get("type")
    if typ not in SUPPORTED_SCHEMES:
        errors.append("unsupported-proxy-type")
    if not p.get("server"):
        errors.append("missing-server")
    if not valid_port(p.get("port")):
        errors.append("invalid-port")

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
    for key in required.get(typ, ()):
        if not p.get(key):
            errors.append(f"missing-{key}")

    if p.get("network") == "ws" and "ws-opts" not in p:
        warnings.append("ws-network-without-ws-opts")
    if p.get("network") == "grpc" and "grpc-opts" not in p:
        warnings.append("grpc-network-without-grpc-opts")
    if p.get("tls") and not p.get("servername") and not p.get("sni"):
        warnings.append("tls-without-sni")
    return errors, warnings


def validate_yaml_structure(data):
    errors = []
    if not isinstance(data, dict):
        return ["root-not-mapping"]
    proxies = data.get("proxies")
    groups = data.get("proxy-groups")
    rules = data.get("rules")
    if not isinstance(proxies, list):
        errors.append("proxies-not-list")
    if not isinstance(groups, list):
        errors.append("proxy-groups-not-list")
    if not isinstance(rules, list):
        errors.append("rules-not-list")

    names = set()
    if isinstance(proxies, list):
        for p in proxies:
            if not isinstance(p, dict):
                errors.append("proxy-not-mapping")
                continue
            n = p.get("name")
            if not n:
                errors.append("proxy-missing-name")
            elif n in names:
                errors.append(f"duplicate-proxy-name:{n}")
            names.add(n)

    group_names = set()
    if isinstance(groups, list):
        for g in groups:
            if not isinstance(g, dict):
                errors.append("group-not-mapping")
                continue
            n = g.get("name")
            if not n:
                errors.append("group-missing-name")
            elif n in group_names:
                errors.append(f"duplicate-group-name:{n}")
            group_names.add(n)
            for ref in g.get("proxies", []) or []:
                if ref != "DIRECT" and ref not in names and ref not in group_names:
                    # Forward references to groups are valid in Mihomo;
                    # resolve them after all groups have been collected.
                    pass
    # Second pass: validate proxy/group references after every group name exists.
    if isinstance(groups, list):
        for g in groups:
            if not isinstance(g, dict):
                continue
            for ref in g.get("proxies", []) or []:
                if ref != "DIRECT" and ref not in names and ref not in group_names:
                    errors.append(f"group-reference-missing:{ref}")
    return errors


# ============================================================
# ADAPTIVE WORKERS / BATCHING
# ============================================================

def choose_workers(count):
    if count <= 100:
        return 8
    if count <= 500:
        return 16
    if count <= 2000:
        return 24
    if count <= 5000:
        return 32
    return 32


def choose_batch_size(count):
    if count <= 100:
        return 50
    if count <= 1000:
        return 100
    if count <= 5000:
        return 100
    return 150


def test_in_batches(proxies, cache, mode):
    workers = min(choose_workers(len(proxies)), MAX_WORKERS)
    batch_size = choose_batch_size(len(proxies))
    results = []
    total = len(proxies)

    for start in range(0, total, batch_size):
        batch = proxies[start:start + batch_size]
        print(f"[TEST] {start + 1}-{min(start + len(batch), total)}/{total} | workers={workers} | mode={mode}")
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(tcp_test, p, cache, mode): p for p in batch}
            for future in as_completed(futures):
                p = futures[future]
                try:
                    t = future.result()
                except Exception as exc:
                    t = {
                        "dns_status": "TEST_ERROR",
                        "tcp_status": "TEST_ERROR",
                        "reachable": False,
                        "latency_ms": None,
                        "family": None,
                        "address": None,
                        "cached": False,
                        "error": type(exc).__name__,
                    }
                p["_test"] = t
                p["_score"] = score_proxy(p, t)
                if t.get("dns_status") == "DNS_OK" and t.get("tcp_status") == "TCP_OK":
                    p["_status"] = "TCP_OK / PROTOCOL_UNKNOWN"
                elif t.get("dns_status") == "DNS_OK":
                    p["_status"] = "DNS_OK / TCP_FAIL"
                else:
                    p["_status"] = "DNS_FAIL"
                results.append(p)
        cache.save()
    return results


# ============================================================
# DEDUPLICATION
# ============================================================

def deduplicate(proxies):
    exact_seen = set()
    semantic_seen = set()
    unique = []
    exact_dups = 0
    semantic_dups = 0

    for p in proxies:
        fp = fingerprint_proxy(p)
        if fp in exact_seen:
            exact_dups += 1
            continue
        exact_seen.add(fp)

        sfp = semantic_fingerprint(p)
        if sfp in semantic_seen:
            semantic_dups += 1
            continue
        semantic_seen.add(sfp)
        unique.append(p)

    return unique, exact_dups, semantic_dups


# ============================================================
# OUTPUT BUILDER
# ============================================================

def strip_internal(p):
    clean = dict(p)
    clean.pop("_test", None)
    clean.pop("_score", None)
    clean.pop("_status", None)
    clean.pop("_unknown", None)
    return clean


def build_yaml(proxies):
    sorted_proxies = sorted(
        proxies,
        key=lambda p: (-int(p.get("_score", 0)), p.get("_test", {}).get("latency_ms") or 999999, p.get("name", ""))
    )
    clean = [strip_internal(p) for p in sorted_proxies]
    names = [p["name"] for p in clean]

    # Requested groups/rule: no fake PROXY group.
    groups = [
        {
            "name": "Mobile-Fast❤",
            "type": "url-test",
            "proxies": names,
            "url": "https://www.gstatic.com/generate_204",
            "interval": 300,
            "timeout": 5000,
            "tolerance": 50,
        },
        {
            "name": "Mobile-Auto❤",
            "type": "fallback",
            "proxies": ["Mobile-Fast❤"] + names,
            "url": "https://www.gstatic.com/generate_204",
            "interval": 300,
            "timeout": 5000,
        },
    ]

    # Automatic DNS section; no prompt.
    dns = {
        "enable": True,
        "ipv6": False,
        "enhanced-mode": "fake-ip",
        "nameserver": ["1.1.1.1", "8.8.8.8"],
        "fallback": ["9.9.9.9", "1.0.0.1"],
    }

    return {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "dns": dns,
        "proxies": clean,
        "proxy-groups": groups,
        "rules": ["MATCH,Mobile-Fast❤"],
    }


def atomic_yaml_write(path, data):
    folder = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(prefix=".akbar98_", suffix=".yaml", dir=folder, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            yaml.safe_dump(data, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
            f.flush()
            os.fsync(f.fileno())
        with open(tmp, "r", encoding="utf-8") as f:
            loaded = yaml.safe_load(f)
        errs = validate_yaml_structure(loaded)
        if errs:
            raise ValueError("YAML validation failed: " + ", ".join(errs[:10]))
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except Exception:
                pass


# ============================================================
# REPORTS
# ============================================================

def write_reports(out_dir, stem, stats, proxies, failures, unknowns):
    report_path = os.path.join(out_dir, f"{stem}_report.txt")
    failed_path = os.path.join(out_dir, f"{stem}_failed.txt")

    with open(report_path, "w", encoding="utf-8") as f:
        f.write("Akbar98 Final Converter Report\n")
        f.write("=" * 64 + "\n")
        for k, v in stats.items():
            f.write(f"{k:<28}: {v}\n")
        f.write("\nTest semantics:\n")
        f.write("- LIGHT default: DNS -> TCP connect -> close\n")
        f.write("- No HTTP health check or application download by converter\n")
        f.write("- TCP_OK does NOT prove protocol usability\n")
        f.write("\nTop results:\n")
        for p in sorted(proxies, key=lambda x: (-x.get("_score", 0), x.get("_test", {}).get("latency_ms") or 999999))[:100]:
            t = p.get("_test", {})
            f.write(
                f"{p['name']} | {p['type']} | score={p.get('_score', 0)} | "
                f"status={p.get('_status', '')} | latency={t.get('latency_ms')}ms | "
                f"family={t.get('family')} | {p.get('server')}:{p.get('port')}\n"
            )
        if unknowns:
            f.write("\nUnknown parameters:\n")
            for name, keys in unknowns.items():
                f.write(f"{name}: {', '.join(keys)}\n")

    with open(failed_path, "w", encoding="utf-8") as f:
        f.write("Akbar98 Failed / Unsupported Input\n")
        f.write("=" * 64 + "\n")
        for item in failures:
            f.write(item + "\n")

    return report_path, failed_path


# ============================================================
# MAIN
# ============================================================

def main():
    clear_input_file()
    open_nano_for_input()
    content = read_and_clear_input()

    # User chooses only output folder/name. No test-related questions.
    out_folder = input("Enter output folder name in Download: ").strip()
    if not out_folder:
        print("[ERROR] Folder name required.")
        return 1

    out_dir = os.path.join("/storage/emulated/0/Download", out_folder)
    os.makedirs(out_dir, exist_ok=True)

    out_name = input("Enter output file name (without extension): ").strip()
    if not out_name:
        print("[ERROR] File name required.")
        return 1

    out_name = clean_name(out_name)
    out_path = os.path.join(out_dir, out_name + ".yaml")

    mode = DEFAULT_TEST_MODE
    print("\n" + "=" * 64)
    print("Akbar98 Final Low-Data Engine")
    print("=" * 64)
    print(f"Test mode          : {mode}")
    print("Test pipeline      : DNS -> TCP -> close")
    print("HTTP/download test : OFF")
    print("Mihomo URL-Test    : ON (inside YAML)")
    print("DNS section        : ON (automatic)")
    print("=" * 64)

    lines, _ = expand_input(content)
    # Preserve order while removing exact repeated source lines.
    source_lines = []
    source_seen = set()
    for line in lines:
        line = line.strip()
        if line and line not in source_seen:
            source_seen.add(line)
            source_lines.append(line)

    used = set()
    parsed = []
    failures = []
    unknowns = {}
    for line in source_lines:
        p, err, unknown = parse_link(line, used)
        if p:
            p["_unknown"] = unknown
            parsed.append(p)
            if unknown:
                unknowns[p["name"]] = unknown
        else:
            failures.append(f"{err} | {line[:500]}")

    if not parsed:
        clear_input_file()
        print("[ERROR] No valid supported proxy links found.")
        return 1

    before_dedup = len(parsed)
    parsed, exact_dups, semantic_dups = deduplicate(parsed)

    cache = CacheStore(CACHE_PATH)
    tested = test_in_batches(parsed, cache, mode)

    mihomo_valid = []
    mihomo_failed = 0
    for p in tested:
        errs, warns = mihomo_validate_proxy(p)
        p["_mihomo_errors"] = errs
        p["_mihomo_warnings"] = warns
        if not errs:
            mihomo_valid.append(p)
        else:
            mihomo_failed += 1
            failures.append(f"mihomo-invalid | {p['name']} | {', '.join(errs)}")

    if not mihomo_valid:
        clear_input_file()
        print("[ERROR] No Mihomo-compatible proxies remain.")
        return 1

    yaml_data = build_yaml(mihomo_valid)
    yaml_errors = validate_yaml_structure(yaml_data)
    if yaml_errors:
        clear_input_file()
        print("[ERROR] Final YAML validation failed:")
        for e in yaml_errors[:20]:
            print(" -", e)
        return 1

    try:
        atomic_yaml_write(out_path, yaml_data)
    except Exception as exc:
        clear_input_file()
        print(f"[ERROR] Could not write validated YAML: {exc}")
        return 1

    reachable = sum(1 for p in mihomo_valid if p.get("_test", {}).get("tcp_status") == "TCP_OK")
    dns_ok = sum(1 for p in mihomo_valid if p.get("_test", {}).get("dns_status") == "DNS_OK")
    cached_tcp = sum(1 for p in mihomo_valid if p.get("_test", {}).get("cached"))

    stats = {
        "Input links": len(source_lines),
        "Parsed": before_dedup,
        "Exact duplicates": exact_dups,
        "Semantic duplicates": semantic_dups,
        "After dedup": len(parsed),
        "DNS OK": dns_ok,
        "TCP reachable": reachable,
        "TCP unreachable": len(parsed) - reachable,
        "Mihomo valid": len(mihomo_valid),
        "Mihomo invalid": mihomo_failed,
        "Cached TCP results": cached_tcp,
        "Test mode": mode,
        "HTTP/download by converter": "OFF",
        "Main YAML": out_path,
    }

    report_path, failed_path = write_reports(
        out_dir, out_name, stats, mihomo_valid, failures, unknowns
    )

    # Final guarantee for the next execution.
    clear_input_file()
    cache.save()

    print("\n" + "=" * 64)
    print("[DONE] Akbar98 YAML created and validated successfully.")
    print("=" * 64)
    print(f"YAML       : {out_path}")
    print(f"Report     : {report_path}")
    print(f"Failed     : {failed_path}")
    print(f"Input      : {len(source_lines)}")
    print(f"Parsed     : {before_dedup}")
    print(f"After dedup: {len(parsed)}")
    print(f"TCP OK     : {reachable}")
    print(f"Final      : {len(mihomo_valid)}")
    print("Input file : EMPTY")
    print("Data test  : DNS/TCP connection-only")
    print("Downloads  : OFF")
    print("URL-Test   : Mihomo YAML only")
    print("=" * 64)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    finally:
        try:
            clear_input_file()
        except Exception:
            pass
