#!/data/data/com.termux/files/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Ultra Live AutoSwitch Parser – Clash Meta Generator
با سوئیچینگ زنده و خودکار
"""
# ====================== IMPORTS ======================
import time
import yaml
from concurrent.futures import ThreadPoolExecutor
import threading
import threading
import os
import sys
import re
import socket
import time
import json
import base64
import yaml
import subprocess

from urllib.parse import (
    urlparse,
    parse_qs,
    unquote
)

from concurrent.futures import (
    ThreadPoolExecutor,
    as_completed
)

# ---------------- Paths ----------------
BASE_DIR = "/storage/emulated/0/Download/akbar98"
os.makedirs(BASE_DIR, exist_ok=True)
INPUT_PATH = os.path.join(BASE_DIR, "input.txt")

with open(INPUT_PATH,"w",encoding="utf-8") as f: f.write("")
try: subprocess.call(["nano", INPUT_PATH])
except: pass

out_folder = input("Enter output folder name in Download: ").strip() or "ClashMetaAutoSwitch"
OUT_DIR = os.path.join("/storage/emulated/0/Download", out_folder)
os.makedirs(OUT_DIR, exist_ok=True)
out_file = input("Enter output file name (without extension): ").strip() or "autoswitch_proxies"
OUT_PATH = os.path.join(OUT_DIR, f"{out_file}.yaml")

# ---------------- Helpers ----------------
def b64fix(s):
    if not s:
        return ""
    s = str(s).strip().replace("\n", "").replace(" ", "")
    s = s.replace("-", "+").replace("_", "/")
    pad = len(s) % 4
    if pad:
        s += "=" * (4 - pad)
    return s

def is_probably_base64(s):
    if not isinstance(s, str): return False
    s = s.strip()
    if len(s) < 8: return False
    try:
        base64.b64decode(b64fix(s))
        return True
    except Exception:
        return False

def safe_int(v, default=0):
    try:
        return int(v)
    except Exception:
        try:
            return int(float(v))
        except Exception:
            return default

def sanitize(s):
    if not s: return ""
    return re.sub(r"[^A-Za-z0-9_\- .]", "", str(s)).strip()

_used_names = set()
def uniq_name(base):
    base = sanitize(str(base)) or "Proxy"
    name = base
    i = 2
    while name in _used_names:
        name = f"{base} {i}"
        i += 1
    _used_names.add(name)
    return name

def tail(s, n=6):
    if not s: return ""
    s2 = re.sub(r"[-]", "", str(s))
    return s2[-n:] if len(s2) >= n else s2
    def b64fix(s): return s.replace("-", "+").replace("_", "/") + "=" * (-len(s) % 4)
    
def safe_int(x,d=0): 
    try: return int(x)
    except: return d
def sanitize(s): return re.sub(r'[\n\r]+','',str(s).strip())

_used_names=set()
def uniq_name(base):
    name=base; c=1
    while name in _used_names:
        name=f"{base}-{c}"; c+=1
    _used_names.add(name)
    return name

def split_host_port(hostport):
    if ":" in hostport: h,p=hostport.split(":",1); return h.strip(), safe_int(p)
    return hostport.strip(), None
    

# ---------------- TCP Ping ----------------
def tcp_ping_once(host,port,timeout=0.5):
    try:
        s=socket.socket(); s.settimeout(timeout)
        t0=time.time(); s.connect((host,port)); s.close()
        return int((time.time()-t0)*1000)
    except: return None

def tcp_ping_median(host,port,n=3):
    pings=[p for _ in range(n) if (p:=tcp_ping_once(host,port))]
    if not pings: return None
    pings.sort(); m=len(pings)//2
    return pings[m] if len(pings)%2 else (pings[m-1]+pings[m])//2

def attach_ping(proxy):
    proxy["ping"]=tcp_ping_median(proxy["server"],proxy["port"])
    proxy["status"]="✅" if proxy["ping"] is not None else "❌"
    return proxy

# ---------------- Parsers ----------------
def parse_vless(line):
    try:
        if not line.startswith("vless://"): return None
        raw=line[8:]; name=None
        if "#" in raw: raw,name=raw.split("#",1); name=unquote(name)
        creds,_,params=raw.partition("?"); uuid,_,hostport=creds.partition("@")
        host,port=split_host_port(hostport)
        param_dict=dict(p.split("=",1) for p in params.split("&") if "=" in p)
        proxy={"name":uniq_name(name or f"VLESS-{host}-{port}"),"type":"vless","server":host,
               "port":safe_int(port,443),"uuid":uuid,"tls":param_dict.get("security")=="tls",
               "network":param_dict.get("type","tcp"),"mptcp":True,"tfo":True}
        if proxy["network"]=="ws": proxy["ws-opts"]={"path":param_dict.get("path","/"),"headers":{"Host":param_dict.get("host",host)}}
        return proxy
    except: return None

def parse_vmess(line):
    try:
        if not line.startswith("vmess://"): return None
        raw=line[8:]
        js=None
        try: js=base64.b64decode(b64fix(raw)).decode()
        except: js=unquote(raw)
        import json; js=json.loads(js)
        host=js.get("add") or js.get("address"); port=js.get("port"); uuid=js.get("id") or js.get("uuid")
        proxy={"name":uniq_name(js.get("ps") or f"VMESS-{host}-{uuid[-6:]}"),"type":"vmess",
               "server":host,"port":safe_int(port),"uuid":uuid,"alterId":int(js.get("aid",0)),
               "cipher":js.get("scy","auto"),"network":js.get("net","tcp"),"tls":js.get("tls")=="tls"}
        return proxy
    except: return None

def parse_trojan(line):
    try:
        if not line.startswith("trojan://"): return None
        raw=line[9:]; name=None
        if "#" in raw: raw,name=raw.split("#",1); name=unquote(name)
        creds,_,params=raw.partition("?"); password,_,hostport=creds.partition("@")
        host,port=split_host_port(hostport)
        proxy={"name":uniq_name(name or f"Trojan-{host}-{port}"),"type":"trojan","server":host,
               "port":safe_int(port,443),"password":password,"tls":True,"network":params.get("type","tcp"),
               "mptcp":True,"tfo":True}
        return proxy
    except: return None

def parse_ss(line):
    try:
        if not line.startswith("ss://"): return None
        raw=line[5:]; decoded=base64.urlsafe_b64decode(b64fix(raw.split("#")[0])).decode()
        method_pass,_,hostport=decoded.partition("@"); cipher,password=method_pass.split(":",1)
        host,port=split_host_port(hostport)
        return {"name":uniq_name(f"SS-{host}-{port}"),"type":"ss","server":host,"port":safe_int(port),
                "cipher":cipher,"password":password,"udp":True}
    except: return None

def parse_ssr(line):
    try:
        if not line.startswith("ssr://"): return None
        raw=base64.urlsafe_b64decode(b64fix(line[6:])).decode()
        items=raw.split(":")
        if len(items)<6: return None
        host,port,protocol,method,obfs,pass_b64=items[:6]
        password=base64.urlsafe_b64decode(b64fix(pass_b64)).decode()
        return {"name":uniq_name(f"SSR-{host}-{port}"),"type":"ssr","server":host,"port":safe_int(port),
                "protocol":protocol,"cipher":method,"obfs":obfs,"password":password}
    except: return None

def parse_hysteria(line):
    try:
        if not line.lower().startswith("hysteria://"): return None
        raw=line[len("hysteria://"):]
        creds,_,params=raw.partition("?"); host,port=split_host_port(creds)
        param_dict=dict(p.split("=",1) for p in params.split("&") if "=" in p)
        return {"name":uniq_name(f"Hysteria-{host}-{port}"),"type":"hysteria","server":host,"port":safe_int(port),
                "protocol":param_dict.get("protocol","udp"),"auth":param_dict.get("auth",""),"obfs":param_dict.get("obfs","")}
    except: return None

def parse_tuic(line): return {"name":uniq_name("TUIC"),"type":"tuic"} if line.startswith("tuic://") else None
def parse_wireguard(line): return {"name":uniq_name("WireGuard"),"type":"wireguard"} if line.startswith("wg://") else None
def parse_http(line): return {"name":uniq_name("HTTP"),"type":"http","server":line} if line.startswith("http") else None
def parse_socks(line): return {"name":uniq_name("SOCKS"),"type":"socks","server":line} if line.startswith("socks") else None

def parse_line(line):
    line=sanitize(line)
    for p in (parse_vless,parse_vmess,parse_trojan,parse_ss,parse_ssr,parse_hysteria,parse_tuic,parse_wireguard,parse_http,parse_socks):
        if (res:=p(line)): return res
    return None
    
# ---------------- Groups ----------------

def generate_groups(proxies):
    alive=[p for p in proxies if p["status"]=="✅" and p.get("ping")]
    alive.sort(key=lambda x:x["ping"])
    top_fast=alive[:15]; stable=[p for p in alive if p["ping"]<650][:15]; top3=alive[:15]; all_names=[p["name"] for p in alive]
    
    return [
        {"name":"🌐 All Proxies","type":"select","proxies":all_names},
         {
            "name": "🥌 Selector",
            "type": "select",
            "proxies": [
                "💚 Top Fast",
                "💛 Top Stable <650ms",
                "⚡ Top 3 AutoSwitch",
                "🪀Fallback Stable",
                "🌐 All Proxies"
            ]
       },
        {"name":"⚡ Top 3 AutoSwitch","type":"url-test","proxies":[p["name"] for p in top3],
         "url":"http://www.google.com/generate_204","interval":8761,"tolerance":850},
        {"name":"🪀Fallback Stable","type":"fallback","proxies":all_names,
         "url":"http://www.google.com/generate_204","interval":7652},
        {"name":"💚 Top Fast","type":"url-test","proxies":[p["name"] for p in top_fast],
         "url":"http://www.google.com/generate_204","interval":9871,"tolerance":850},
        {"name":"💛 Top Stable <650ms","type":"url-test","proxies":[p["name"] for p in stable],
         "url":"http://www.google.com/generate_204","interval":1765,"tolerance":950}
     
    ]

# ---------------- Main ----------------
if __name__=="__main__":
    lines=open(INPUT_PATH,"r",encoding="utf-8").read().splitlines()
    proxies=[p for ln in lines if (p:=parse_line(ln))]
    
    with ThreadPoolExecutor(max_workers=30) as exe:
        proxies=list(exe.map(attach_ping, proxies))
    
    alive=[p for p in proxies if p["status"]=="✅"]
    if not alive:
        print("[ERROR] No alive proxies found.")
        exit(1)
    
    alive.sort(key=lambda x:x["ping"])
    
    data={"proxies":alive,"proxy-groups":generate_groups(alive)}
    
    with open(OUT_PATH,"w",encoding="utf-8") as f: yaml.dump(data,f,allow_unicode=True)
    
    print(f"[DONE] Ultra Premium AutoSwitch Stable YAML saved: {OUT_PATH}")
