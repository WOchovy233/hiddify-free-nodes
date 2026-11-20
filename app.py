# -*- coding: utf-8 -*-
"""
节点捕食者 Pro
面向 Hiddify 的免费节点抓取、地区筛选、稳定性质检与订阅导出工具。

主要特性：
- Windows 图形界面（无黑框）
- 实时抓取/测速进度
- TCP + TLS 双重探测、多轮稳定性复测、抖动过滤
- 常用国家/地区勾选
- 仅保留可规范化为 Hiddify 可导入格式的节点
- 同时导出 Base64 订阅 TXT 和 Clash/Mihomo YAML
"""

from __future__ import annotations

import base64
import concurrent.futures
import ctypes
import ipaddress
import json
import os
import queue
import re
import socket
import ssl
import sys
import threading
import time
import traceback
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

import requests
import dns.exception
import dns.resolver
from ruamel.yaml import YAML

APP_NAME = "节点捕食者 Pro"
APP_VERSION = "2.1"
OUTPUT_TXT = "clean_nodes.txt"
OUTPUT_YAML = "clean_nodes.yaml"
OUTPUT_SINGBOX = "clean_nodes_singbox.json"
OUTPUT_PLAIN = "clean_nodes_plain.txt"

SOURCE_URLS = [
    "https://ghproxy.net/https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/clash.yml",
    "https://raw.githubusercontent.com/anaer/Sub/main/clash.yaml",
    "https://raw.githubusercontent.com/zhangkaiitugithub/passcro/main/speednodes.yaml",
    "https://raw.githubusercontent.com/chengaopan/AutoMergePublicNodes/master/list.yml",
    "https://cdn.jsdelivr.net/gh/free18/v2ray@main/c.yaml",
    "https://raw.githubusercontent.com/mfuu/v2ray/master/clash.yaml",
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.yml",
    "https://raw.githubusercontent.com/ripaojiedian/freenode/main/clash",
    "https://raw.githubusercontent.com/awesome-vpn/awesome-vpn/master/clash.yaml",
    "https://sunmiao4458.github.io/free-proxy-airport/clash.yaml",
]

SUPPORTED_TYPES = {
    "vmess", "vless", "trojan", "ss",
    "hysteria2", "hysteria", "tuic", "wireguard",
    "ssh", "anytls", "socks5", "http",
}
TCP_PROTOCOLS = {"vmess", "vless", "trojan", "ss", "ssh", "anytls", "socks5", "http"}
UDP_PROTOCOLS = {"hysteria2", "hysteria", "tuic", "wireguard"}
TLS_DEFAULT_TYPES = {"trojan", "hysteria2", "tuic", "anytls"}
SUPPORTED_NETWORKS = {"tcp", "ws", "grpc", "http", "h2", "httpupgrade", "xhttp", "quic", "kcp"}
SUPPORTED_SS_CIPHERS = {
    "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
    "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
    "aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
    "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
    "chacha20-ietf", "chacha20", "rc4-md5", "none",
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
}
SUPPORTED_VLESS_FLOWS = {"", "xtls-rprx-vision", "xtls-rprx-vision-udp443"}
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
HOST_RE = re.compile(r"^[A-Za-z0-9._:\-\[\]]+$")
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")

QUALITY_PRESETS = {
    "fast": {"label": "极速（1轮，不推荐）", "attempts": 1, "required": 1},
    "balanced": {"label": "均衡（3轮2次成功）", "attempts": 3, "required": 2},
    "strict": {"label": "严格（3轮全成功 · 推荐）", "attempts": 3, "required": 3},
}

# 常用、免费节点中通过率相对较高的国家/地区。默认全部勾选。
REGION_DEFS = [
    {"code": "HK", "cn": "香港", "en": "Hong Kong", "aliases": ["香港", "hong kong", "hongkong", "hkg", "hk", "深港"]},
    {"code": "TW", "cn": "台湾", "en": "Taiwan", "aliases": ["台湾", "台灣", "taiwan", "taipei", "台北", "新北", "彰化", "hinet", "tpe", "tw"]},
    {"code": "JP", "cn": "日本", "en": "Japan", "aliases": ["日本", "japan", "tokyo", "osaka", "东京", "東京", "大阪", "埼玉", "nrt", "kix", "jp"]},
    {"code": "SG", "cn": "新加坡", "en": "Singapore", "aliases": ["新加坡", "狮城", "獅城", "singapore", "changi", "sin", "sg"]},
    {"code": "KR", "cn": "韩国", "en": "South Korea", "aliases": ["韩国", "韓國", "南韩", "korea", "seoul", "首尔", "首爾", "icn", "kr"]},
    {"code": "US", "cn": "美国", "en": "United States", "aliases": ["美国", "美國", "united states", "usa", "los angeles", "san jose", "seattle", "new york", "dallas", "chicago", "miami", "silicon valley", "ashburn", "洛杉矶", "聖荷西", "圣何塞", "西雅图", "纽约", "紐約", "达拉斯", "芝加哥", "迈阿密", "硅谷", "us"]},
    {"code": "CA", "cn": "加拿大", "en": "Canada", "aliases": ["加拿大", "canada", "toronto", "vancouver", "montreal", "多伦多", "温哥华", "蒙特利尔", "ca"]},
    {"code": "GB", "cn": "英国", "en": "United Kingdom", "aliases": ["英国", "英國", "united kingdom", "england", "london", "manchester", "伦敦", "倫敦", "uk", "gb"]},
    {"code": "DE", "cn": "德国", "en": "Germany", "aliases": ["德国", "德國", "germany", "frankfurt", "berlin", "法兰克福", "柏林", "de"]},
    {"code": "FR", "cn": "法国", "en": "France", "aliases": ["法国", "法國", "france", "paris", "marseille", "巴黎", "马赛", "fr"]},
    {"code": "NL", "cn": "荷兰", "en": "Netherlands", "aliases": ["荷兰", "荷蘭", "netherlands", "amsterdam", "rotterdam", "阿姆斯特丹", "鹿特丹", "nl"]},
    {"code": "RU", "cn": "俄罗斯", "en": "Russia", "aliases": ["俄罗斯", "俄羅斯", "russia", "moscow", "saint petersburg", "莫斯科", "圣彼得堡", "ru"]},
    {"code": "TR", "cn": "土耳其", "en": "Turkey", "aliases": ["土耳其", "turkey", "istanbul", "ankara", "伊斯坦布尔", "安卡拉", "tr"]},
    {"code": "IN", "cn": "印度", "en": "India", "aliases": ["印度", "india", "mumbai", "delhi", "bangalore", "孟买", "新德里", "班加罗尔", "in"]},
    {"code": "ID", "cn": "印度尼西亚", "en": "Indonesia", "aliases": ["印尼", "印度尼西亚", "indonesia", "jakarta", "雅加达", "泗水", "id"]},
    {"code": "MY", "cn": "马来西亚", "en": "Malaysia", "aliases": ["马来西亚", "馬來西亞", "malaysia", "kuala lumpur", "吉隆坡", "my"]},
    {"code": "TH", "cn": "泰国", "en": "Thailand", "aliases": ["泰国", "泰國", "thailand", "bangkok", "曼谷", "th"]},
    {"code": "VN", "cn": "越南", "en": "Vietnam", "aliases": ["越南", "vietnam", "viet nam", "hanoi", "河内", "胡志明", "vn"]},
    {"code": "PH", "cn": "菲律宾", "en": "Philippines", "aliases": ["菲律宾", "菲律賓", "philippines", "manila", "马尼拉", "ph"]},
    {"code": "AU", "cn": "澳大利亚", "en": "Australia", "aliases": ["澳大利亚", "澳洲", "australia", "sydney", "melbourne", "悉尼", "墨尔本", "au"]},
    {"code": "NZ", "cn": "新西兰", "en": "New Zealand", "aliases": ["新西兰", "新西蘭", "new zealand", "auckland", "奥克兰", "nz"]},
    {"code": "BR", "cn": "巴西", "en": "Brazil", "aliases": ["巴西", "brazil", "sao paulo", "圣保罗", "br"]},
    {"code": "AR", "cn": "阿根廷", "en": "Argentina", "aliases": ["阿根廷", "argentina", "buenos aires", "布宜诺斯艾利斯", "ar"]},
    {"code": "CL", "cn": "智利", "en": "Chile", "aliases": ["智利", "chile", "santiago", "圣地亚哥", "cl"]},
    {"code": "MX", "cn": "墨西哥", "en": "Mexico", "aliases": ["墨西哥", "mexico", "mexico city", "墨西哥城", "mx"]},
    {"code": "ZA", "cn": "南非", "en": "South Africa", "aliases": ["南非", "south africa", "johannesburg", "cape town", "约翰内斯堡", "开普敦", "za"]},
    {"code": "EG", "cn": "埃及", "en": "Egypt", "aliases": ["埃及", "egypt", "cairo", "开罗", "eg"]},
    {"code": "AE", "cn": "阿联酋", "en": "United Arab Emirates", "aliases": ["阿联酋", "阿聯酋", "uae", "united arab emirates", "dubai", "abu dhabi", "迪拜", "阿布扎比", "ae"]},
    {"code": "SA", "cn": "沙特阿拉伯", "en": "Saudi Arabia", "aliases": ["沙特", "沙特阿拉伯", "saudi arabia", "riyadh", "jeddah", "利雅得", "sa"]},
    {"code": "IL", "cn": "以色列", "en": "Israel", "aliases": ["以色列", "israel", "tel aviv", "特拉维夫", "il"]},
    {"code": "PL", "cn": "波兰", "en": "Poland", "aliases": ["波兰", "波蘭", "poland", "warsaw", "华沙", "pl"]},
    {"code": "CZ", "cn": "捷克", "en": "Czechia", "aliases": ["捷克", "czechia", "czech republic", "prague", "布拉格", "cz"]},
    {"code": "AT", "cn": "奥地利", "en": "Austria", "aliases": ["奥地利", "奧地利", "austria", "vienna", "维也纳", "at"]},
    {"code": "CH", "cn": "瑞士", "en": "Switzerland", "aliases": ["瑞士", "switzerland", "zurich", "geneva", "苏黎世", "日内瓦", "ch"]},
    {"code": "SE", "cn": "瑞典", "en": "Sweden", "aliases": ["瑞典", "sweden", "stockholm", "斯德哥尔摩", "se"]},
    {"code": "NO", "cn": "挪威", "en": "Norway", "aliases": ["挪威", "norway", "oslo", "奥斯陆", "no"]},
    {"code": "DK", "cn": "丹麦", "en": "Denmark", "aliases": ["丹麦", "丹麥", "denmark", "copenhagen", "哥本哈根", "dk"]},
    {"code": "FI", "cn": "芬兰", "en": "Finland", "aliases": ["芬兰", "芬蘭", "finland", "helsinki", "赫尔辛基", "fi"]},
    {"code": "IE", "cn": "爱尔兰", "en": "Ireland", "aliases": ["爱尔兰", "愛爾蘭", "ireland", "dublin", "都柏林", "ie"]},
    {"code": "ES", "cn": "西班牙", "en": "Spain", "aliases": ["西班牙", "spain", "madrid", "barcelona", "马德里", "巴塞罗那", "es"]},
    {"code": "PT", "cn": "葡萄牙", "en": "Portugal", "aliases": ["葡萄牙", "portugal", "lisbon", "里斯本", "pt"]},
    {"code": "IT", "cn": "意大利", "en": "Italy", "aliases": ["意大利", "italy", "milan", "rome", "米兰", "罗马", "it"]},
    {"code": "BE", "cn": "比利时", "en": "Belgium", "aliases": ["比利时", "比利時", "belgium", "brussels", "布鲁塞尔", "be"]},
    {"code": "RO", "cn": "罗马尼亚", "en": "Romania", "aliases": ["罗马尼亚", "羅馬尼亞", "romania", "bucharest", "布加勒斯特", "ro"]},
    {"code": "HU", "cn": "匈牙利", "en": "Hungary", "aliases": ["匈牙利", "hungary", "budapest", "布达佩斯", "hu"]},
    {"code": "UA", "cn": "乌克兰", "en": "Ukraine", "aliases": ["乌克兰", "烏克蘭", "ukraine", "kyiv", "kiev", "基辅", "ua"]},
    {"code": "KZ", "cn": "哈萨克斯坦", "en": "Kazakhstan", "aliases": ["哈萨克斯坦", "哈薩克", "kazakhstan", "almaty", "阿拉木图", "kz"]},
    {"code": "PK", "cn": "巴基斯坦", "en": "Pakistan", "aliases": ["巴基斯坦", "pakistan", "karachi", "拉合尔", "pk"]},
    {"code": "BD", "cn": "孟加拉国", "en": "Bangladesh", "aliases": ["孟加拉", "孟加拉国", "bangladesh", "dhaka", "达卡", "bd"]},
    {"code": "KH", "cn": "柬埔寨", "en": "Cambodia", "aliases": ["柬埔寨", "cambodia", "phnom penh", "金边", "kh"]},
    {"code": "MO", "cn": "澳门", "en": "Macau", "aliases": ["澳门", "澳門", "macau", "macao", "mo"]},
    {"code": "LK", "cn": "斯里兰卡", "en": "Sri Lanka", "aliases": ["斯里兰卡", "斯里蘭卡", "sri lanka", "colombo", "科伦坡", "lk"]},
]

REGION_BY_CODE = {r["code"]: r for r in REGION_DEFS}
REGION_ALIAS_INDEX: list[tuple[str, str, bool]] = []
for _r in REGION_DEFS:
    for _alias in _r["aliases"]:
        REGION_ALIAS_INDEX.append((_alias.upper(), _r["code"], len(_alias) <= 2 and _alias.isalpha()))


def flag_for(code: str) -> str:
    try:
        return "".join(chr(0x1F1E6 + ord(ch) - ord("A")) for ch in code.upper() if "A" <= ch <= "Z")
    except Exception:
        return ""


def app_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def now_text() -> str:
    return datetime.now().strftime("%H:%M:%S")


def as_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on", "tls", "reality"}


def as_int(value: Any, default: Optional[int] = None) -> Optional[int]:
    try:
        if isinstance(value, bool):
            return default
        return int(str(value).strip())
    except Exception:
        return default


def clean_text(value: Any, limit: int = 90) -> str:
    text = CONTROL_RE.sub(" ", str(value or ""))
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit]


def normalize_host(value: Any) -> Optional[str]:
    host = str(value or "").strip()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    host = host.rstrip(".")
    if not host or len(host) > 253 or " " in host or "/" in host:
        return None
    if "://" in host or not HOST_RE.match(host):
        return None
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    # 域名：允许普通域名；不接受空标签
    if "." not in host:
        return None
    labels = host.split(".")
    if any(not label or len(label) > 63 for label in labels):
        return None
    return host


def normalize_port(value: Any) -> Optional[int]:
    port = as_int(value)
    if port is None or not 1 <= port <= 65535:
        return None
    return port


def node_identity(node: dict) -> str:
    for key in ("uuid", "id", "password", "auth", "psk"):
        value = node.get(key)
        if value not in (None, ""):
            return str(value)
    return ""


def dedupe_key(node: dict) -> tuple:
    return (
        str(node.get("type", "")).lower(),
        str(node.get("server", "")).lower(),
        as_int(node.get("port"), 0),
        node_identity(node),
    )


def sanitize_headers(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    result: dict[str, str] = {}
    for key, val in value.items():
        k = clean_text(key, 80)
        v = clean_text(val, 300)
        if k and v:
            result[k] = v
    return result


def sanitize_ws_opts(value: Any) -> dict:
    if not isinstance(value, dict):
        return {}
    opts: dict[str, Any] = {}
    path = value.get("path")
    if path not in (None, ""):
        opts["path"] = clean_text(path, 500)
    headers = sanitize_headers(value.get("headers"))
    if headers:
        opts["headers"] = headers
    max_early = as_int(value.get("max-early-data"))
    if max_early is not None and max_early >= 0:
        opts["max-early-data"] = max_early
    early_header = value.get("early-data-header-name")
    if early_header:
        opts["early-data-header-name"] = clean_text(early_header, 100)
    return opts


def sanitize_grpc_opts(value: Any) -> dict:
    if not isinstance(value, dict):
        return {}
    service = value.get("grpc-service-name") or value.get("service-name") or value.get("serviceName")
    service = clean_text(service, 200)
    return {"grpc-service-name": service} if service else {}


def sanitize_h2_opts(value: Any) -> dict:
    if not isinstance(value, dict):
        return {}
    opts: dict[str, Any] = {}
    host = value.get("host")
    if isinstance(host, list):
        host = [clean_text(x, 200) for x in host if clean_text(x, 200)]
    elif host:
        host = [clean_text(host, 200)]
    if host:
        opts["host"] = host
    path = value.get("path")
    if path:
        opts["path"] = clean_text(path, 500)
    return opts


def sanitize_http_opts(value: Any) -> dict:
    if not isinstance(value, dict):
        return {}
    opts: dict[str, Any] = {}
    method = clean_text(value.get("method"), 10).upper()
    if method in {"GET", "POST", "HEAD"}:
        opts["method"] = method
    path = value.get("path")
    if isinstance(path, list):
        path = [clean_text(x, 300) for x in path if clean_text(x, 300)]
    elif path:
        path = [clean_text(path, 300)]
    if path:
        opts["path"] = path
    headers = sanitize_headers(value.get("headers"))
    if headers:
        opts["headers"] = headers
    return opts


def sanitize_reality_opts(value: Any) -> dict:
    if not isinstance(value, dict):
        return {}
    public_key = clean_text(value.get("public-key") or value.get("publicKey"), 200)
    short_id = clean_text(value.get("short-id") or value.get("shortId"), 100)
    if not public_key:
        return {}
    spider_x = clean_text(value.get("spider-x") or value.get("spiderX"), 500)
    opts: dict[str, Any] = {"public-key": public_key}
    if short_id:
        opts["short-id"] = short_id
    if spider_x:
        opts["spider-x"] = spider_x
    return opts


def sanitize_alpn(value: Any) -> list[str]:
    if isinstance(value, str):
        values = re.split(r"[,\s]+", value)
    elif isinstance(value, list):
        values = value
    else:
        return []
    result = []
    for item in values:
        item = clean_text(item, 30).lower()
        if item and re.match(r"^[a-z0-9.+_-]+$", item):
            result.append(item)
    return result[:5]


def sanitize_plugin_opts(value: Any) -> dict:
    if not isinstance(value, dict):
        return {}
    result: dict[str, Any] = {}
    for key, val in value.items():
        k = clean_text(key, 60).lower()
        if not re.match(r"^[a-z0-9_-]+$", k):
            continue
        if isinstance(val, bool):
            result[k] = val
        elif isinstance(val, (int, float)) and not isinstance(val, bool):
            result[k] = val
        elif isinstance(val, str):
            v = clean_text(val, 500)
            if v:
                result[k] = v
    return result


def sanitize_fingerprint(value: Any) -> str:
    fingerprint = clean_text(value, 50).lower()
    allowed = {
        "chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq",
        "random", "randomized", "randomizednoalpn",
    }
    return fingerprint if fingerprint in allowed else ""


def sanitize_json_value(value: Any, depth: int = 0) -> Any:
    """保留 XHTTP/KCP 等新传输层的嵌套选项，同时限制深度和大小。"""
    if depth > 5:
        return None
    if isinstance(value, bool) or isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        return clean_text(value, 1000)
    if isinstance(value, list):
        return [sanitize_json_value(item, depth + 1) for item in value[:80]]
    if isinstance(value, dict):
        result = {}
        for key, val in list(value.items())[:100]:
            k = clean_text(key, 80)
            if not k or not re.match(r"^[A-Za-z0-9_.:-]+$", k):
                continue
            cleaned = sanitize_json_value(val, depth + 1)
            if cleaned not in (None, "", [], {}):
                result[k] = cleaned
        return result
    return None


def sanitize_string_list(value: Any, limit: int = 20) -> list[str]:
    if isinstance(value, str):
        values = re.split(r"[,;\s]+", value)
    elif isinstance(value, list):
        values = value
    else:
        return []
    result = []
    for item in values[:limit]:
        text = clean_text(item, 300)
        if text:
            result.append(text)
    return result


def sanitize_int_list(value: Any) -> list[int]:
    if not isinstance(value, list):
        return []
    result = []
    for item in value[:10]:
        number = as_int(item)
        if number is not None and 0 <= number <= 16777215:
            result.append(number)
    return result


def sanitize_xhttp_opts(value: Any) -> dict:
    cleaned = sanitize_json_value(value)
    return cleaned if isinstance(cleaned, dict) else {}


def sanitize_transport(node: dict, raw: dict, network: str) -> bool:
    """规范化 V2Ray/Xray 传输层。返回 False 表示明显残缺。"""
    node["network"] = network
    if network in {"ws", "httpupgrade"}:
        opts = sanitize_ws_opts(raw.get("ws-opts"))
        if network == "httpupgrade":
            extra = sanitize_json_value(raw.get("httpupgrade-opts"))
            if isinstance(extra, dict):
                opts.update(extra)
        if opts:
            node["ws-opts"] = opts
        return True
    if network == "grpc":
        opts = sanitize_grpc_opts(raw.get("grpc-opts"))
        if opts:
            node["grpc-opts"] = opts
        return True
    if network == "h2":
        opts = sanitize_h2_opts(raw.get("h2-opts"))
        if opts:
            node["h2-opts"] = opts
        return True
    if network == "http":
        opts = sanitize_http_opts(raw.get("http-opts"))
        if opts:
            node["http-opts"] = opts
        return True
    if network == "xhttp":
        opts = sanitize_xhttp_opts(raw.get("xhttp-opts"))
        if opts:
            node["xhttp-opts"] = opts
        return True
    if network in {"kcp", "quic"}:
        opts = sanitize_json_value(raw.get(f"{network}-opts"))
        if isinstance(opts, dict) and opts:
            node[f"{network}-opts"] = opts
        return True
    return True


def sanitize_node(raw: Any) -> Optional[dict]:
    """把原始节点规范化为 Hiddify / sing-box / Clash Meta 可导入的结构。"""
    if not isinstance(raw, dict):
        return None
    node_type = str(raw.get("type") or "").strip().lower()
    node_type = {
        "reality": "vless", "hy2": "hysteria2", "wg": "wireguard",
        "socks": "socks5", "https": "http", "http-proxy": "http",
    }.get(node_type, node_type)
    if node_type not in SUPPORTED_TYPES:
        return None

    server = normalize_host(raw.get("server"))
    port = normalize_port(raw.get("port"))
    name = clean_text(raw.get("name") or f"{node_type}-{server}", 90)
    if not server or not port or not name:
        return None

    node: dict[str, Any] = {"name": name, "type": node_type, "server": server, "port": port}
    if "udp" in raw:
        node["udp"] = as_bool(raw.get("udp"), True)
    if "tfo" in raw:
        node["tfo"] = as_bool(raw.get("tfo"), False)

    security = clean_text(raw.get("security"), 20).lower()
    skip_cert = as_bool(raw.get("skip-cert-verify"), False)
    servername = clean_text(raw.get("servername") or raw.get("sni") or raw.get("server-name"), 253)
    client_fingerprint = sanitize_fingerprint(raw.get("client-fingerprint") or raw.get("fingerprint"))
    alpn = sanitize_alpn(raw.get("alpn"))
    reality_opts = sanitize_reality_opts(raw.get("reality-opts"))
    if security == "reality" and not reality_opts:
        return None
    if reality_opts:
        security = "reality"

    tls = as_bool(raw.get("tls"), node_type in TLS_DEFAULT_TYPES)
    if security in {"tls", "reality", "xtls"}:
        tls = True

    network = str(raw.get("network") or "tcp").strip().lower()
    if network not in SUPPORTED_NETWORKS:
        return None

    if node_type == "vmess":
        uuid = str(raw.get("uuid") or raw.get("id") or "").strip()
        if not UUID_RE.match(uuid):
            return None
        node["uuid"] = uuid
        alter_id = as_int(raw.get("alterId", raw.get("alter-id", 0)), 0)
        if alter_id is None or alter_id < 0 or alter_id > 65535:
            return None
        node["alterId"] = alter_id
        cipher = clean_text(raw.get("cipher") or "auto", 40).lower()
        node["cipher"] = cipher if cipher in {"auto", "aes-128-gcm", "chacha20-poly1305", "zero", "none"} else "auto"

    elif node_type == "vless":
        uuid = str(raw.get("uuid") or raw.get("id") or "").strip()
        if not UUID_RE.match(uuid):
            return None
        node["uuid"] = uuid
        # 兼容最新 VLESS Encryption：mlkem768x25519plus.*
        encryption = clean_text(raw.get("encryption") or "none", 1000)
        if not encryption or any(ch.isspace() for ch in encryption):
            encryption = "none"
        if encryption.lower() == "none":
            encryption = "none"
        elif not encryption.lower().startswith("mlkem768x25519plus."):
            return None
        node["encryption"] = encryption
        flow = clean_text(raw.get("flow"), 80).lower()
        if flow == "xtls-rprx-vision-udp443":
            flow = "xtls-rprx-vision"
        if flow and not re.match(r"^xtls-rprx-[a-z0-9-]+$", flow):
            return None
        if flow:
            node["flow"] = flow

    elif node_type == "trojan":
        password = clean_text(raw.get("password") or raw.get("auth"), 500)
        if not password:
            return None
        node["password"] = password
        tls = True

    elif node_type == "ss":
        cipher = clean_text(raw.get("cipher") or raw.get("method"), 60).lower()
        password = str(raw.get("password") or "")
        if cipher not in SUPPORTED_SS_CIPHERS or not password:
            return None
        node["cipher"] = cipher
        node["password"] = password[:1000]
        plugin = clean_text(raw.get("plugin"), 80).lower()
        if plugin:
            if plugin not in {"obfs", "v2ray-plugin", "shadow-tls", "restls"}:
                return None
            opts = sanitize_plugin_opts(raw.get("plugin-opts"))
            if not opts:
                return None
            node["plugin"] = plugin
            node["plugin-opts"] = opts
        return node

    elif node_type == "anytls":
        password = clean_text(raw.get("password") or raw.get("auth"), 500)
        if not password:
            return None
        node["password"] = password
        tls = True
        for key in ("idle-session-check-interval", "idle-session-timeout", "min-idle-session"):
            if raw.get(key) not in (None, ""):
                node[key] = sanitize_json_value(raw.get(key))

    elif node_type == "hysteria2":
        password = clean_text(raw.get("password") or raw.get("auth") or raw.get("auth-str"), 500)
        if not password:
            return None
        node["password"] = password
        tls = True
        obfs = clean_text(raw.get("obfs"), 80)
        if obfs:
            node["obfs"] = obfs
            obfs_password = clean_text(raw.get("obfs-password") or raw.get("obfs_password"), 500)
            if obfs_password:
                node["obfs-password"] = obfs_password
        for key in ("up", "down", "up-mbps", "down-mbps", "ports", "pinSHA256"):
            if raw.get(key) not in (None, ""):
                node[key] = sanitize_json_value(raw.get(key))

    elif node_type == "hysteria":
        auth = clean_text(raw.get("auth-str") or raw.get("auth") or raw.get("auth_str"), 500)
        if not auth:
            return None
        node["auth-str"] = auth
        tls = True
        for key in ("obfs", "protocol", "up", "down", "up-mbps", "down-mbps",
                    "recv-window-conn", "recv-window", "disable-mtu-discovery"):
            if raw.get(key) not in (None, ""):
                node[key] = sanitize_json_value(raw.get(key))
        if not node.get("up"):
            node["up"] = "100 Mbps"
        if not node.get("down"):
            node["down"] = "100 Mbps"

    elif node_type == "tuic":
        uuid = str(raw.get("uuid") or raw.get("id") or "").strip()
        password = str(raw.get("password") or "")
        if not UUID_RE.match(uuid) or not password:
            return None
        node["uuid"] = uuid
        node["password"] = password[:1000]
        tls = True
        congestion = clean_text(raw.get("congestion-controller") or raw.get("congestion_control"), 60)
        if congestion:
            node["congestion-controller"] = congestion
        relay_mode = clean_text(raw.get("udp-relay-mode") or raw.get("udp_relay_mode"), 60)
        if relay_mode:
            node["udp-relay-mode"] = relay_mode
        for key in ("reduce-rtt", "disable-sni", "heartbeat-interval", "udp-over-stream", "zero-rtt-handshake"):
            if raw.get(key) not in (None, ""):
                node[key] = sanitize_json_value(raw.get(key))

    elif node_type == "wireguard":
        private_key = clean_text(raw.get("private-key") or raw.get("private_key"), 500)
        public_key = clean_text(raw.get("public-key") or raw.get("public_key") or raw.get("peer-public-key"), 500)
        if not private_key or not public_key:
            return None
        node["private-key"] = private_key
        node["public-key"] = public_key
        pre_shared = clean_text(raw.get("pre-shared-key") or raw.get("pre_shared_key") or raw.get("preshared-key"), 500)
        if pre_shared:
            node["pre-shared-key"] = pre_shared
        ip_value = sanitize_string_list(raw.get("ip") or raw.get("local-address") or raw.get("address"), 8)
        if ip_value:
            node["ip"] = ip_value
        ipv6 = raw.get("ipv6")
        if isinstance(ipv6, str) and ipv6.strip():
            node["ipv6"] = ipv6.strip()
        elif isinstance(ipv6, list):
            node["ipv6"] = sanitize_string_list(ipv6, 8)
        reserved = sanitize_int_list(raw.get("reserved"))
        if reserved:
            node["reserved"] = reserved
        for key in ("mtu", "keepalive", "persistent-keepalive", "workers", "dns", "remote-dns-resolve",
                    "wnoise", "wnoisecount", "wnoisedelay", "wpayloadsize"):
            if raw.get(key) not in (None, ""):
                node[key] = sanitize_json_value(raw.get(key))

    elif node_type == "ssh":
        username = clean_text(raw.get("username") or raw.get("user"), 200)
        if not username:
            return None
        node["username"] = username
        password = clean_text(raw.get("password"), 1000)
        if password:
            node["password"] = password
        private_key = raw.get("private-key") or raw.get("private_key")
        if isinstance(private_key, str) and private_key.strip():
            node["private-key"] = private_key.strip()[:8000]
        passphrase = clean_text(raw.get("private-key-passphrase") or raw.get("private_key_passphrase"), 500)
        if passphrase:
            node["private-key-passphrase"] = passphrase
        host_key = sanitize_string_list(raw.get("host-key") or raw.get("host_key"), 20)
        if host_key:
            node["host-key"] = host_key
        host_key_algs = sanitize_string_list(raw.get("host-key-algorithms") or raw.get("host_key_algorithms"), 20)
        if host_key_algs:
            node["host-key-algorithms"] = host_key_algs
        if not password and "private-key" not in node:
            return None

    elif node_type in {"socks5", "http"}:
        username = clean_text(raw.get("username") or raw.get("user"), 200)
        password = clean_text(raw.get("password"), 500)
        if username:
            node["username"] = username
        if password:
            node["password"] = password
        if node_type == "http" and raw.get("headers"):
            headers = sanitize_headers(raw.get("headers"))
            if headers:
                node["headers"] = headers

    if tls:
        node["tls"] = True
    if servername:
        node["servername"] = servername
    if client_fingerprint:
        node["client-fingerprint"] = client_fingerprint
    if alpn:
        node["alpn"] = alpn
    if reality_opts:
        node["reality-opts"] = reality_opts
    if skip_cert:
        node["skip-cert-verify"] = True

    if node_type in {"vmess", "vless", "trojan"}:
        if not sanitize_transport(node, raw, network):
            return None

    packet_encoding = clean_text(raw.get("packet-encoding") or raw.get("packet_encoding"), 30).lower()
    if packet_encoding in {"packet", "xudp"}:
        node["packet-encoding"] = packet_encoding
    return node


def tls_expected(node: dict) -> bool:
    return str(node.get("type")) in TLS_DEFAULT_TYPES or as_bool(node.get("tls"), False)


def is_reality_node(node: dict) -> bool:
    return bool(node.get("reality-opts"))


def node_sni(node: dict) -> str:
    sni = clean_text(node.get("servername"), 253)
    if sni:
        return sni
    ws_opts = node.get("ws-opts")
    if isinstance(ws_opts, dict):
        headers = ws_opts.get("headers")
        if isinstance(headers, dict):
            for key, val in headers.items():
                if str(key).lower() == "host":
                    return clean_text(val, 253)
    h2_opts = node.get("h2-opts")
    if isinstance(h2_opts, dict):
        hosts = h2_opts.get("host")
        if isinstance(hosts, list) and hosts:
            return clean_text(hosts[0], 253)
    return ""


def ensure_unique_names(nodes: list[dict]) -> None:
    used: set[str] = set()
    for node in nodes:
        base = clean_text(node.get("name") or "Node", 78)
        name = base
        index = 2
        while name.casefold() in used:
            name = f"{base} #{index}"
            index += 1
        used.add(name.casefold())
        node["name"] = name


def detect_region(name: str) -> Optional[str]:
    """根据国旗、中文名、英文名、国家代码和常见城市识别地区。"""
    text = str(name or "")
    upper = text.upper()
    candidates: list[tuple[int, str]] = []

    # 国旗 emoji 最准确，优先按出现位置判断
    for match in re.finditer(r"[\U0001F1E6-\U0001F1FF]{2}", text):
        chars = match.group(0)
        code = "".join(chr(ord(ch) - 0x1F1E6 + ord("A")) for ch in chars)
        if code in REGION_BY_CODE:
            candidates.append((match.start(), code))

    for alias_upper, code, is_code in REGION_ALIAS_INDEX:
        if is_code:
            pattern = rf"(?<![A-Z]){re.escape(alias_upper)}(?![A-Z])"
            match = re.search(pattern, upper)
        else:
            found = upper.find(alias_upper)
            match = found if found >= 0 else None
        if match is not None:
            pos = match.start() if hasattr(match, "start") else int(match)
            candidates.append((pos, code))

    if not candidates:
        return None
    candidates.sort(key=lambda pair: (pair[0], -len(REGION_BY_CODE[pair[1]]["cn"])))
    return candidates[0][1]


def choose_region_node_name(node: dict) -> str:
    region = detect_region(node.get("name", ""))
    if region:
        return f"{flag_for(region)} {node.get('name', '')}"
    return str(node.get("name", "Node"))


@dataclass
class ProbeAttempt:
    ok: bool
    latency_ms: int = 0
    tls_ok: bool = True
    error: str = ""


@dataclass
class NodeRecord:
    node: dict
    region: Optional[str] = None
    quick_latency: int = 0
    latencies: list[int] = field(default_factory=list)
    failures: int = 0
    tls_ok: bool = True
    score: float = 999999.0
    verified: bool = False
    static_only: bool = False


@dataclass
class RunConfig:
    latency_limit_ms: int = 360
    quality_mode: str = "strict"
    jitter_limit_ms: int = 120
    max_workers: int = 80
    max_nodes: int = 100
    selected_regions: set[str] = field(default_factory=set)
    keep_unknown_region: bool = False
    output_dir: Path = field(default_factory=app_dir)

def uri_host(server: str) -> str:
    if ":" in server and not server.startswith("["):
        return f"[{server}]"
    return server


def query_string(pairs: Iterable[tuple[str, Any]]) -> str:
    clean_pairs = [(str(k), str(v)) for k, v in pairs if v not in (None, "")]
    return urllib.parse.urlencode(clean_pairs, quote_via=urllib.parse.quote, safe="")


def display_node_name(node: dict) -> str:
    name = clean_text(node.get("name") or "Node", 90)
    region = detect_region(name)
    if region:
        flag = flag_for(region)
        if flag and flag not in name:
            name = f"{flag} {name}"
    return name


def transport_values(node: dict) -> dict[str, str]:
    """提取 WS/gRPC/H2/XHTTP 等传输层共用的 host/path/service 参数。"""
    network = str(node.get("network") or "tcp").lower()
    result = {"network": network, "host": "", "path": "", "service": "", "mode": ""}
    opts = node.get("ws-opts") if isinstance(node.get("ws-opts"), dict) else {}
    headers = opts.get("headers") if isinstance(opts.get("headers"), dict) else {}
    for key, value in headers.items():
        if str(key).lower() == "host":
            result["host"] = clean_text(value, 253)
            break
    if opts.get("path"):
        result["path"] = clean_text(opts.get("path"), 500)
    if opts.get("max-early-data"):
        result["ed"] = str(as_int(opts.get("max-early-data"), 0) or 0)
    if opts.get("early-data-header-name"):
        result["eh"] = clean_text(opts.get("early-data-header-name"), 100)
    grpc = node.get("grpc-opts") if isinstance(node.get("grpc-opts"), dict) else {}
    if grpc.get("grpc-service-name"):
        result["service"] = clean_text(grpc.get("grpc-service-name"), 200)
    h2 = node.get("h2-opts") if isinstance(node.get("h2-opts"), dict) else {}
    if isinstance(h2.get("host"), list) and h2.get("host"):
        result["host"] = clean_text(h2["host"][0], 253)
    if h2.get("path"):
        result["path"] = clean_text(h2.get("path"), 500)
    http = node.get("http-opts") if isinstance(node.get("http-opts"), dict) else {}
    if isinstance(http.get("path"), list) and http.get("path"):
        result["path"] = clean_text(http["path"][0], 500)
    elif http.get("path"):
        result["path"] = clean_text(http.get("path"), 500)
    http_headers = http.get("headers") if isinstance(http.get("headers"), dict) else {}
    for key, value in http_headers.items():
        if str(key).lower() == "host":
            result["host"] = clean_text(value, 253)
            break
    xhttp = node.get("xhttp-opts") if isinstance(node.get("xhttp-opts"), dict) else {}
    for key in ("host", "path", "mode"):
        if xhttp.get(key) not in (None, ""):
            result[key] = clean_text(xhttp.get(key), 500)
    return result


def build_uri(node: dict) -> Optional[str]:
    """转换成 Hiddify 可识别的标准分享链接；WireGuard 使用 JSON/YAML 输出。"""
    node_type = str(node.get("type") or "").lower()
    server = str(node.get("server") or "")
    port = normalize_port(node.get("port"))
    name = display_node_name(node)
    if not node_type or not server or not port or not name:
        return None
    fragment = urllib.parse.quote(name, safe="")
    host = uri_host(server)
    network = str(node.get("network") or "tcp")
    tls = tls_expected(node)
    reality = is_reality_node(node)
    sni = node_sni(node)
    fingerprint = clean_text(node.get("client-fingerprint"), 50)
    alpn = ",".join(sanitize_alpn(node.get("alpn")))
    skip_cert = as_bool(node.get("skip-cert-verify"), False)
    tv = transport_values(node)
    query = query_string

    if node_type == "vmess":
        v2ray = {
            "v": "2", "ps": name, "add": server, "port": str(port),
            "id": str(node.get("uuid") or ""), "aid": str(node.get("alterId", 0)),
            "scy": str(node.get("cipher") or "auto"), "net": network,
            "type": "http" if network == "http" else "none",
            "host": tv.get("host", ""), "path": tv.get("path", ""),
            "tls": "tls" if tls and not reality else "",
            "sni": sni, "alpn": alpn, "fp": fingerprint,
        }
        if reality:
            ro = node.get("reality-opts") or {}
            v2ray["tls"] = "reality"
            v2ray["pbk"] = ro.get("public-key", "")
            v2ray["sid"] = ro.get("short-id", "")
        if network == "grpc":
            v2ray["path"] = tv.get("service", "")
        elif network == "xhttp":
            v2ray["path"] = tv.get("path", "")
            v2ray["host"] = tv.get("host", "")
            if tv.get("mode"):
                v2ray["mode"] = tv.get("mode")
        if skip_cert:
            v2ray["allowInsecure"] = 1
        payload = json.dumps(v2ray, ensure_ascii=False, separators=(",", ":"))
        return "vmess://" + base64.b64encode(payload.encode("utf-8")).decode("ascii")

    if node_type == "vless":
        security = "reality" if reality else ("tls" if tls else "none")
        params: list[tuple[str, Any]] = [
            ("encryption", node.get("encryption") or "none"),
            ("security", security), ("type", network),
        ]
        if sni:
            params.append(("sni", sni))
        if fingerprint:
            params.append(("fp", fingerprint))
        if alpn:
            params.append(("alpn", alpn))
        if node.get("flow"):
            params.append(("flow", node.get("flow")))
        if network in {"ws", "httpupgrade", "xhttp"}:
            if tv.get("host"):
                params.append(("host", tv.get("host")))
            if tv.get("path"):
                params.append(("path", tv.get("path")))
            if tv.get("ed"):
                params.append(("ed", tv.get("ed")))
            if tv.get("eh"):
                params.append(("eh", tv.get("eh")))
            if tv.get("mode"):
                params.append(("mode", tv.get("mode")))
        elif network == "grpc":
            if tv.get("service"):
                params.append(("serviceName", tv.get("service")))
        elif network == "h2":
            if tv.get("host"):
                params.append(("host", tv.get("host")))
            if tv.get("path"):
                params.append(("path", tv.get("path")))
        if reality:
            ro = node.get("reality-opts") or {}
            params.append(("pbk", ro.get("public-key", "")))
            if ro.get("short-id"):
                params.append(("sid", ro.get("short-id")))
            if ro.get("spider-x"):
                params.append(("spx", ro.get("spider-x")))
            if not fingerprint:
                params.append(("fp", "chrome"))
        if skip_cert:
            params.append(("allowInsecure", "1"))
        return f"vless://{node.get('uuid')}@{host}:{port}?{query(params)}#{fragment}"

    if node_type == "trojan":
        params = [("security", "tls"), ("type", network)]
        if sni:
            params.append(("sni", sni))
        if fingerprint:
            params.append(("fp", fingerprint))
        if alpn:
            params.append(("alpn", alpn))
        if network in {"ws", "httpupgrade", "xhttp"}:
            if tv.get("host"):
                params.append(("host", tv.get("host")))
            if tv.get("path"):
                params.append(("path", tv.get("path")))
            if tv.get("mode"):
                params.append(("mode", tv.get("mode")))
        elif network == "grpc":
            if tv.get("service"):
                params.append(("serviceName", tv.get("service")))
        elif network == "h2":
            if tv.get("host"):
                params.append(("host", tv.get("host")))
            if tv.get("path"):
                params.append(("path", tv.get("path")))
        if skip_cert:
            params.append(("allowInsecure", "1"))
        password = urllib.parse.quote(str(node.get("password") or ""), safe="")
        return f"trojan://{password}@{host}:{port}?{query(params)}#{fragment}"

    if node_type == "ss":
        userinfo = base64.urlsafe_b64encode(
            f"{node.get('cipher')}:{node.get('password')}".encode("utf-8")
        ).decode("ascii").rstrip("=")
        link = f"ss://{userinfo}@{host}:{port}"
        plugin = str(node.get("plugin") or "")
        if plugin:
            opts = node.get("plugin-opts") if isinstance(node.get("plugin-opts"), dict) else {}
            if plugin == "obfs":
                value = f"obfs-local;obfs={clean_text(opts.get('mode'), 30) or 'http'}"
                if opts.get("host"):
                    value += f";obfs-host={clean_text(opts.get('host'), 253)}"
            elif plugin == "v2ray-plugin":
                value = f"v2ray-plugin;mode={clean_text(opts.get('mode'), 30) or 'websocket'}"
                if opts.get("host"):
                    value += f";host={clean_text(opts.get('host'), 253)}"
                if opts.get("path"):
                    value += f";path={clean_text(opts.get('path'), 500)}"
                if as_bool(opts.get("tls"), False):
                    value += ";tls"
            else:
                value = plugin
                for key, val in opts.items():
                    if isinstance(val, bool):
                        if val:
                            value += f";{key}"
                    elif val not in (None, ""):
                        value += f";{key}={clean_text(val, 300)}"
            link += "?" + urllib.parse.urlencode({"plugin": value}, quote_via=urllib.parse.quote, safe="")
        return link + "#" + fragment

    if node_type == "anytls":
        params = [("security", "tls")]
        if sni:
            params.append(("sni", sni))
        if fingerprint:
            params.append(("fp", fingerprint))
        if alpn:
            params.append(("alpn", alpn))
        if skip_cert:
            params.append(("insecure", "1"))
        password = urllib.parse.quote(str(node.get("password") or ""), safe="")
        return f"anytls://{password}@{host}:{port}?{query(params)}#{fragment}"

    if node_type == "hysteria2":
        params = []
        if sni:
            params.append(("sni", sni))
        if skip_cert:
            params.append(("insecure", "1"))
        if alpn:
            params.append(("alpn", alpn))
        if node.get("obfs"):
            params.append(("obfs", node.get("obfs")))
        if node.get("obfs-password"):
            params.append(("obfs-password", node.get("obfs-password")))
        for key in ("up", "down"):
            value = _mbps(node.get(key))
            if value is not None:
                params.append((key, str(value)))
        if node.get("pinSHA256"):
            params.append(("pinSHA256", node.get("pinSHA256")))
        if node.get("ports"):
            params.append(("ports", node.get("ports")))
        password = urllib.parse.quote(str(node.get("password") or ""), safe="")
        return f"hysteria2://{password}@{host}:{port}/?{query(params)}#{fragment}"

    if node_type == "hysteria":
        params = []
        if node.get("protocol"):
            params.append(("protocol", node.get("protocol")))
        if node.get("auth-str"):
            params.append(("auth", node.get("auth-str")))
        if sni:
            params.append(("peer", sni))
        if skip_cert:
            params.append(("insecure", "1"))
        if alpn:
            params.append(("alpn", alpn))
        for source, target in (("up", "upmbps"), ("down", "downmbps")):
            value = _mbps(node.get(source))
            if value is not None:
                params.append((target, str(value)))
        if node.get("obfs"):
            params.append(("obfs", node.get("obfs")))
        return f"hysteria://{host}:{port}?{query(params)}#{fragment}"

    if node_type == "tuic":
        params = []
        if node.get("congestion-controller"):
            params.append(("congestion_control", node.get("congestion-controller")))
        if node.get("udp-relay-mode"):
            params.append(("udp_relay_mode", node.get("udp-relay-mode")))
        if sni:
            params.append(("sni", sni))
        if alpn:
            params.append(("alpn", alpn))
        if skip_cert:
            params.append(("allow_insecure", "1"))
        if as_bool(node.get("disable-sni"), False):
            params.append(("disable_sni", "1"))
        if as_bool(node.get("reduce-rtt"), False):
            params.append(("reduce_rtt", "1"))
        if node.get("heartbeat-interval"):
            params.append(("heartbeat", node.get("heartbeat-interval")))
        userinfo = urllib.parse.quote(str(node.get("uuid") or ""), safe="") + ":" + \
                   urllib.parse.quote(str(node.get("password") or ""), safe="")
        return f"tuic://{userinfo}@{host}:{port}?{query(params)}#{fragment}"

    if node_type == "ssh":
        if not node.get("password"):
            return None
        username = urllib.parse.quote(str(node.get("username") or ""), safe="")
        password = urllib.parse.quote(str(node.get("password") or ""), safe="")
        return f"ssh://{username}:{password}@{host}:{port}#{fragment}"

    if node_type in {"http", "socks5"}:
        scheme = "https" if node_type == "http" and tls else node_type
        username = urllib.parse.quote(str(node.get("username") or ""), safe="")
        password = urllib.parse.quote(str(node.get("password") or ""), safe="")
        userinfo = ""
        if username or password:
            userinfo = username + (":" + password if password else "") + "@"
        return f"{scheme}://{userinfo}{host}:{port}#{fragment}"

    # WireGuard 的分享链接在不同客户端之间不统一，因此只写入 YAML/JSON。
    return None


def _plugin_opts_string(opts: Any) -> str:
    if not isinstance(opts, dict):
        return ""
    parts = []
    for key, value in opts.items():
        if isinstance(value, bool):
            if value:
                parts.append(str(key))
        elif value not in (None, ""):
            parts.append(f"{key}={value}")
    return ";".join(parts)


def to_clash_node(node: dict) -> dict:
    """输出 Clash Meta / Mihomo 节点，保留 Hiddify 常用扩展字段。"""
    node_type = str(node.get("type") or "")
    out: dict[str, Any] = {}
    for key in ("name", "type", "server", "port", "udp", "tfo"):
        if node.get(key) not in (None, ""):
            out[key] = node[key]
    for key in ("uuid", "alterId", "cipher", "password", "username", "auth-str"):
        if node.get(key) not in (None, ""):
            out[key] = node[key]

    if node_type in {"vless", "vmess", "trojan"}:
        for key in ("network", "ws-opts", "grpc-opts", "h2-opts", "http-opts",
                    "xhttp-opts", "kcp-opts", "quic-opts", "reality-opts",
                    "tls", "servername", "skip-cert-verify", "client-fingerprint",
                    "alpn", "flow", "encryption", "packet-encoding"):
            if node.get(key) not in (None, ""):
                out[key] = node[key]
        if isinstance(out.get("http-opts"), dict):
            http_opts = dict(out["http-opts"])
            headers = http_opts.get("headers")
            if isinstance(headers, dict):
                http_opts["headers"] = {
                    str(key): [str(value)] if not isinstance(value, list) else value
                    for key, value in headers.items()
                }
            out["http-opts"] = http_opts
    elif node_type == "ss":
        for key in ("plugin", "plugin-opts"):
            if node.get(key) not in (None, ""):
                out[key] = node[key]
    elif node_type in {"hysteria2", "tuic", "anytls"}:
        for key in ("obfs", "obfs-password", "up", "down", "pinSHA256", "ports",
                    "congestion-controller", "udp-relay-mode", "reduce-rtt",
                    "disable-sni", "heartbeat-interval", "idle-session-check-interval",
                    "idle-session-timeout", "min-idle-session", "client-fingerprint"):
            if node.get(key) not in (None, ""):
                out[key] = node[key]
        if node.get("servername"):
            out["sni"] = node["servername"]
        if node.get("skip-cert-verify"):
            out["skip-cert-verify"] = True
        if node.get("alpn"):
            out["alpn"] = node["alpn"]
    elif node_type == "hysteria":
        for key in ("auth-str", "obfs", "protocol", "up", "down", "up-mbps", "down-mbps",
                    "recv-window-conn", "recv-window", "disable-mtu-discovery"):
            if node.get(key) not in (None, ""):
                out[key] = node[key]
        if node.get("servername"):
            out["sni"] = node["servername"]
        if node.get("skip-cert-verify"):
            out["skip-cert-verify"] = True
        if node.get("alpn"):
            out["alpn"] = node["alpn"]
    elif node_type == "wireguard":
        ip = node.get("ip")
        if isinstance(ip, list):
            ip = ",".join(str(item) for item in ip)
        if ip:
            out["ip"] = ip
        for key in ("ipv6", "private-key", "public-key", "pre-shared-key", "reserved",
                    "mtu", "keepalive", "persistent-keepalive", "dns", "remote-dns-resolve",
                    "wnoise", "wnoisecount", "wnoisedelay", "wpayloadsize"):
            if node.get(key) not in (None, ""):
                out[key] = node[key]
    elif node_type == "ssh":
        for key in ("private-key", "private-key-passphrase", "host-key", "host-key-algorithms"):
            if node.get(key) not in (None, ""):
                out[key] = node[key]
    elif node_type == "http":
        for key in ("headers", "tls", "servername", "skip-cert-verify"):
            if node.get(key) not in (None, ""):
                out[key] = node[key]
    return out


def _mbps(value: Any) -> Optional[int]:
    if value in (None, ""):
        return None
    if isinstance(value, (int, float)):
        return max(0, int(value))
    match = re.search(r"\d+", str(value))
    return int(match.group(0)) if match else None


def singbox_tls(node: dict) -> Optional[dict]:
    if not tls_expected(node):
        return None
    result: dict[str, Any] = {"enabled": True}
    sni = node_sni(node)
    if sni:
        result["server_name"] = sni
    if as_bool(node.get("skip-cert-verify"), False):
        result["insecure"] = True
    alpn = sanitize_alpn(node.get("alpn"))
    if alpn:
        result["alpn"] = alpn
    fingerprint = clean_text(node.get("client-fingerprint"), 50)
    if fingerprint:
        result["utls"] = {"enabled": True, "fingerprint": fingerprint}
    reality = node.get("reality-opts")
    if isinstance(reality, dict):
        result["reality"] = {
            "enabled": True,
            "public_key": reality.get("public-key", ""),
        }
        if reality.get("short-id"):
            result["reality"]["short_id"] = reality.get("short-id")
        if not fingerprint:
            result["utls"] = {"enabled": True, "fingerprint": "chrome"}
    return result


def singbox_transport(node: dict) -> Optional[dict]:
    network = str(node.get("network") or "tcp").lower()
    tv = transport_values(node)
    if network == "ws":
        result: dict[str, Any] = {"type": "ws"}
        if tv.get("path"):
            result["path"] = tv["path"]
        if tv.get("host"):
            result["headers"] = {"Host": tv["host"]}
        if tv.get("ed"):
            result["max_early_data"] = as_int(tv["ed"], 0)
        if tv.get("eh"):
            result["early_data_header_name"] = tv["eh"]
        return result
    if network == "httpupgrade":
        result = {"type": "httpupgrade"}
        if tv.get("host"):
            result["host"] = tv["host"]
        if tv.get("path"):
            result["path"] = tv["path"]
        return result
    if network == "grpc":
        return {"type": "grpc", "service_name": tv.get("service", "")}
    if network == "h2":
        return {"type": "http", "host": [tv.get("host", "")], "path": tv.get("path", "")}
    if network == "http":
        return {"type": "http", "host": [tv.get("host", "")], "path": tv.get("path", "")}
    if network == "xhttp":
        opts = node.get("xhttp-opts") if isinstance(node.get("xhttp-opts"), dict) else {}
        return {"type": "xhttp", **opts}
    if network == "quic":
        return {"type": "quic"}
    if network == "kcp":
        opts = node.get("kcp-opts") if isinstance(node.get("kcp-opts"), dict) else {}
        return {"type": "kcp", **opts}
    return None


def to_singbox_outbound(node: dict, tag: str) -> dict:
    node_type = str(node.get("type") or "")
    out: dict[str, Any] = {"type": node_type, "tag": tag}
    if node_type == "ss":
        out["type"] = "shadowsocks"
    elif node_type == "socks5":
        out["type"] = "socks"
    out["server"] = node.get("server")
    out["server_port"] = node.get("port")

    if node_type == "vless":
        out["uuid"] = node.get("uuid")
        if node.get("flow"):
            out["flow"] = node.get("flow")
        if node.get("encryption") not in (None, "", "none"):
            out["encryption"] = node.get("encryption")
        if node.get("packet-encoding"):
            out["packet_encoding"] = node.get("packet-encoding")
    elif node_type == "vmess":
        out["uuid"] = node.get("uuid")
        out["security"] = node.get("cipher") or "auto"
        out["alter_id"] = node.get("alterId", 0)
        if node.get("packet-encoding"):
            out["packet_encoding"] = node.get("packet-encoding")
    elif node_type == "trojan":
        out["password"] = node.get("password")
    elif node_type == "ss":
        out["method"] = node.get("cipher")
        out["password"] = node.get("password")
        if node.get("plugin"):
            out["plugin"] = node.get("plugin")
            out["plugin_opts"] = _plugin_opts_string(node.get("plugin-opts"))
    elif node_type == "hysteria2":
        out["password"] = node.get("password")
        up = _mbps(node.get("up") or node.get("up-mbps"))
        down = _mbps(node.get("down") or node.get("down-mbps"))
        if up:
            out["up_mbps"] = up
        if down:
            out["down_mbps"] = down
        if node.get("obfs"):
            out["obfs"] = {"type": node.get("obfs")}
            if node.get("obfs-password"):
                out["obfs"]["password"] = node.get("obfs-password")
    elif node_type == "hysteria":
        out["auth_str"] = node.get("auth-str")
        up = _mbps(node.get("up") or node.get("up-mbps"))
        down = _mbps(node.get("down") or node.get("down-mbps"))
        if up:
            out["up_mbps"] = up
        if down:
            out["down_mbps"] = down
        if node.get("obfs"):
            out["obfs"] = node.get("obfs")
    elif node_type == "tuic":
        out["uuid"] = node.get("uuid")
        out["password"] = node.get("password")
        if node.get("congestion-controller"):
            out["congestion_control"] = node.get("congestion-controller")
        if node.get("udp-relay-mode"):
            out["udp_relay_mode"] = node.get("udp-relay-mode")
        if node.get("reduce-rtt") is not None:
            out["reduce_rtt"] = as_bool(node.get("reduce-rtt"), False)
        if node.get("disable-sni") is not None:
            out["disable_sni"] = as_bool(node.get("disable-sni"), False)
        if node.get("heartbeat-interval"):
            out["heartbeat"] = node.get("heartbeat-interval")
    elif node_type == "wireguard":
        out["private_key"] = node.get("private-key")
        out["peer_public_key"] = node.get("public-key")
        if node.get("pre-shared-key"):
            out["pre_shared_key"] = node.get("pre-shared-key")
        addresses = []
        if isinstance(node.get("ip"), list):
            addresses.extend(str(item) for item in node.get("ip"))
        elif node.get("ip"):
            addresses.append(str(node.get("ip")))
        if isinstance(node.get("ipv6"), list):
            addresses.extend(str(item) for item in node.get("ipv6"))
        elif node.get("ipv6"):
            addresses.append(str(node.get("ipv6")))
        if addresses:
            out["local_address"] = addresses
        if node.get("reserved"):
            out["reserved"] = node.get("reserved")
        if node.get("mtu"):
            out["mtu"] = as_int(node.get("mtu"), 1408)
        for key, target in (("keepalive", "persistent_keepalive_interval"),
                            ("persistent-keepalive", "persistent_keepalive_interval"),
                            ("wnoise", "fake_packets"), ("wnoisecount", "fake_packets_count"),
                            ("wnoisedelay", "fake_packets_delay"), ("wpayloadsize", "fake_packets_size")):
            if node.get(key) not in (None, ""):
                out[target] = sanitize_json_value(node.get(key))
    elif node_type == "ssh":
        out["user"] = node.get("username")
        if node.get("password"):
            out["password"] = node.get("password")
        if node.get("private-key"):
            out["private_key"] = node.get("private-key")
        if node.get("private-key-passphrase"):
            out["private_key_passphrase"] = node.get("private-key-passphrase")
        if node.get("host-key"):
            out["host_key"] = node.get("host-key")
    elif node_type == "anytls":
        out["password"] = node.get("password")
        for key, target in (("idle-session-check-interval", "idle_session_check_interval"),
                            ("idle-session-timeout", "idle_session_timeout"),
                            ("min-idle-session", "min_idle_session")):
            if node.get(key) not in (None, ""):
                out[target] = node.get(key)
    elif node_type == "socks5":
        out["version"] = "5"
        if node.get("username"):
            out["username"] = node.get("username")
        if node.get("password"):
            out["password"] = node.get("password")
    elif node_type == "http":
        if node.get("username"):
            out["username"] = node.get("username")
        if node.get("password"):
            out["password"] = node.get("password")
        if node.get("headers"):
            out["headers"] = node.get("headers")

    tls = singbox_tls(node)
    if tls:
        out["tls"] = tls
    transport = singbox_transport(node)
    if transport:
        out["transport"] = transport
    return out


def save_outputs(records: list[NodeRecord], config: RunConfig, log: Callable[[str], None]) -> dict:
    """生成 Hiddify 兼容的 TXT、Clash Meta YAML 和 sing-box JSON。"""
    prepared: list[dict] = []
    for record in records:
        node = dict(record.node)
        node["name"] = display_node_name(node)
        prepared.append(node)
    if not prepared:
        raise RuntimeError("没有可导出的合规节点。")
    ensure_unique_names(prepared)

    links: list[str] = []
    no_link = 0
    for node in prepared:
        link = build_uri(node)
        if link:
            links.append(link)
        else:
            no_link += 1
    if no_link:
        log(f"{no_link} 个节点没有统一的分享链接格式，已保留在 YAML/JSON 中，不写入 TXT。")

    output_dir = Path(config.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    txt_path = output_dir / OUTPUT_TXT
    plain_path = output_dir / OUTPUT_PLAIN
    yaml_path = output_dir / OUTPUT_YAML
    singbox_path = output_dir / OUTPUT_SINGBOX

    base64_content = base64.b64encode("\n".join(links).encode("utf-8")).decode("ascii")
    txt_tmp = txt_path.with_suffix(".txt.tmp")
    txt_tmp.write_text(base64_content, encoding="utf-8", newline="\n")
    os.replace(txt_tmp, txt_path)
    plain_tmp = plain_path.with_suffix(".txt.tmp")
    plain_tmp.write_text("\n".join(links) + ("\n" if links else ""), encoding="utf-8", newline="\n")
    os.replace(plain_tmp, plain_path)

    group_name = "🚀 自动选择"
    clash_nodes = [to_clash_node(node) for node in prepared]
    yaml_data = {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "warning",
        "proxies": clash_nodes,
        "proxy-groups": [
            {
                "name": group_name, "type": "url-test",
                "url": "https://www.gstatic.com/generate_204",
                "interval": 300, "tolerance": 50,
                "proxies": [node["name"] for node in prepared],
            }
        ],
        "rules": [f"MATCH,{group_name}"],
    }
    yaml = YAML(typ="safe", pure=True)
    yaml.default_flow_style = False
    yaml.width = 4096
    yaml.indent(mapping=2, sequence=4, offset=2)
    yaml_tmp = yaml_path.with_suffix(".yaml.tmp")
    with yaml_tmp.open("w", encoding="utf-8", newline="\n") as handle:
        yaml.dump(yaml_data, handle)
    os.replace(yaml_tmp, yaml_path)

    node_names = [node["name"] for node in prepared]
    outbounds = [to_singbox_outbound(node, node["name"]) for node in prepared]
    outbounds.extend([
        {
            "type": "urltest", "tag": "⚡ 自动测速",
            "outbounds": node_names,
            "url": "https://www.gstatic.com/generate_204",
            "interval": "5m", "tolerance": 50,
        },
        {
            "type": "selector", "tag": group_name,
            "outbounds": ["⚡ 自动测速"] + node_names,
            "default": "⚡ 自动测速",
        },
        {"type": "direct", "tag": "direct"},
        {"type": "block", "tag": "block"},
    ])
    singbox_data = {
        "log": {"level": "warn", "timestamp": True},
        "outbounds": outbounds,
        "route": {
            "rules": [{"action": "sniff"}],
            "final": group_name,
            "auto_detect_interface": True,
        },
    }
    json_tmp = singbox_path.with_suffix(".json.tmp")
    json_tmp.write_text(json.dumps(singbox_data, ensure_ascii=False, indent=2), encoding="utf-8", newline="\n")
    os.replace(json_tmp, singbox_path)

    return {
        "txt": txt_path, "plain": plain_path, "yaml": yaml_path,
        "singbox": singbox_path, "count": len(prepared), "link_count": len(links),
    }


def resolve_addresses(server: str, port: int) -> list[tuple[int, int, int, tuple]]:
    try:
        ip = ipaddress.ip_address(server)
        family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
        return [(family, socket.SOCK_STREAM, socket.IPPROTO_TCP, (str(ip), port))]
    except ValueError:
        pass

    # DNSPython has a hard timeout. The system getaddrinfo has no timeout and can
    # stall the whole scan on a few dead domain names, so it is deliberately not
    # used here.
    query_name = server.rstrip(".").encode("idna").decode("ascii")
    resolver = _dns_resolver()
    result: list[tuple[int, int, int, tuple]] = []
    seen: set[tuple] = set()
    for record_type, family in (("A", socket.AF_INET), ("AAAA", socket.AF_INET6)):
        try:
            answers = resolver.resolve(query_name, record_type, lifetime=1.8)
        except (dns.exception.DNSException, OSError):
            continue
        for answer in answers:
            try:
                ip = ipaddress.ip_address(str(answer))
            except ValueError:
                continue
            key = (family, str(ip))
            if key in seen:
                continue
            seen.add(key)
            result.append((family, socket.SOCK_STREAM, socket.IPPROTO_TCP, (str(ip), port)))
        if result:
            break
    return result


def _tls_handshake(sock: socket.socket, node: dict, timeout: float) -> bool:
    sni = node_sni(node)
    server = str(node.get("server") or "")
    if not sni:
        try:
            ipaddress.ip_address(server)
            hostname = server
        except ValueError:
            hostname = server
    else:
        hostname = sni

    context = ssl.create_default_context()
    if as_bool(node.get("skip-cert-verify"), False):
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    context.set_alpn_protocols(["h2", "http/1.1"])
    sock.settimeout(timeout)
    with context.wrap_socket(sock, server_hostname=hostname):
        return True


def probe_once(node: dict, latency_limit_ms: int, timeout_s: float) -> ProbeAttempt:
    """一次 TCP 连接探测；TLS 节点额外做握手校验，REALITY 节点只测 TCP。"""
    server = str(node.get("server") or "")
    port = normalize_port(node.get("port"))
    if not server or not port:
        return ProbeAttempt(False, error="地址或端口无效")
    try:
        addresses = resolve_addresses(server, port)
    except Exception as exc:
        return ProbeAttempt(False, error=f"DNS失败:{clean_text(exc, 60)}")
    if not addresses:
        return ProbeAttempt(False, error="DNS无结果")

    last_error = "连接失败"
    # 域名可能解析出多个 IP，最多尝试 2 个地址，避免单 IP 故障误杀。
    for family, socktype, proto, sockaddr in addresses[:2]:
        sock = None
        try:
            sock = socket.socket(family, socktype, proto)
            sock.settimeout(timeout_s)
            start = time.perf_counter()
            sock.connect(sockaddr)
            latency_ms = max(1, int((time.perf_counter() - start) * 1000))
            if latency_ms > latency_limit_ms:
                last_error = f"延迟{latency_ms}ms超过上限"
                sock.close()
                sock = None
                continue
            if tls_expected(node) and not is_reality_node(node):
                try:
                    _tls_handshake(sock, node, timeout_s)
                    sock = None
                except Exception as exc:
                    last_error = f"TLS失败:{clean_text(exc, 80)}"
                    try:
                        sock.close()
                    except Exception:
                        pass
                    sock = None
                    continue
            try:
                if sock is not None:
                    sock.close()
            except Exception:
                pass
            return ProbeAttempt(True, latency_ms=latency_ms, tls_ok=True)
        except Exception as exc:
            last_error = clean_text(exc, 80) or last_error
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass
    return ProbeAttempt(False, tls_ok=False, error=last_error)


def _probe_executor(
    records: list[NodeRecord],
    config: RunConfig,
    emit: Callable[[dict], None],
    cancel_event: threading.Event,
    progress_start: float,
    progress_end: float,
    title: str,
    worker_factory: Callable[[NodeRecord, threading.Event], Callable[[], Any]],
    on_result: Callable[[NodeRecord, Any], None],
) -> None:
    total = len(records)
    if total == 0:
        return
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, config.max_workers))
    future_map: dict[concurrent.futures.Future, NodeRecord] = {}
    last_emit = 0.0
    try:
        for record in records:
            if cancel_event.is_set():
                break
            future_map[executor.submit(worker_factory, record, cancel_event)] = record
        completed = 0
        for future in concurrent.futures.as_completed(future_map):
            record = future_map[future]
            if cancel_event.is_set():
                for f in future_map:
                    f.cancel()
                break
            try:
                result = future.result()
            except Exception as exc:
                result = ProbeAttempt(False, error=f"探测异常:{clean_text(exc, 80)}")
            on_result(record, result)
            completed += 1
            now = time.monotonic()
            if completed == total or now - last_emit >= 0.12:
                last_emit = now
                pct = progress_start + (progress_end - progress_start) * (completed / total)
                emit({
                    "type": "progress",
                    "value": pct,
                    "status": f"{title}  {completed}/{total}",
                })
    finally:
        executor.shutdown(wait=False, cancel_futures=True)


def run_quick_probe(
    records: list[NodeRecord], config: RunConfig, emit: Callable[[dict], None],
    cancel_event: threading.Event, progress_start: float, progress_end: float,
) -> list[NodeRecord]:
    timeout_s = max(1.1, min(4.0, config.latency_limit_ms / 1000.0 + 0.8))
    tcp_records = [r for r in records if str(r.node.get("type")) not in UDP_PROTOCOLS]
    udp_records = [r for r in records if str(r.node.get("type")) in UDP_PROTOCOLS]

    def worker(record: NodeRecord, _cancel: threading.Event) -> ProbeAttempt:
        return probe_once(record.node, config.latency_limit_ms, timeout_s)

    def on_result(record: NodeRecord, result: ProbeAttempt) -> None:
        if result.ok and result.latency_ms <= config.latency_limit_ms:
            record.quick_latency = result.latency_ms
            record.latencies = [result.latency_ms]
            record.tls_ok = result.tls_ok
        else:
            record.failures += 1

    _probe_executor(
        tcp_records, config, emit, cancel_event, progress_start,
        progress_end if not udp_records else progress_end - 2.0,
        "TCP 快速测速", worker, on_result,
    )

    # Hysteria2/TUIC/WireGuard 是 UDP/QUIC 协议，普通 TCP 探测会误杀。
    # 这里做 DNS/地址静态校验后保留，并在输出中标记为静态节点。
    alive_udp: list[NodeRecord] = []
    if udp_records and not cancel_event.is_set():
        for index, record in enumerate(udp_records, start=1):
            if cancel_event.is_set():
                break
            server = str(record.node.get("server") or "")
            port = normalize_port(record.node.get("port"))
            try:
                addresses = resolve_addresses(server, port) if server and port else []
            except Exception:
                addresses = []
            if addresses:
                record.quick_latency = 1
                record.latencies = [1]
                record.static_only = True
                record.verified = True
                record.score = 5000.0 + index
                alive_udp.append(record)
            if index % 20 == 0 or index == len(udp_records):
                pct = progress_end - 2.0 + 2.0 * index / max(1, len(udp_records))
                emit({"type": "progress", "value": pct, "status": f"UDP 协议静态校验 {index}/{len(udp_records)}"})
        emit({
            "type": "log",
            "text": f"UDP 协议静态校验通过 {len(alive_udp)} 个（Hysteria2/TUIC/WireGuard 不做 TCP 握手测速）",
        })

    alive_tcp = [r for r in tcp_records if r.quick_latency > 0]
    return alive_tcp + alive_udp


def run_quality_probe(
    records: list[NodeRecord], config: RunConfig, emit: Callable[[dict], None],
    cancel_event: threading.Event, progress_start: float, progress_end: float,
) -> list[NodeRecord]:
    preset = QUALITY_PRESETS[config.quality_mode]
    total_attempts = preset["attempts"]
    required = preset["required"]
    remaining_attempts = max(0, total_attempts - 1)
    timeout_s = max(1.1, min(4.0, config.latency_limit_ms / 1000.0 + 0.8))
    if remaining_attempts <= 0:
        return records

    def worker(record: NodeRecord, cancel: threading.Event) -> list[ProbeAttempt]:
        results: list[ProbeAttempt] = []
        for index in range(remaining_attempts):
            if cancel.is_set():
                break
            if index > 0:
                time.sleep(0.18)
            results.append(probe_once(record.node, config.latency_limit_ms, timeout_s))
        return results

    def on_result(record: NodeRecord, results: Any) -> None:
        if isinstance(results, ProbeAttempt):
            results = [results]
        if not isinstance(results, list):
            results = []
        for attempt in results:
            if attempt.ok:
                record.latencies.append(attempt.latency_ms)
                record.tls_ok = record.tls_ok and attempt.tls_ok
            else:
                record.failures += 1
        successes = len(record.latencies)
        if successes < required:
            return
        if record.failures > (total_attempts - required):
            return
        if tls_expected(record.node) and not is_reality_node(record.node) and not record.tls_ok:
            return
        jitter = max(record.latencies) - min(record.latencies) if len(record.latencies) >= 2 else 0
        if jitter > config.jitter_limit_ms:
            return
        avg = sum(record.latencies) / len(record.latencies)
        if avg > config.latency_limit_ms:
            return
        record.score = avg + jitter * 0.75 + record.failures * 350.0
        record.verified = True

    _probe_executor(
        records, config, emit, cancel_event, progress_start, progress_end,
        "稳定性复测", worker, on_result,
    )
    return [r for r in records if r.verified]


def fetch_sources(emit: Callable[[dict], None], cancel_event: threading.Event) -> list[dict]:
    total = len(SOURCE_URLS)
    all_nodes: list[dict] = []
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) NodeHunterPro/2.0",
        "Accept": "text/yaml,text/plain,*/*",
    })
    for index, url in enumerate(SOURCE_URLS, start=1):
        if cancel_event.is_set():
            break
        emit({"type": "log", "text": f"抓取源 {index}/{total}：{urllib.parse.urlparse(url).netloc}"})
        response = None
        last_error = ""
        for attempt in range(2):
            try:
                response = session.get(url, timeout=(6, 14))
                break
            except Exception as exc:
                last_error = clean_text(exc, 100)
                if attempt == 0:
                    time.sleep(0.35)
        try:
            if response is None:
                raise RuntimeError(last_error or "请求失败")
            if response.status_code != 200:
                emit({"type": "log", "text": f"  ↳ HTTP {response.status_code}，跳过"})
                continue
            text = response.content.decode(response.encoding or "utf-8", errors="replace")
            # 部分免费源混入 C0/C1 控制字符，先清理再解析，避免整份 YAML 被丢弃。
            text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]", "", text)
            yaml = YAML(typ="safe", pure=True)
            data = yaml.load(text)
            proxies = data.get("proxies") if isinstance(data, dict) else None
            if isinstance(proxies, list):
                valid = [item for item in proxies if isinstance(item, dict)]
                all_nodes.extend(valid)
                emit({"type": "log", "text": f"  ↳ 获取 {len(valid)} 个节点"})
            else:
                emit({"type": "log", "text": "  ↳ 未发现 proxies 列表"})
        except Exception as exc:
            emit({"type": "log", "text": f"  ↳ 抓取失败：{clean_text(exc, 100)}"})
        emit({
            "type": "progress",
            "value": 18.0 * index / total,
            "status": f"抓取源 {index}/{total} · 已获取 {len(all_nodes)} 个节点",
        })
    return all_nodes


def build_records(raw_nodes: list[dict], config: RunConfig, emit: Callable[[dict], None]) -> list[NodeRecord]:
    records: list[NodeRecord] = []
    seen: set[tuple] = set()
    invalid = unsupported = wrong_region = duplicate = 0
    type_counts: dict[str, int] = {}
    total = len(raw_nodes)
    for index, raw in enumerate(raw_nodes, start=1):
        node = sanitize_node(raw)
        if node is None:
            invalid += 1
            continue
        node_type = str(node.get("type"))
        if node_type not in SUPPORTED_TYPES:
            unsupported += 1
            continue
        region = detect_region(str(node.get("name", "")))
        if region is None:
            if not config.keep_unknown_region:
                wrong_region += 1
                continue
        elif region not in config.selected_regions:
            wrong_region += 1
            continue
        key = dedupe_key(node)
        if key in seen:
            duplicate += 1
            continue
        seen.add(key)
        type_counts[node_type] = type_counts.get(node_type, 0) + 1
        records.append(NodeRecord(node=node, region=region))
        if index % 250 == 0:
            emit({
                "type": "progress",
                "value": 18.0 + 8.0 * index / max(1, total),
                "status": f"格式与地区预筛 {index}/{total}",
            })
    emit({
        "type": "log",
        "text": (
            f"预筛完成：原始 {total} → 合规 {len(records)}；"
            f"无效/不支持 {invalid}，地区不符 {wrong_region}，重复 {duplicate}"
        ),
    })
    if type_counts:
        emit({"type": "log", "text": "协议分布：" + "，".join(f"{k.upper()} {v}" for k, v in sorted(type_counts.items()))})
    return records


def run_pipeline(config: RunConfig, emit: Callable[[dict], None], cancel_event: threading.Event) -> None:
    started = time.perf_counter()
    try:
        emit({"type": "log", "text": f"开始任务 · 延迟上限 {config.latency_limit_ms}ms · {QUALITY_PRESETS[config.quality_mode]['label']}"})
        raw_nodes = fetch_sources(emit, cancel_event)
        if cancel_event.is_set():
            emit({"type": "cancelled"})
            return
        if not raw_nodes:
            raise RuntimeError("所有订阅源均未获取到节点，请检查网络或稍后重试。")

        emit({"type": "progress", "value": 18.0, "status": f"开始格式与地区预筛 · 原始节点 {len(raw_nodes)}"})
        records = build_records(raw_nodes, config, emit)
        if not records:
            raise RuntimeError("预筛后没有剩余节点，请检查地区选择或保留无法识别地区的选项。")

        quick = run_quick_probe(records, config, emit, cancel_event, 26.0, 56.0)
        emit({"type": "log", "text": f"快速测速通过：{len(quick)} 个（延迟 ≤ {config.latency_limit_ms}ms）"})
        if cancel_event.is_set():
            emit({"type": "cancelled"})
            return
        if not quick:
            raise RuntimeError("没有节点通过延迟测速，请放宽延迟档位或稍后重试。")

        preset = QUALITY_PRESETS[config.quality_mode]
        static_udp = [r for r in quick if r.static_only]
        tcp_quick = [r for r in quick if not r.static_only]
        if preset["attempts"] > 1 and tcp_quick:
            verified = run_quality_probe(tcp_quick, config, emit, cancel_event, 56.0, 92.0)
            verified.extend(static_udp)
            emit({
                "type": "log",
                "text": (
                    f"稳定性复测通过：{len(verified) - len(static_udp)} 个 TCP 节点"
                    f"（{preset['label']}，抖动 ≤ {config.jitter_limit_ms}ms）"
                    f"；另保留 {len(static_udp)} 个已静态校验的 UDP 节点"
                ),
            })
        else:
            for record in tcp_quick:
                record.score = float(record.quick_latency + record.failures * 350.0)
                record.verified = True
            verified = tcp_quick + static_udp
            emit({"type": "progress", "value": 92.0, "status": "极速模式：跳过稳定性复测"})

        if cancel_event.is_set():
            emit({"type": "cancelled"})
            return
        if not verified:
            raise RuntimeError("节点未通过稳定性复测，请尝试均衡模式或放宽延迟/抖动限制。")

        verified.sort(key=lambda item: (item.score, item.quick_latency))
        if config.max_nodes > 0:
            verified = verified[: config.max_nodes]

        emit({"type": "progress", "value": 95.0, "status": "正在生成 Hiddify 订阅文件"})
        result = save_outputs(verified, config, lambda text: emit({"type": "log", "text": text}))
        elapsed = time.perf_counter() - started
        emit({
            "type": "done",
            "count": result["count"],
            "txt": str(result["txt"]),
            "plain": str(result["plain"]),
            "yaml": str(result["yaml"]),
            "singbox": str(result["singbox"]),
            "link_count": result["link_count"],
            "elapsed": elapsed,
        })
        emit({"type": "progress", "value": 100.0, "status": f"完成 · 导出 {result['count']} 个节点"})
    except Exception as exc:
        emit({"type": "log", "text": "错误：" + str(exc)})
        emit({"type": "error", "text": str(exc), "traceback": traceback.format_exc()})


# ============================== 图形界面 ==============================

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, scrolledtext, ttk
    from tkinter import font as tkfont
except ImportError:  # GitHub Actions / headless Linux only uses the core pipeline.
    tk = None
    filedialog = messagebox = scrolledtext = ttk = tkfont = None


COLORS = {
    "bg": "#0B1220", "card": "#111C2E", "card2": "#17243A",
    "border": "#263A58", "text": "#E6EDF7", "muted": "#8FA4C0",
    "accent": "#22C55E", "accent_dark": "#168A42",
    "blue": "#3B82F6", "blue_dark": "#2563EB",
    "red": "#EF4444", "red_dark": "#B91C1C",
    "yellow": "#FBBF24", "log_bg": "#080E18",
}


def enable_high_dpi() -> None:
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass


class NodeHunterApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.events: queue.Queue[dict] = queue.Queue()
        self.cancel_event = threading.Event()
        self.worker: Optional[threading.Thread] = None
        self.running = False
        self.output_dir = app_dir()
        self.current_page = "filter"
        self.region_vars: dict[str, tk.BooleanVar] = {}
        self.region_buttons: dict[str, tk.Button] = {}
        self.nav_buttons: dict[str, tk.Button] = {}

        self.font_family = "Microsoft YaHei UI"
        try:
            available = set(tkfont.families(root))
        except Exception:
            available = set()
        if available and self.font_family not in available:
            self.font_family = "Segoe UI" if "Segoe UI" in available else "TkDefaultFont"

        self._configure_window()
        self._configure_styles()
        self._build_ui()
        self.show_page("filter")
        self.root.after(100, self._poll_events)

    def _configure_window(self) -> None:
        self.root.title(f"{APP_NAME} v{APP_VERSION} · Hiddify 节点质检工具")
        self.root.geometry("1120x840")
        self.root.minsize(980, 700)
        self.root.configure(bg=COLORS["bg"])
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        icon_path = app_dir() / "app.ico"
        if icon_path.exists():
            try:
                self.root.iconbitmap(default=str(icon_path))
            except Exception:
                pass

    def _configure_styles(self) -> None:
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure(".", background=COLORS["bg"], foreground=COLORS["text"], font=(self.font_family, 10))
        style.configure("TFrame", background=COLORS["bg"])
        style.configure("TLabel", background=COLORS["bg"], foreground=COLORS["text"], font=(self.font_family, 10))
        style.configure("Card.TRadiobutton", background=COLORS["card"], foreground=COLORS["text"],
                        indicatorcolor=COLORS["card2"], focuscolor=COLORS["card"], font=(self.font_family, 10))
        style.map("Card.TRadiobutton",
                  background=[("active", COLORS["card"]), ("disabled", COLORS["card"])],
                  foreground=[("disabled", COLORS["muted"])])
        style.configure("Card.TCheckbutton", background=COLORS["card"], foreground=COLORS["text"],
                        indicatorcolor=COLORS["card2"], focuscolor=COLORS["card"], font=(self.font_family, 10))
        style.map("Card.TCheckbutton",
                  background=[("active", COLORS["card"])],
                  foreground=[("disabled", COLORS["muted"])])
        style.configure("Green.Horizontal.TProgressbar", troughcolor=COLORS["card2"], background=COLORS["accent"],
                        bordercolor=COLORS["card2"], lightcolor=COLORS["accent"], darkcolor=COLORS["accent"],
                        thickness=14)
        style.configure("Dark.TSpinbox", fieldbackground=COLORS["card2"], background=COLORS["card2"],
                        foreground=COLORS["text"], arrowcolor=COLORS["text"], bordercolor=COLORS["border"],
                        insertcolor=COLORS["text"], padding=5)
        style.map("Dark.TSpinbox",
                  fieldbackground=[("disabled", COLORS["card"]), ("readonly", COLORS["card2"])],
                  foreground=[("disabled", COLORS["muted"])])
        style.configure("Dark.TCombobox", fieldbackground=COLORS["card2"], background=COLORS["card2"],
                        foreground=COLORS["text"], arrowcolor=COLORS["text"], bordercolor=COLORS["border"],
                        lightcolor=COLORS["card2"], darkcolor=COLORS["card2"], padding=5)
        style.map("Dark.TCombobox",
                  fieldbackground=[("readonly", COLORS["card2"]), ("disabled", COLORS["card"])],
                  foreground=[("readonly", COLORS["text"]), ("disabled", COLORS["muted"])],
                  selectbackground=[("readonly", COLORS["card2"])],
                  selectforeground=[("readonly", COLORS["text"])])
        style.configure("Vertical.TScrollbar", background=COLORS["card2"], troughcolor=COLORS["card"],
                        bordercolor=COLORS["card"], arrowcolor=COLORS["muted"])
        self.root.option_add("*TCombobox*Listbox.background", COLORS["card2"])
        self.root.option_add("*TCombobox*Listbox.foreground", COLORS["text"])
        self.root.option_add("*TCombobox*Listbox.selectBackground", COLORS["blue"])
        self.root.option_add("*TCombobox*Listbox.selectForeground", "#FFFFFF")

    def _make_button(self, parent, text: str, command, kind: str = "secondary",
                     font_size: int = 10, padx: int = 16, pady: int = 9) -> tk.Button:
        palettes = {
            "primary": (COLORS["accent"], "#FFFFFF", COLORS["accent_dark"]),
            "blue": (COLORS["blue"], "#FFFFFF", COLORS["blue_dark"]),
            "secondary": (COLORS["card2"], COLORS["text"], COLORS["border"]),
            "danger": (COLORS["red"], "#FFFFFF", COLORS["red_dark"]),
            "ghost": (COLORS["card"], COLORS["muted"], COLORS["card2"]),
        }
        bg, fg, active_bg = palettes.get(kind, palettes["secondary"])
        button = tk.Button(
            parent, text=text, command=command, bg=bg, fg=fg,
            activebackground=active_bg, activeforeground=fg,
            disabledforeground=COLORS["muted"], relief="flat", bd=0,
            highlightthickness=0, cursor="hand2",
            font=(self.font_family, font_size, "bold" if kind != "ghost" else "normal"),
            padx=padx, pady=pady,
        )
        if kind != "ghost":
            button.bind("<Enter>", lambda _e, b=button, c=active_bg: b.configure(bg=c) if str(b.cget("state")) != "disabled" else None)
            button.bind("<Leave>", lambda _e, b=button, c=bg: b.configure(bg=c) if str(b.cget("state")) != "disabled" else None)
        return button

    def _make_card(self, parent, title: str, subtitle: str = "") -> tuple[tk.Frame, tk.Frame]:
        outer = tk.Frame(parent, bg=COLORS["card"], highlightbackground=COLORS["border"],
                         highlightthickness=1, bd=0)
        inner = tk.Frame(outer, bg=COLORS["card"])
        inner.pack(fill="both", expand=True, padx=18, pady=15)
        tk.Label(inner, text=title, bg=COLORS["card"], fg=COLORS["text"],
                 font=(self.font_family, 13, "bold"), anchor="w").pack(fill="x")
        if subtitle:
            tk.Label(inner, text=subtitle, bg=COLORS["card"], fg=COLORS["muted"],
                     font=(self.font_family, 9), anchor="w", justify="left").pack(fill="x", pady=(3, 10))
        else:
            tk.Frame(inner, bg=COLORS["card"], height=8).pack(fill="x")
        body = tk.Frame(inner, bg=COLORS["card"])
        body.pack(fill="both", expand=True)
        return outer, body

    def _build_ui(self) -> None:
        self.root.grid_rowconfigure(2, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

        header = tk.Frame(self.root, bg=COLORS["bg"])
        header.grid(row=0, column=0, sticky="ew", padx=24, pady=(20, 10))
        header.grid_columnconfigure(0, weight=1)
        title_box = tk.Frame(header, bg=COLORS["bg"])
        title_box.grid(row=0, column=0, sticky="w")
        tk.Label(title_box, text="节点捕食者", bg=COLORS["bg"], fg=COLORS["text"],
                 font=(self.font_family, 22, "bold")).pack(side="left")
        tk.Label(title_box, text="  PRO", bg=COLORS["bg"], fg=COLORS["accent"],
                 font=(self.font_family, 12, "bold")).pack(side="left", pady=(8, 0))
        tk.Label(header, text="Hiddify 专用 · 多轮质检 · 自动去劣", bg=COLORS["bg"],
                 fg=COLORS["muted"], font=(self.font_family, 10)).grid(row=1, column=0, sticky="w", pady=(2, 0))
        self.header_status = tk.Label(header, text="● 待机", bg=COLORS["card2"], fg=COLORS["accent"],
                                      font=(self.font_family, 10, "bold"), padx=14, pady=7)
        self.header_status.grid(row=0, column=1, rowspan=2, sticky="e")

        nav = tk.Frame(self.root, bg=COLORS["bg"])
        nav.grid(row=1, column=0, sticky="ew", padx=24, pady=(4, 12))
        self.nav_buttons["filter"] = self._make_button(nav, "①  筛选策略", lambda: self.show_page("filter"), "secondary", 10)
        self.nav_buttons["filter"].pack(side="left", padx=(0, 8))
        self.nav_buttons["region"] = self._make_button(nav, "②  地区选择", lambda: self.show_page("region"), "secondary", 10)
        self.nav_buttons["region"].pack(side="left", padx=(0, 8))
        self.start_button = self._make_button(nav, "③  开始抓取", self.on_start, "primary", 11, padx=26, pady=9)
        self.start_button.pack(side="left")
        tk.Label(nav, text="  Hiddify 全协议订阅 · Reality / Hy2 / TUIC / AnyTLS / WG / SSH",
                 bg=COLORS["bg"], fg=COLORS["muted"], font=(self.font_family, 9)).pack(side="left", padx=10)

        self.content = tk.Frame(self.root, bg=COLORS["bg"])
        self.content.grid(row=2, column=0, sticky="nsew", padx=24)
        self.content.grid_rowconfigure(0, weight=1)
        self.content.grid_columnconfigure(0, weight=1)
        self.pages = {
            "filter": self._build_filter_page(),
            "region": self._build_region_page(),
        }
        for page in self.pages.values():
            page.grid(row=0, column=0, sticky="nsew")

        self._build_footer()
    def _build_filter_page(self) -> tk.Frame:
        page = tk.Frame(self.content, bg=COLORS["bg"])
        page.grid_rowconfigure(1, weight=1)
        page.grid_columnconfigure(0, weight=1)

        intro = tk.Frame(page, bg=COLORS["bg"])
        intro.grid(row=0, column=0, sticky="ew", pady=(0, 12))
        tk.Label(intro, text="筛选策略", bg=COLORS["bg"], fg=COLORS["text"],
                 font=(self.font_family, 15, "bold")).pack(anchor="w")
        tk.Label(intro, text="先设延迟门槛，再用多轮复测和 TLS 握手剔除秒通但不稳定的节点。",
                 bg=COLORS["bg"], fg=COLORS["muted"], font=(self.font_family, 9)).pack(anchor="w", pady=(3, 0))

        cards = tk.Frame(page, bg=COLORS["bg"])
        cards.grid(row=1, column=0, sticky="nsew")
        for column in range(3):
            cards.grid_columnconfigure(column, weight=1, uniform="filtercards")
        cards.grid_rowconfigure(0, weight=1)

        latency_card, latency_body = self._make_card(cards, "01 · 延迟门槛", "TCP 建连延迟上限，超过即淘汰")
        latency_card.grid(row=0, column=0, sticky="nsew", padx=(0, 6), pady=(0, 10))
        self.latency_choice = tk.StringVar(value="360")
        for value, label, hint in [("360", "360 ms", "极速档"), ("500", "500 ms", "均衡档"), ("800", "800 ms", "宽松档")]:
            ttk.Radiobutton(latency_body, text=f"{label}    {hint}", value=value,
                            variable=self.latency_choice, style="Card.TRadiobutton",
                            command=self._update_latency_widgets).pack(anchor="w", pady=4)
        custom_row = tk.Frame(latency_body, bg=COLORS["card"])
        custom_row.pack(anchor="w", fill="x", pady=(6, 0))
        ttk.Radiobutton(custom_row, text="自定义", value="custom", variable=self.latency_choice,
                        style="Card.TRadiobutton", command=self._update_latency_widgets).pack(side="left")
        self.custom_latency_var = tk.IntVar(value=600)
        self.custom_latency_spin = ttk.Spinbox(
            custom_row, from_=100, to=3000, increment=50, width=7,
            textvariable=self.custom_latency_var, style="Dark.TSpinbox")
        self.custom_latency_spin.pack(side="left", padx=(8, 4))
        tk.Label(custom_row, text="ms", bg=COLORS["card"], fg=COLORS["muted"],
                 font=(self.font_family, 9)).pack(side="left")
        tk.Label(latency_body, text="建议 360ms 起步；优先选择延迟低且抖动小的节点。",
                 bg=COLORS["card"], fg=COLORS["muted"], font=(self.font_family, 9),
                 justify="left", wraplength=270).pack(anchor="w", pady=(14, 0))

        quality_card, quality_body = self._make_card(cards, "02 · 稳定性质检", "多轮探测 + TLS 握手 + 抖动限制")
        quality_card.grid(row=0, column=1, sticky="nsew", padx=6, pady=(0, 10))
        self.quality_label_var = tk.StringVar(value=QUALITY_PRESETS["strict"]["label"])
        self.quality_combo = ttk.Combobox(
            quality_body, textvariable=self.quality_label_var, state="readonly",
            values=[preset["label"] for preset in QUALITY_PRESETS.values()],
            style="Dark.TCombobox", width=29)
        self.quality_combo.pack(anchor="w", fill="x")
        self.quality_combo.bind("<<ComboboxSelected>>", lambda _event: self._update_quality_widgets())
        tk.Label(quality_body, text="严格模式连续 3 次 TCP 探测全部成功，并检查 TLS 证书/握手。",
                 bg=COLORS["card"], fg=COLORS["muted"], font=(self.font_family, 9),
                 justify="left", wraplength=280).pack(anchor="w", pady=(8, 12))
        jitter_row = tk.Frame(quality_body, bg=COLORS["card"])
        jitter_row.pack(anchor="w", fill="x")
        tk.Label(jitter_row, text="最大抖动", bg=COLORS["card"], fg=COLORS["text"],
                 font=(self.font_family, 10)).pack(side="left")
        self.jitter_var = tk.IntVar(value=120)
        self.jitter_spin = ttk.Spinbox(
            jitter_row, from_=30, to=1000, increment=10, width=7,
            textvariable=self.jitter_var, style="Dark.TSpinbox")
        self.jitter_spin.pack(side="left", padx=(10, 4))
        tk.Label(jitter_row, text="ms", bg=COLORS["card"], fg=COLORS["muted"],
                 font=(self.font_family, 9)).pack(side="left")
        tk.Label(quality_body, text="抖动越小越稳；建议 80-180ms。",
                 bg=COLORS["card"], fg=COLORS["muted"], font=(self.font_family, 9),
                 justify="left").pack(anchor="w", pady=(8, 0))

        perf_card, perf_body = self._make_card(cards, "03 · 性能与产出", "控制并发和最终保留数量")
        perf_card.grid(row=0, column=2, sticky="nsew", padx=(6, 0), pady=(0, 10))
        self.max_nodes_var = tk.IntVar(value=100)
        self.threads_var = tk.IntVar(value=80)
        self._spin_row(perf_body, "最多保留", self.max_nodes_var, 0, 500, 10, "个（0=不限）")
        self._spin_row(perf_body, "并发线程", self.threads_var, 10, 300, 10, "个")
        tk.Label(perf_body, text="输出目录", bg=COLORS["card"], fg=COLORS["muted"],
                 font=(self.font_family, 9)).pack(anchor="w", pady=(12, 3))
        path_row = tk.Frame(perf_body, bg=COLORS["card"])
        path_row.pack(fill="x")
        self.output_label = tk.Label(path_row, text=str(self.output_dir), bg=COLORS["card"], fg=COLORS["text"],
                                     font=(self.font_family, 8), anchor="w", justify="left")
        self.output_label.pack(side="left", fill="x", expand=True)
        self._make_button(path_row, "更改", self.choose_output_dir, "ghost", 8, padx=8, pady=5).pack(side="right")
        tk.Label(perf_body, text="输出：TXT / 纯链接 / Clash Meta YAML / sing-box JSON。\nUDP/QUIC 协议只做静态校验。",
                 bg=COLORS["card"], fg=COLORS["muted"], font=(self.font_family, 8),
                 justify="left", wraplength=260).pack(anchor="w", pady=(9, 0))

        info = tk.Frame(page, bg=COLORS["card2"], highlightbackground=COLORS["border"], highlightthickness=1)
        info.grid(row=2, column=0, sticky="ew", pady=(0, 2))
        tk.Label(
            info,
            text=("质检流水线：协议字段规范化 -> 地区识别/筛选 -> 快速 TCP 存活 -> "
                  "多轮 TCP 复测 + TLS 握手校验 + 抖动过滤 -> 按延迟与稳定性排序"),
            bg=COLORS["card2"], fg=COLORS["muted"], font=(self.font_family, 9),
            anchor="w", justify="left", padx=14, pady=10,
        ).pack(fill="x")
        self._update_latency_widgets()
        self._update_quality_widgets()
        return page

    def _spin_row(self, parent, label: str, variable: tk.IntVar, minimum: int, maximum: int,
                  increment: int, suffix: str) -> None:
        row = tk.Frame(parent, bg=COLORS["card"])
        row.pack(anchor="w", fill="x", pady=4)
        tk.Label(row, text=label, bg=COLORS["card"], fg=COLORS["text"],
                 font=(self.font_family, 10)).pack(side="left")
        spin = ttk.Spinbox(row, from_=minimum, to=maximum, increment=increment, width=7,
                           textvariable=variable, style="Dark.TSpinbox")
        spin.pack(side="left", padx=(10, 4))
        tk.Label(row, text=suffix, bg=COLORS["card"], fg=COLORS["muted"],
                 font=(self.font_family, 9)).pack(side="left")

    def _build_region_page(self) -> tk.Frame:
        page = tk.Frame(self.content, bg=COLORS["bg"])
        page.grid_rowconfigure(1, weight=1)
        page.grid_columnconfigure(0, weight=1)

        top = tk.Frame(page, bg=COLORS["bg"])
        top.grid(row=0, column=0, sticky="ew", pady=(0, 12))
        top.grid_columnconfigure(0, weight=1)
        title_box = tk.Frame(top, bg=COLORS["bg"])
        title_box.grid(row=0, column=0, sticky="w")
        tk.Label(title_box, text="地区选择", bg=COLORS["bg"], fg=COLORS["text"],
                 font=(self.font_family, 15, "bold")).pack(side="left")
        self.region_count_label = tk.Label(title_box, text="", bg=COLORS["bg"], fg=COLORS["accent"],
                                           font=(self.font_family, 10, "bold"))
        self.region_count_label.pack(side="left", padx=(12, 0), pady=(4, 0))
        tk.Label(top, text="默认全部勾选；点掉不需要的国家/地区，未识别地区的节点默认剔除。",
                 bg=COLORS["bg"], fg=COLORS["muted"], font=(self.font_family, 9)).grid(
                     row=1, column=0, sticky="w", pady=(2, 0))

        actions = tk.Frame(top, bg=COLORS["bg"])
        actions.grid(row=0, column=1, rowspan=2, sticky="e")
        self._make_button(actions, "全选", lambda: self._set_all_regions(True), "secondary", 9, padx=12, pady=6).pack(side="left", padx=4)
        self._make_button(actions, "全不选", lambda: self._set_all_regions(False), "secondary", 9, padx=12, pady=6).pack(side="left", padx=4)
        self._make_button(actions, "恢复默认", lambda: self._set_all_regions(True), "ghost", 9, padx=12, pady=6).pack(side="left", padx=4)

        card = tk.Frame(page, bg=COLORS["card"], highlightbackground=COLORS["border"], highlightthickness=1)
        card.grid(row=1, column=0, sticky="nsew")
        card.grid_rowconfigure(0, weight=1)
        card.grid_columnconfigure(0, weight=1)

        canvas = tk.Canvas(card, bg=COLORS["card"], highlightthickness=0, bd=0)
        canvas.grid(row=0, column=0, sticky="nsew", padx=(12, 0), pady=12)
        scrollbar = ttk.Scrollbar(card, orient="vertical", command=canvas.yview, style="Vertical.TScrollbar")
        scrollbar.grid(row=0, column=1, sticky="ns", padx=(0, 6), pady=12)
        canvas.configure(yscrollcommand=scrollbar.set)

        inner = tk.Frame(canvas, bg=COLORS["card"])
        window_id = canvas.create_window((0, 0), window=inner, anchor="nw")
        inner.bind("<Configure>", lambda _event: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda event: canvas.itemconfigure(window_id, width=event.width))

        def on_mousewheel(event):
            delta = -1 if event.delta > 0 else 1
            canvas.yview_scroll(delta * 2, "units")

        def bind_wheel(_event):
            canvas.bind_all("<MouseWheel>", on_mousewheel)

        def unbind_wheel(_event):
            canvas.unbind_all("<MouseWheel>")

        canvas.bind("<Enter>", bind_wheel)
        canvas.bind("<Leave>", unbind_wheel)

        for col in range(4):
            inner.grid_columnconfigure(col, weight=1, uniform="regions")
        for index, region in enumerate(REGION_DEFS):
            code = region["code"]
            var = tk.BooleanVar(value=True)
            self.region_vars[code] = var
            var.trace_add("write", lambda *_args: self._update_region_count())
            button = tk.Button(
                inner, text="", command=lambda c=code: self._toggle_region(c),
                bg=COLORS["card"], fg=COLORS["text"], activebackground=COLORS["card2"],
                activeforeground=COLORS["text"], relief="flat", bd=0, highlightthickness=0,
                cursor="hand2", anchor="w", justify="left", padx=8, pady=5,
                font=(self.font_family, 9))
            button.grid(row=index // 4, column=index % 4, sticky="ew", padx=5, pady=3)
            self.region_buttons[code] = button

        bottom = tk.Frame(page, bg=COLORS["bg"])
        bottom.grid(row=2, column=0, sticky="ew", pady=(10, 0))
        self.keep_unknown_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            bottom, text="保留无法识别地区的节点（可能包含不需要的地区，默认关闭）",
            variable=self.keep_unknown_var, style="Card.TCheckbutton",
        ).pack(side="left")
        tk.Label(bottom, text="地区识别依据：国旗 Emoji、国家名、常见城市名和国家代码。",
                 bg=COLORS["bg"], fg=COLORS["muted"], font=(self.font_family, 8)).pack(side="right")
        self._update_region_count()
        return page

    def _build_footer(self) -> None:
        footer = tk.Frame(self.root, bg=COLORS["bg"])
        footer.grid(row=3, column=0, sticky="ew", padx=24, pady=(12, 18))
        footer.grid_columnconfigure(0, weight=1)

        progress_card = tk.Frame(footer, bg=COLORS["card"], highlightbackground=COLORS["border"], highlightthickness=1)
        progress_card.grid(row=0, column=0, sticky="ew")
        progress_card.grid_columnconfigure(0, weight=1)

        top = tk.Frame(progress_card, bg=COLORS["card"])
        top.grid(row=0, column=0, sticky="ew", padx=16, pady=(12, 4))
        top.grid_columnconfigure(0, weight=1)
        self.status_label = tk.Label(top, text="等待开始 · 先选择筛选策略和地区", bg=COLORS["card"],
                                     fg=COLORS["text"], font=(self.font_family, 10, "bold"), anchor="w")
        self.status_label.grid(row=0, column=0, sticky="w")
        self.percent_label = tk.Label(top, text="0%", bg=COLORS["card"], fg=COLORS["accent"],
                                      font=(self.font_family, 18, "bold"))
        self.percent_label.grid(row=0, column=1, sticky="e")

        self.progress_bar = ttk.Progressbar(progress_card, mode="determinate", maximum=100,
                                            style="Green.Horizontal.TProgressbar")
        self.progress_bar.grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 10))

        actions = tk.Frame(progress_card, bg=COLORS["card"])
        actions.grid(row=2, column=0, sticky="ew", padx=16, pady=(0, 12))
        self.stop_button = self._make_button(actions, "停止任务", self.on_stop, "danger", 9, padx=16, pady=6)
        self.stop_button.pack(side="left")
        self.stop_button.pack_forget()
        self._make_button(actions, "打开输出目录", self.open_output_folder, "ghost", 9, padx=12, pady=6).pack(side="right")
        self.detail_label = tk.Label(actions, text="", bg=COLORS["card"], fg=COLORS["muted"],
                                     font=(self.font_family, 9))
        self.detail_label.pack(side="left", padx=(12, 0))

        log_card = tk.Frame(footer, bg=COLORS["log_bg"], highlightbackground=COLORS["border"], highlightthickness=1)
        log_card.grid(row=1, column=0, sticky="ew", pady=(10, 0))
        log_card.grid_columnconfigure(0, weight=1)
        self.log_text = scrolledtext.ScrolledText(
            log_card, height=8, bg=COLORS["log_bg"], fg="#B9C8DA", insertbackground=COLORS["text"],
            relief="flat", bd=0, highlightthickness=0,
            font=("Consolas" if self.font_family != "TkDefaultFont" else "Courier New", 9),
            padx=12, pady=9, wrap="word", state="disabled")
        self.log_text.grid(row=0, column=0, sticky="ew")
        self._append_log("工具就绪。TCP 节点多轮质检；Hysteria2/TUIC/WireGuard 等 UDP 协议做静态校验。")

    def show_page(self, page_name: str) -> None:
        self.current_page = page_name
        self.pages[page_name].tkraise()
        for name, button in self.nav_buttons.items():
            if name == page_name:
                button.configure(bg=COLORS["blue"], fg="#FFFFFF", activebackground=COLORS["blue_dark"])
            else:
                button.configure(bg=COLORS["card2"], fg=COLORS["text"], activebackground=COLORS["border"])

    def _update_latency_widgets(self) -> None:
        state = "normal" if self.latency_choice.get() == "custom" else "disabled"
        if hasattr(self, "custom_latency_spin"):
            self.custom_latency_spin.configure(state=state)

    def _update_quality_widgets(self) -> None:
        state = "disabled" if self._quality_key() == "fast" else "normal"
        if hasattr(self, "jitter_spin"):
            self.jitter_spin.configure(state=state)

    def _quality_key(self) -> str:
        label = self.quality_label_var.get()
        for key, preset in QUALITY_PRESETS.items():
            if preset["label"] == label:
                return key
        return "strict"

    def _toggle_region(self, code: str) -> None:
        var = self.region_vars[code]
        var.set(not var.get())

    def _update_region_count(self) -> None:
        if not hasattr(self, "region_count_label"):
            return
        selected = sum(1 for var in self.region_vars.values() if var.get())
        self.region_count_label.configure(text=f"已选 {selected}/{len(self.region_vars)}")
        for code, var in self.region_vars.items():
            button = self.region_buttons.get(code)
            if button is None:
                continue
            region = REGION_BY_CODE[code]
            if var.get():
                button.configure(text=f"☑  {flag_for(code)}  {region['cn']} · {region['en']}",
                                 bg="#123626", fg=COLORS["text"])
            else:
                button.configure(text=f"☐  {flag_for(code)}  {region['cn']} · {region['en']}",
                                 bg=COLORS["card"], fg=COLORS["muted"])

    def _set_all_regions(self, value: bool) -> None:
        for var in self.region_vars.values():
            var.set(value)

    def _append_log(self, text: str) -> None:
        self.log_text.configure(state="normal")
        self.log_text.insert("end", f"[{now_text()}] {text}\n")
        lines = int(self.log_text.index("end-1c").split(".")[0])
        if lines > 800:
            self.log_text.delete("1.0", "120.0")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _latency_limit(self) -> int:
        choice = self.latency_choice.get()
        if choice == "custom":
            try:
                value = int(self.custom_latency_var.get())
            except Exception:
                value = 600
            return max(100, min(3000, value))
        try:
            return int(choice)
        except Exception:
            return 360

    def _safe_int_var(self, var: tk.IntVar, default: int, minimum: int, maximum: int) -> int:
        try:
            value = int(var.get())
        except Exception:
            value = default
        return max(minimum, min(maximum, value))

    def choose_output_dir(self) -> None:
        chosen = filedialog.askdirectory(initialdir=str(self.output_dir), title="选择输出目录")
        if chosen:
            self.output_dir = Path(chosen)
            self.output_label.configure(text=str(self.output_dir))

    def open_output_folder(self) -> None:
        try:
            self.output_dir.mkdir(parents=True, exist_ok=True)
            os.startfile(str(self.output_dir))
        except Exception as exc:
            messagebox.showerror("无法打开目录", str(exc))

    def on_start(self) -> None:
        if self.running:
            return
        selected_regions = {code for code, var in self.region_vars.items() if var.get()}
        if not selected_regions:
            messagebox.showwarning("未选择地区", "至少保留一个地区，或点击全选后再开始。")
            self.show_page("region")
            return
        quality_key = self._quality_key()
        jitter = self._safe_int_var(self.jitter_var, 120, 30, 1000) if quality_key != "fast" else 9999
        config = RunConfig(
            latency_limit_ms=self._latency_limit(),
            quality_mode=quality_key,
            jitter_limit_ms=jitter,
            max_workers=self._safe_int_var(self.threads_var, 80, 10, 300),
            max_nodes=self._safe_int_var(self.max_nodes_var, 100, 0, 500),
            selected_regions=selected_regions,
            keep_unknown_region=bool(self.keep_unknown_var.get()),
            output_dir=self.output_dir,
        )
        self.cancel_event.clear()
        self.running = True
        self._set_running_ui(True)
        self.progress_bar["value"] = 0
        self.percent_label.configure(text="0%")
        self.status_label.configure(text="正在启动任务...")
        self.detail_label.configure(text="")
        self.header_status.configure(text="● 运行中", fg=COLORS["yellow"])
        self._append_log("=" * 52)
        self._append_log(
            f"新任务：延迟<={config.latency_limit_ms}ms，{QUALITY_PRESETS[quality_key]['label']}，"
            f"最多保留 {config.max_nodes if config.max_nodes else '不限'} 个，地区 {len(selected_regions)} 个。")
        self.worker = threading.Thread(target=run_pipeline, args=(config, self.events.put, self.cancel_event),
                                       name="NodeHunterWorker", daemon=True)
        self.worker.start()

    def on_stop(self) -> None:
        if not self.running:
            return
        self.cancel_event.set()
        self.status_label.configure(text="正在停止，等待当前探测超时结束...")
        self._append_log("用户请求停止任务。")
        self.stop_button.configure(state="disabled", text="正在停止...")

    def _set_running_ui(self, running: bool) -> None:
        if running:
            self.start_button.configure(state="disabled", bg=COLORS["card2"], text="③  抓取中...")
            self.nav_buttons["filter"].configure(state="disabled")
            self.nav_buttons["region"].configure(state="disabled")
            self.stop_button.pack(side="left")
            self.stop_button.configure(state="normal", text="停止任务")
        else:
            self.start_button.configure(state="normal", bg=COLORS["accent"], text="③  开始抓取")
            self.nav_buttons["filter"].configure(state="normal")
            self.nav_buttons["region"].configure(state="normal")
            self.stop_button.pack_forget()

    def _poll_events(self) -> None:
        try:
            while True:
                event = self.events.get_nowait()
                self._handle_event(event)
        except queue.Empty:
            pass
        self.root.after(80, self._poll_events)

    def _handle_event(self, event: dict) -> None:
        event_type = event.get("type")
        if event_type == "log":
            self._append_log(str(event.get("text", "")))
        elif event_type == "progress":
            value = max(0.0, min(100.0, float(event.get("value", 0.0))))
            self.progress_bar["value"] = value
            self.percent_label.configure(text=f"{value:.0f}%")
            self.status_label.configure(text=str(event.get("status", "")))
        elif event_type == "done":
            self.running = False
            self._set_running_ui(False)
            count = event.get("count", 0)
            link_count = event.get("link_count", count)
            elapsed = float(event.get("elapsed", 0.0))
            self.status_label.configure(text=f"任务完成 · 已导出 {count} 个高质量节点")
            self.detail_label.configure(text=f"耗时 {elapsed:.1f}s")
            self.progress_bar["value"] = 100
            self.percent_label.configure(text="100%")
            self.header_status.configure(text="● 已完成", fg=COLORS["accent"])
            self._append_log(f"完成：{count} 个节点，TXT 分享链接 {link_count} 条")
            self._append_log(f"TXT：{event.get('txt')}")
            self._append_log(f"纯链接：{event.get('plain')}")
            self._append_log(f"Clash Meta：{event.get('yaml')}")
            self._append_log(f"sing-box：{event.get('singbox')}")
            messagebox.showinfo(
                "抓取完成",
                f"已导出 {count} 个通过质检的节点。\n"
                f"其中 TXT 分享链接 {link_count} 条。\n\n"
                f"TXT（Hiddify 订阅）：\n{event.get('txt')}\n\n"
                f"纯链接：\n{event.get('plain')}\n\n"
                f"Clash Meta（PC）：\n{event.get('yaml')}\n\n"
                f"sing-box（全协议）：\n{event.get('singbox')}\n\n"
                f"耗时：{elapsed:.1f} 秒")
        elif event_type == "error":
            self.running = False
            self._set_running_ui(False)
            text = str(event.get("text", "未知错误"))
            self.status_label.configure(text="任务失败 · " + text)
            self.header_status.configure(text="● 失败", fg=COLORS["red"])
            self._append_log("任务失败：" + text)
            messagebox.showerror("任务失败", text)
        elif event_type == "cancelled":
            self.running = False
            self._set_running_ui(False)
            self.status_label.configure(text="任务已停止 · 未覆盖旧输出文件")
            self.header_status.configure(text="● 已停止", fg=COLORS["yellow"])
            self._append_log("任务已停止，未覆盖旧输出文件。")

    def _on_close(self) -> None:
        if self.running:
            if not messagebox.askyesno("退出程序", "任务仍在运行。确定停止并退出吗？"):
                return
            self.cancel_event.set()
        self.root.destroy()


def main() -> None:
    if tk is None:
        raise SystemExit("当前 Python 环境缺少 tkinter，请安装 python3-tk 或使用 runner.py 无界面模式。")
    enable_high_dpi()
    root = tk.Tk()
    NodeHunterApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
