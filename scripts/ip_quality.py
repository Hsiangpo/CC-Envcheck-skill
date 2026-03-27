#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""IP 质量检测辅助模块。"""

from __future__ import annotations

import json
import socket
import subprocess
from typing import Any
from urllib.error import URLError
from urllib.request import urlopen


GOOD_IP_TYPES = {"residential", "mobile"}
BAD_IP_TYPES = {"hosting", "vpn", "proxy"}


def fetch_json(url: str, timeout: int = 8) -> dict[str, Any] | None:
    """读取 JSON 接口。"""
    try:
        with urlopen(url, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8", errors="ignore"))
    except (URLError, TimeoutError, socket.timeout, OSError, json.JSONDecodeError):
        return None


def run_whois(ip: str) -> str:
    """读取 whois 文本。"""
    try:
        result = subprocess.run(
            ["/usr/bin/env", "whois", ip],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        return (result.stdout or "")[:6000]
    except subprocess.TimeoutExpired:
        return ""


def parse_whois_country(text: str) -> str | None:
    """提取 whois country。"""
    for line in text.splitlines():
        if line.lower().startswith("country:"):
            value = line.split(":", 1)[1].strip()
            if value:
                return value
    return None


def assess_ip_quality(ip: str, expected_ip_type: str = "residential") -> dict[str, Any]:
    """用多权威渠道评估 IP 质量。"""
    ipinfo = fetch_json(f"https://ipinfo.io/{ip}/json")
    ip_api = fetch_json(
        f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,timezone,isp,org,as,asname,proxy,hosting,mobile,query"
    )
    proxycheck = fetch_json(
        f"https://proxycheck.io/v2/{ip}?vpn=1&asn=1&risk=1&port=1&seen=1&days=7&tag=cc-check"
    )
    bgpview = fetch_json(f"https://api.bgpview.io/ip/{ip}")
    whois_text = run_whois(ip)
    whois_country = parse_whois_country(whois_text)

    proxy_data = None
    if proxycheck and proxycheck.get("status") == "ok":
        proxy_data = proxycheck.get(ip, {})

    timezone = None
    if ipinfo and ipinfo.get("timezone"):
        timezone = str(ipinfo["timezone"])
    elif ip_api and ip_api.get("timezone"):
        timezone = str(ip_api["timezone"])

    country = None
    if ipinfo and ipinfo.get("country"):
        country = str(ipinfo["country"])
    elif ip_api and ip_api.get("country"):
        country = str(ip_api["country"])

    locale = "en_US.UTF-8" if country == "US" else None
    language = "en_US" if country == "US" else None

    details: list[str] = []
    if ipinfo:
        details.append(
            "ipinfo:"
            f" country={ipinfo.get('country', '?')}"
            f" timezone={ipinfo.get('timezone', '?')}"
            f" org={ipinfo.get('org', '?')}"
        )
    else:
        details.append("ipinfo: unavailable")

    if ip_api and ip_api.get("status") == "success":
        details.append(
            "ip-api:"
            f" proxy={ip_api.get('proxy', '?')}"
            f" hosting={ip_api.get('hosting', '?')}"
            f" mobile={ip_api.get('mobile', '?')}"
            f" isp={ip_api.get('isp', '?')}"
        )
    else:
        details.append("ip-api: unavailable")

    if isinstance(proxy_data, dict) and proxy_data:
        details.append(
            "proxycheck:"
            f" proxy={proxy_data.get('proxy', '?')}"
            f" type={proxy_data.get('type', '?')}"
            f" risk={proxy_data.get('risk', '?')}"
            f" provider={proxy_data.get('provider', '?')}"
        )
    else:
        details.append("proxycheck: unavailable")

    if isinstance(bgpview, dict) and bgpview.get("status") == "ok":
        data = bgpview.get("data", {})
        rir = data.get("rir_allocation", {})
        details.append(
            "bgpview:"
            f" prefix_count={len(data.get('prefixes', []) or [])}"
            f" rir={rir.get('rir_name', '?')}"
        )
    else:
        details.append("bgpview: unavailable")

    details.append(f"whois: country={whois_country or '?'}")

    status = "pass"
    summary = "IP quality looks acceptable"
    recommendations: list[str] = []

    proxy_flag = str(proxy_data.get("proxy", "")).lower() == "yes" if isinstance(proxy_data, dict) else False
    ip_type = str(proxy_data.get("type", "")).lower() if isinstance(proxy_data, dict) else ""
    hosting = bool(ip_api.get("hosting")) if isinstance(ip_api, dict) and ip_api.get("status") == "success" else False
    api_proxy = bool(ip_api.get("proxy")) if isinstance(ip_api, dict) and ip_api.get("status") == "success" else False

    if proxy_flag or api_proxy or hosting:
        status = "fail"
        summary = "IP is flagged as proxy/VPN/hosting by at least one authority"
        recommendations.append("建议升级为真实住宅/家宽 IP，再进行高敏感环境使用。")
    elif expected_ip_type == "residential":
        if ip_type in BAD_IP_TYPES:
            status = "fail"
            summary = f"IP type is {ip_type}, not residential"
            recommendations.append("建议升级为真实住宅/家宽 IP，再进行高敏感环境使用。")
        elif ip_type and ip_type not in GOOD_IP_TYPES:
            status = "warn"
            summary = f"IP type is {ip_type}, not confidently residential"
            recommendations.append("建议继续用更多权威渠道复核，必要时升级为真实住宅/家宽 IP。")
        elif not ip_type:
            status = "warn"
            summary = "IP type could not be confidently classified"
            recommendations.append("建议继续用更多权威渠道复核，必要时升级为真实住宅/家宽 IP。")

    if country and whois_country and country != whois_country:
        if status == "pass":
            status = "warn"
        recommendations.append(f"geo country={country} but whois country={whois_country}, 需要人工复核。")

    return {
        "status": status,
        "summary": summary,
        "details": details + recommendations,
        "target_timezone": timezone,
        "target_locale": locale,
        "target_language": language,
        "country": country,
        "ip_type": ip_type or None,
    }
