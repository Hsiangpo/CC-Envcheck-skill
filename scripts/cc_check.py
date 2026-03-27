#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CC-check 技能主脚本。"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import plistlib
import re
import socket
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.request import urlopen

try:
    import paramiko  # type: ignore
except Exception:  # pragma: no cover - 依赖缺失时降级
    paramiko = None


ENV_BLOCK_START = "# >>> cc-check env >>>"
ENV_BLOCK_END = "# <<< cc-check env <<<"
ENV_BLOCK = """# >>> cc-check env >>>
export TZ="America/Los_Angeles"
export LANG="en_US.UTF-8"
export LC_ALL="en_US.UTF-8"
export LANGUAGE="en_US"
export HTTP_PROXY="http://127.0.0.1:7897"
export HTTPS_PROXY="$HTTP_PROXY"
export http_proxy="$HTTP_PROXY"
export https_proxy="$HTTP_PROXY"
export ALL_PROXY="$HTTP_PROXY"
export all_proxy="$HTTP_PROXY"
export DISABLE_TELEMETRY="1"
export DISABLE_ERROR_REPORTING="1"
export CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1"
# <<< cc-check env <<<"""

SUSPICIOUS_DNS = {
    "114.114.114.114",
    "223.5.5.5",
    "223.6.6.6",
    "119.29.29.29",
}
PUBLIC_MARKERS = [
    "dns-hijack",
    "respect-rules: true",
    "proxy-server-nameserver",
    "cc.gpteamservices.com",
]
LOW_RISK_GOOGLE_MARKERS = (
    "2400:cb00:",
    "192.178.",
    "172.69.",
    "108.162.",
)
FAIL_GOOGLE_MARKERS = (
    "124.220.",
    "124.23.",
    "210.87.",
    "223.6.6.6",
    "114.114.114.114",
)
LAUNCH_AGENT_LABEL = "io.github.clash-verge-rev.dns-cleanup"
LAUNCH_AGENT_NAME = f"{LAUNCH_AGENT_LABEL}.plist"
CLASH_APP_PROCESS = "/Applications/Clash Verge.app/Contents/MacOS/clash-verge"


@dataclass
class Context:
    skill_root: Path
    home: Path
    claude_dir: Path
    clash_dir: Path | None
    vpn_root: Path | None
    public_subscription_url: str | None


@dataclass
class Finding:
    group: str
    key: str
    status: str
    summary: str
    details: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def run_zsh(command: str, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    """执行 zsh 命令并返回结果。"""
    return subprocess.run(
        ["/bin/zsh", "-lc", command],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def load_json(path: Path) -> dict[str, Any] | None:
    """读取 JSON 文件。"""
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def load_module(path: Path, name: str, extra_path: Path | None = None) -> Any | None:
    """动态加载 Python 模块。"""
    if not path.exists():
        return None
    if extra_path is not None:
        sys.path.insert(0, str(extra_path))
    try:
        spec = importlib.util.spec_from_file_location(name, path)
        if spec is None or spec.loader is None:
            return None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    except Exception:
        return None
    finally:
        if extra_path is not None and sys.path and sys.path[0] == str(extra_path):
            sys.path.pop(0)


def detect_vpn_root(explicit: str | None) -> Path | None:
    """发现 VPN 项目根目录。"""
    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit).expanduser())
    env_path = os.environ.get("CC_CHECK_VPN_PROJECT_ROOT")
    if env_path:
        candidates.append(Path(env_path).expanduser())

    home = Path.home()
    candidates.extend(
        [
            home / "Develop" / "Masterpiece" / "System" / "My_VPN",
            home / "Develop" / "My_VPN",
            home / "Projects" / "My_VPN",
            home / "Code" / "My_VPN",
            home / "My_VPN",
        ]
    )

    for candidate in candidates:
        if (candidate / "scripts" / "subscription_builder.py").exists():
            return candidate
    return None


def detect_clash_dir(explicit: str | None) -> Path | None:
    """发现 Clash Verge 支持目录。"""
    if explicit:
        path = Path(explicit).expanduser()
        return path if path.exists() else None

    env_path = os.environ.get("CC_CHECK_CLASH_DIR")
    if env_path:
        path = Path(env_path).expanduser()
        return path if path.exists() else None

    default_path = (
        Path.home()
        / "Library"
        / "Application Support"
        / "io.github.clash-verge-rev.clash-verge-rev"
    )
    return default_path if default_path.exists() else None


def detect_public_subscription_url(vpn_root: Path | None, explicit: str | None) -> str | None:
    """发现公开订阅地址。"""
    if explicit:
        return explicit

    env_url = os.environ.get("CC_CHECK_PUBLIC_SUBSCRIPTION_URL")
    if env_url:
        return env_url

    if vpn_root is None:
        return None

    builder = load_module(
        vpn_root / "scripts" / "subscription_builder.py",
        "subscription_builder_for_cc_check",
        vpn_root / "scripts",
    )
    if builder is None:
        return None
    try:
        state = builder.build_state()
        return state.get("subscription_url")
    except Exception:
        return None


def make_context(args: argparse.Namespace) -> Context:
    """构建运行上下文。"""
    skill_root = Path(__file__).resolve().parents[1]
    home = Path.home()
    claude_dir = home / ".claude"
    vpn_root = detect_vpn_root(args.vpn_root)
    clash_dir = detect_clash_dir(args.clash_dir)
    public_subscription_url = detect_public_subscription_url(vpn_root, args.public_subscription_url)
    return Context(
        skill_root=skill_root,
        home=home,
        claude_dir=claude_dir,
        clash_dir=clash_dir,
        vpn_root=vpn_root,
        public_subscription_url=public_subscription_url,
    )


def profile_has_expected_env(path: Path) -> bool:
    """检查 profile 是否已有环境块。"""
    if not path.exists():
        return False
    text = path.read_text(encoding="utf-8", errors="ignore")
    return all(token in text for token in ('TZ="America/Los_Angeles"', 'LANG="en_US.UTF-8"', 'HTTP_PROXY="http://127.0.0.1:7897"'))


def get_dns_servers(service: str) -> list[str]:
    """读取某个网络服务的 DNS。"""
    result = run_zsh(f'networksetup -getdnsservers "{service}"')
    if result.returncode != 0:
        return []
    output = result.stdout.strip()
    if "There aren't any DNS Servers set" in output:
        return []
    return [line.strip() for line in output.splitlines() if line.strip()]


def list_network_services() -> list[str]:
    """列出网络服务。"""
    result = run_zsh("networksetup -listallnetworkservices")
    if result.returncode != 0:
        return []
    services: list[str] = []
    for line in result.stdout.splitlines()[1:]:
        cleaned = line.lstrip("*").strip()
        if cleaned:
            services.append(cleaned)
    return services


def fetch_public_ip() -> str | None:
    """读取当前外网 IP。"""
    for url in ("https://ifconfig.me/ip", "https://api.ipify.org"):
        try:
            with urlopen(url, timeout=8) as response:
                value = response.read().decode("utf-8", errors="ignore").strip()
                if value:
                    return value
        except (URLError, TimeoutError, socket.timeout, OSError):
            continue
    return None


def parse_input_source() -> str | None:
    """读取当前输入法。"""
    path = Path.home() / "Library/Preferences/com.apple.HIToolbox.plist"
    if not path.exists():
        return None
    try:
        payload = plistlib.loads(path.read_bytes())
    except Exception:
        return None
    sources = payload.get("AppleSelectedInputSources", [])
    if not isinstance(sources, list):
        return None
    for source in sources:
        if not isinstance(source, dict):
            continue
        bundle_id = source.get("Bundle ID")
        input_mode = source.get("Input Mode")
        if input_mode:
            return str(input_mode)
        if bundle_id:
            return str(bundle_id)
    return None


def get_clash_json(path: str) -> dict[str, Any] | None:
    """通过 mihomo unix socket 读取 JSON。"""
    command = f"curl --silent --show-error --unix-socket /tmp/verge/verge-mihomo.sock http://localhost/{path}"
    result = run_zsh(command, timeout=8)
    if result.returncode != 0 or not result.stdout.strip():
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return None


def classify_google_dns(lines: list[str]) -> tuple[str, str]:
    """根据 Google whoami 结果给出状态。"""
    text = " | ".join(lines)
    if not text:
        return "warn", "Google DNS whoami returned empty output"
    if any(marker in text for marker in FAIL_GOOGLE_MARKERS):
        return "fail", f"Google DNS whoami still shows suspicious output: {text}"
    if any(marker in text for marker in LOW_RISK_GOOGLE_MARKERS) or "edns0-client-subnet" in text:
        return "warn", f"Google DNS PoP is acceptable but not ideal: {text}"
    return "pass", f"Google DNS whoami looks acceptable: {text}"


def inspect_claude(context: Context) -> list[Finding]:
    """检查 Claude 相关配置。"""
    findings: list[Finding] = []
    settings_path = context.claude_dir / "settings.json"
    settings = load_json(settings_path)
    if settings is None:
        findings.append(Finding("claude", "settings", "fail", "Claude settings.json is missing or invalid"))
    else:
        language = settings.get("language")
        if language and str(language).lower() != "english":
            findings.append(Finding("claude", "language", "warn", f"Claude language is set to {language}"))
        else:
            findings.append(Finding("claude", "language", "pass", "Claude language setting is neutral"))

    telemetry_dir = context.claude_dir / "telemetry"
    if telemetry_dir.exists() and any(telemetry_dir.iterdir()):
        findings.append(Finding("claude", "telemetry", "fail", "Claude telemetry residue exists"))
    else:
        findings.append(Finding("claude", "telemetry", "pass", "Claude telemetry residue is clean"))

    missing_env = [
        key
        for key in (
            "DISABLE_TELEMETRY",
            "DISABLE_ERROR_REPORTING",
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC",
        )
        if os.environ.get(key) != "1"
    ]
    if missing_env:
        findings.append(Finding("claude", "privacy-env", "fail", f"Missing runtime privacy env: {', '.join(missing_env)}"))
    else:
        findings.append(Finding("claude", "privacy-env", "pass", "Runtime privacy env is aligned"))
    return findings


def inspect_system(context: Context) -> list[Finding]:
    """检查系统环境。"""
    findings: list[Finding] = []
    tz_ok = os.environ.get("TZ") == "America/Los_Angeles"
    lang_ok = os.environ.get("LANG") == "en_US.UTF-8"
    lc_all_ok = os.environ.get("LC_ALL") == "en_US.UTF-8"
    zprofile_ok = profile_has_expected_env(context.home / ".zprofile")
    zshrc_ok = profile_has_expected_env(context.home / ".zshrc")

    if tz_ok and lang_ok and lc_all_ok and zprofile_ok and zshrc_ok:
        findings.append(Finding("system", "locale-timezone", "pass", "Timezone and locale are aligned"))
    else:
        findings.append(
            Finding(
                "system",
                "locale-timezone",
                "fail",
                "Timezone or locale is not fully aligned",
                details=[
                    f"TZ={os.environ.get('TZ', '')}",
                    f"LANG={os.environ.get('LANG', '')}",
                    f"LC_ALL={os.environ.get('LC_ALL', '')}",
                    f".zprofile={'ok' if zprofile_ok else 'missing'}",
                    f".zshrc={'ok' if zshrc_ok else 'missing'}",
                ],
            )
        )

    input_source = parse_input_source()
    if input_source and ("SCIM" in input_source or "ITABC" in input_source):
        findings.append(Finding("system", "input-method", "warn", f"Current input source is {input_source}"))
    else:
        findings.append(Finding("system", "input-method", "pass", "Current input source is low-risk"))

    name = run_zsh("git config --global user.name").stdout.strip()
    email = run_zsh("git config --global user.email").stdout.strip()
    if name or email:
        findings.append(Finding("system", "git-identity", "fail", "Global git identity is still set"))
    else:
        findings.append(Finding("system", "git-identity", "pass", "Global git identity is clean"))
    return findings


def inspect_clash(context: Context, public_ip: str | None) -> list[Finding]:
    """检查 Clash Verge 运行态。"""
    findings: list[Finding] = []
    if context.clash_dir is None:
        return [Finding("clash", "support-dir", "skip", "Clash Verge support directory not found")]

    clash_running = run_zsh(f'pgrep -f "{CLASH_APP_PROCESS}"').returncode == 0
    if not clash_running:
        findings.append(Finding("clash", "process", "fail", "Clash Verge process is not running"))
        return findings
    findings.append(Finding("clash", "process", "pass", "Clash Verge process is running"))

    configs = get_clash_json("configs")
    global_proxy = get_clash_json("proxies/GLOBAL")
    if configs is None:
        findings.append(Finding("clash", "runtime-config", "fail", "Cannot read Clash runtime config"))
    else:
        mode = configs.get("mode")
        if mode == "direct":
            findings.append(Finding("clash", "mode", "fail", "Clash mode is direct"))
        else:
            findings.append(Finding("clash", "mode", "pass", f"Clash mode is {mode}"))

    if global_proxy and global_proxy.get("now"):
        findings.append(Finding("clash", "global-node", "pass", f"GLOBAL now points to {global_proxy.get('now')}"))
    else:
        findings.append(Finding("clash", "global-node", "warn", "Cannot determine current GLOBAL node"))

    runtime_yaml = context.clash_dir / "clash-verge.yaml"
    runtime_text = runtime_yaml.read_text(encoding="utf-8", errors="ignore") if runtime_yaml.exists() else ""
    missing_markers = [marker for marker in PUBLIC_MARKERS[:3] if marker not in runtime_text]
    if missing_markers:
        findings.append(Finding("clash", "runtime-markers", "fail", f"Runtime config is missing markers: {', '.join(missing_markers)}"))
    else:
        findings.append(Finding("clash", "runtime-markers", "pass", "Runtime config contains hardened DNS markers"))

    suspicious_services: list[str] = []
    for service in list_network_services():
        dns_servers = get_dns_servers(service)
        if any(server in SUSPICIOUS_DNS for server in dns_servers):
            suspicious_services.append(service)
    if suspicious_services:
        findings.append(Finding("clash", "system-dns-display", "fail", f"System DNS display still has suspicious values on: {', '.join(suspicious_services)}"))
    else:
        findings.append(Finding("clash", "system-dns-display", "pass", "System DNS display is clean"))

    helper_path = context.clash_dir / "cleanup_system_dns.sh"
    launch_agent = context.home / "Library/LaunchAgents" / LAUNCH_AGENT_NAME
    if helper_path.exists() and launch_agent.exists():
        findings.append(Finding("clash", "dns-cleanup-watchdog", "pass", "DNS cleanup watchdog is installed"))
    else:
        findings.append(Finding("clash", "dns-cleanup-watchdog", "warn", "DNS cleanup watchdog is not installed"))

    google_result = run_zsh("dig +time=3 +tries=1 +short TXT o-o.myaddr.l.google.com @ns1.google.com 2>/dev/null")
    google_lines = [line.strip().strip('"') for line in google_result.stdout.splitlines() if line.strip()]
    google_status, google_summary = classify_google_dns(google_lines)
    findings.append(Finding("clash", "dns-google", google_status, google_summary))

    cloudflare_result = run_zsh("dig +time=3 +tries=1 +short CH TXT whoami.cloudflare @1.1.1.1 2>/dev/null")
    cloudflare_text = cloudflare_result.stdout.strip().replace('"', "")
    if public_ip and cloudflare_text == public_ip:
        findings.append(Finding("clash", "dns-cloudflare", "pass", f"Cloudflare DNS whoami matches egress IP {cloudflare_text}"))
    elif cloudflare_text:
        findings.append(Finding("clash", "dns-cloudflare", "warn", f"Cloudflare DNS whoami returned {cloudflare_text}"))
    else:
        findings.append(Finding("clash", "dns-cloudflare", "fail", "Cloudflare DNS whoami returned empty output"))
    return findings


def inspect_public_subscription(context: Context) -> list[Finding]:
    """检查公开订阅内容。"""
    if not context.public_subscription_url:
        return [Finding("vpn", "public-subscription", "skip", "Public subscription URL is not configured")]
    try:
        with urlopen(context.public_subscription_url, timeout=12) as response:
            text = response.read().decode("utf-8", errors="ignore")
    except URLError as error:
        return [Finding("vpn", "public-subscription", "fail", f"Cannot fetch public subscription: {error.reason}")]

    missing = [marker for marker in PUBLIC_MARKERS if marker not in text]
    if missing:
        return [Finding("vpn", "public-subscription", "fail", f"Public subscription is missing markers: {', '.join(missing)}")]
    return [Finding("vpn", "public-subscription", "pass", "Public subscription contains hardened markers")]


def inspect_remote_vpn(context: Context) -> list[Finding]:
    """检查远端 VPN 服务状态。"""
    if context.vpn_root is None:
        return [Finding("vpn", "remote-service", "skip", "VPN project root not found")]
    if paramiko is None:
        return [Finding("vpn", "remote-service", "skip", "paramiko is unavailable")]

    deploy_module = load_module(
        context.vpn_root / "scripts" / "deploy_6node_subscription.py",
        "deploy_for_cc_check",
        context.vpn_root / "scripts",
    )
    if deploy_module is None or not hasattr(deploy_module, "REMOTE"):
        return [Finding("vpn", "remote-service", "fail", "Cannot load VPN deploy script metadata")]

    remote = deploy_module.REMOTE
    host = remote.get("host")
    port = int(remote.get("ssh_port", 22))
    user = remote.get("ssh_user")
    password = remote.get("ssh_password")
    if not all([host, user, password]):
        return [Finding("vpn", "remote-service", "fail", "Remote deployment credentials are incomplete")]

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname=host, port=port, username=user, password=password, timeout=20, banner_timeout=20)
    except Exception as error:
        return [Finding("vpn", "remote-service", "fail", f"Cannot connect to VPN host: {error.__class__.__name__}")]

    try:
        active = remote_exec(client, "systemctl is-active gpteam-ss").strip()
        listeners = remote_exec(client, "ss -lntup | grep 8388 || true")
    finally:
        client.close()

    findings: list[Finding] = []
    if active == "active":
        findings.append(Finding("vpn", "remote-service", "pass", "Remote gpteam-ss service is active"))
    else:
        findings.append(Finding("vpn", "remote-service", "fail", f"Remote gpteam-ss service is {active or 'unknown'}"))

    if "xray" in listeners.lower():
        findings.append(Finding("vpn", "remote-listener", "pass", "Remote 8388 listener belongs to Xray"))
    elif "8388" in listeners:
        findings.append(Finding("vpn", "remote-listener", "fail", "Remote 8388 listener is not owned by Xray"))
    else:
        findings.append(Finding("vpn", "remote-listener", "fail", "Remote 8388 listener is missing"))
    return findings


def remote_exec(client: Any, command: str) -> str:
    """执行远端命令。"""
    _stdin, stdout, stderr = client.exec_command(command, timeout=120)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    return (out + ("\n" + err if err else "")).strip()


def inspect_vpn(context: Context) -> list[Finding]:
    """检查 VPN 项目与远端状态。"""
    if context.vpn_root is None:
        return [Finding("vpn", "project-root", "skip", "VPN project root was not detected")]

    findings: list[Finding] = [Finding("vpn", "project-root", "pass", f"VPN project root detected at {context.vpn_root.name}")]

    test_result = run_zsh(f'cd "{context.vpn_root}" && python3 -m unittest tests/test_subscription_builder.py', timeout=120)
    if test_result.returncode == 0:
        findings.append(Finding("vpn", "unit-tests", "pass", "VPN project unit tests passed"))
    else:
        findings.append(Finding("vpn", "unit-tests", "fail", "VPN project unit tests failed"))

    generated_file = context.vpn_root / "docs/output/clash-meta.yaml"
    if generated_file.exists():
        text = generated_file.read_text(encoding="utf-8", errors="ignore")
        missing = [marker for marker in PUBLIC_MARKERS if marker not in text]
        if missing:
            findings.append(Finding("vpn", "generated-subscription", "fail", f"Generated subscription is missing markers: {', '.join(missing)}"))
        else:
            findings.append(Finding("vpn", "generated-subscription", "pass", "Generated subscription contains hardened markers"))
    else:
        findings.append(Finding("vpn", "generated-subscription", "fail", "Generated subscription file is missing"))

    findings.extend(inspect_public_subscription(context))
    findings.extend(inspect_remote_vpn(context))
    return findings


def collect_findings(context: Context) -> list[Finding]:
    """收集所有发现。"""
    public_ip = fetch_public_ip()
    findings: list[Finding] = []
    findings.extend(inspect_claude(context))
    findings.extend(inspect_system(context))
    findings.extend(inspect_clash(context, public_ip))
    findings.extend(inspect_vpn(context))
    if public_ip:
        findings.append(Finding("network", "public-ip", "pass", f"Public egress IP is {public_ip}"))
    else:
        findings.append(Finding("network", "public-ip", "warn", "Public egress IP could not be determined"))
    return findings


def upsert_env_block(path: Path) -> None:
    """写入受管环境块。"""
    original = path.read_text(encoding="utf-8", errors="ignore") if path.exists() else ""
    pattern = re.compile(
        rf"{re.escape(ENV_BLOCK_START)}.*?{re.escape(ENV_BLOCK_END)}\n?",
        re.DOTALL,
    )
    updated = pattern.sub("", original).strip()
    if updated:
        updated = ENV_BLOCK + "\n\n" + updated + "\n"
    else:
        updated = ENV_BLOCK + "\n"
    path.write_text(updated, encoding="utf-8")


def ensure_verge_dns_toggle(clash_dir: Path) -> None:
    """确保 Clash Verge 的 DNS 设置开关关闭。"""
    verge_yaml = clash_dir / "verge.yaml"
    if not verge_yaml.exists():
        return
    text = verge_yaml.read_text(encoding="utf-8", errors="ignore")
    if "enable_dns_settings:" in text:
        text = re.sub(r"enable_dns_settings:\s*.*", "enable_dns_settings: false", text)
    else:
        text += "\nenable_dns_settings: false\n"
    verge_yaml.write_text(text, encoding="utf-8")


def build_cleanup_script() -> str:
    """生成 DNS 展示清理脚本。"""
    return """#!/bin/zsh
set -euo pipefail

if ! pgrep -f "/Applications/Clash Verge.app/Contents/MacOS/clash-verge" >/dev/null 2>&1; then
  exit 0
fi

while IFS= read -r service; do
  service=${service#\\*}
  service=${service## }
  [[ -z "$service" ]] && continue
  current=$(/usr/sbin/networksetup -getdnsservers "$service" 2>/dev/null || true)
  if [[ "$current" == *"114.114.114.114"* ]] || [[ "$current" == *"223.5.5.5"* ]] || [[ "$current" == *"223.6.6.6"* ]] || [[ "$current" == *"119.29.29.29"* ]]; then
    /usr/sbin/networksetup -setdnsservers "$service" Empty >/dev/null 2>&1 || true
  fi
done < <(/usr/sbin/networksetup -listallnetworkservices | tail -n +2)
"""


def build_launch_agent(script_path: Path) -> str:
    """生成 LaunchAgent。"""
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>Label</key>
    <string>{LAUNCH_AGENT_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
      <string>/bin/zsh</string>
      <string>{script_path}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>StartInterval</key>
    <integer>15</integer>
    <key>StandardOutPath</key>
    <string>/tmp/{LAUNCH_AGENT_LABEL}.out</string>
    <key>StandardErrorPath</key>
    <string>/tmp/{LAUNCH_AGENT_LABEL}.err</string>
  </dict>
</plist>
"""


def install_dns_cleanup(context: Context) -> list[str]:
    """安装系统 DNS 展示清理器。"""
    if context.clash_dir is None:
        return ["Skip DNS cleanup installer: Clash Verge support directory not found"]
    helper_path = context.clash_dir / "cleanup_system_dns.sh"
    launch_agent_dir = context.home / "Library/LaunchAgents"
    launch_agent_path = launch_agent_dir / LAUNCH_AGENT_NAME
    helper_path.write_text(build_cleanup_script(), encoding="utf-8")
    helper_path.chmod(0o755)
    launch_agent_dir.mkdir(parents=True, exist_ok=True)
    launch_agent_path.write_text(build_launch_agent(helper_path), encoding="utf-8")
    uid = os.getuid()
    run_zsh(f'launchctl bootout gui/{uid} "{launch_agent_path}" >/dev/null 2>&1 || true')
    run_zsh(f'launchctl bootstrap gui/{uid} "{launch_agent_path}"')
    run_zsh(f'launchctl kickstart -k gui/{uid}/{LAUNCH_AGENT_LABEL}')
    return ["Installed Clash Verge DNS display cleanup watchdog"]


def clear_suspicious_dns_display() -> list[str]:
    """清理系统中可疑的手工 DNS 展示值。"""
    actions: list[str] = []
    for service in list_network_services():
        current = get_dns_servers(service)
        if any(server in SUSPICIOUS_DNS for server in current):
            run_zsh(f'networksetup -setdnsservers "{service}" Empty')
            actions.append(f"Cleared manual DNS for {service}")
    return actions


def remove_telemetry(context: Context) -> list[str]:
    """清理 Claude telemetry 目录。"""
    actions: list[str] = []
    telemetry_dir = context.claude_dir / "telemetry"
    if telemetry_dir.exists():
        run_zsh(f'rm -rf "{telemetry_dir}"')
        actions.append("Removed Claude telemetry directory")
    return actions


def clear_git_identity() -> list[str]:
    """清理全局 Git 身份。"""
    actions: list[str] = []
    if run_zsh("git config --global user.name").stdout.strip():
        run_zsh("git config --global --unset user.name")
        actions.append("Unset global git user.name")
    if run_zsh("git config --global user.email").stdout.strip():
        run_zsh("git config --global --unset user.email")
        actions.append("Unset global git user.email")
    return actions


def fix_local(context: Context) -> list[str]:
    """执行本地修复。"""
    actions: list[str] = []
    upsert_env_block(context.home / ".zprofile")
    upsert_env_block(context.home / ".zshrc")
    actions.append("Updated ~/.zprofile and ~/.zshrc managed env block")
    actions.extend(remove_telemetry(context))
    actions.extend(clear_git_identity())
    if context.clash_dir is not None:
        ensure_verge_dns_toggle(context.clash_dir)
        actions.append("Set Clash Verge enable_dns_settings to false")
    actions.extend(install_dns_cleanup(context))
    actions.extend(clear_suspicious_dns_display())
    return actions


def redact_text(text: str, tokens: list[str]) -> str:
    """脱敏输出。"""
    redacted = text
    for token in sorted({token for token in tokens if token}, key=len, reverse=True):
        redacted = redacted.replace(token, "***")
    redacted = re.sub(r'("password"\s*:\s*")[^"]+(")', r'\1***\2', redacted)
    redacted = re.sub(r"(-password\s+)\S+", r"\1***", redacted)
    return redacted


def vpn_redaction_tokens(vpn_root: Path) -> list[str]:
    """收集 VPN 相关敏感词。"""
    tokens: list[str] = []
    builder = load_module(vpn_root / "scripts" / "subscription_builder.py", "builder_redact", vpn_root / "scripts")
    deployer = load_module(vpn_root / "scripts" / "deploy_6node_subscription.py", "deployer_redact", vpn_root / "scripts")
    if builder is not None:
        tokens.extend(
            [
                getattr(builder, "SS_PASSWORD", ""),
                getattr(builder, "SUBSCRIPTION_ID", ""),
            ]
        )
    if deployer is not None and hasattr(deployer, "REMOTE"):
        remote = deployer.REMOTE
        tokens.extend([remote.get("ssh_password", ""), remote.get("panel_pass", "")])
    return [token for token in tokens if token]


def should_run_deploy(findings: list[Finding]) -> bool:
    """判断是否需要跑 VPN 部署。"""
    repair_keys = {"public-subscription", "remote-service", "remote-listener"}
    return any(item.status == "fail" and item.key in repair_keys for item in findings)


def fix_vpn(context: Context) -> list[str]:
    """执行 VPN 修复。"""
    if context.vpn_root is None:
        return ["Skip VPN fixes: VPN project root not found"]

    actions: list[str] = []
    run_zsh(f'cd "{context.vpn_root}" && python3 scripts/subscription_builder.py', timeout=120)
    actions.append("Regenerated VPN subscription outputs")

    findings = inspect_vpn(context)
    if should_run_deploy(findings):
        deploy_cmd = f'cd "{context.vpn_root}" && python3 scripts/deploy_6node_subscription.py'
        result = run_zsh(deploy_cmd, timeout=1800)
        if result.returncode != 0:
            secret_tokens = vpn_redaction_tokens(context.vpn_root)
            output = redact_text(result.stdout + "\n" + result.stderr, secret_tokens)
            raise RuntimeError(f"VPN deploy failed:\n{output[-4000:]}")
        actions.append("Ran VPN deploy script to sync public and remote state")
    else:
        actions.append("VPN deploy was not needed")
    return actions


def print_report(findings: list[Finding]) -> None:
    """输出文本报告。"""
    grouped: dict[str, list[Finding]] = {}
    for item in findings:
        grouped.setdefault(item.group, []).append(item)
    for group in sorted(grouped):
        print(f"[{group}]")
        for item in grouped[group]:
            print(f"- {item.status.upper():<4} {item.key}: {item.summary}")
            for detail in item.details:
                print(f"  · {detail}")


def failures(findings: list[Finding]) -> int:
    """统计失败项。"""
    return sum(1 for item in findings if item.status == "fail")


def command_inspect(context: Context, as_json: bool) -> int:
    """执行 inspect。"""
    findings = collect_findings(context)
    if as_json:
        print(json.dumps([item.to_dict() for item in findings], ensure_ascii=False, indent=2))
    else:
        print_report(findings)
    return 0 if failures(findings) == 0 else 2


def command_fix_local(context: Context) -> int:
    """执行本地修复。"""
    for action in fix_local(context):
        print(action)
    return 0


def command_fix_vpn(context: Context) -> int:
    """执行 VPN 修复。"""
    for action in fix_vpn(context):
        print(action)
    return 0


def command_verify(context: Context, as_json: bool) -> int:
    """执行 verify。"""
    return command_inspect(context, as_json)


def command_full(context: Context, as_json: bool) -> int:
    """执行完整流程。"""
    initial = collect_findings(context)
    if failures(initial) == 0:
        if as_json:
            print(json.dumps([item.to_dict() for item in initial], ensure_ascii=False, indent=2))
        else:
            print_report(initial)
        return 0

    local_fail = any(item.group in {"claude", "system", "clash"} and item.status == "fail" for item in initial)
    vpn_fail = any(item.group == "vpn" and item.status == "fail" for item in initial)
    if local_fail:
        for action in fix_local(context):
            print(action)
    if vpn_fail:
        for action in fix_vpn(context):
            print(action)
    return command_verify(context, as_json)


def command_fix_system_dns_display(context: Context, quiet: bool) -> int:
    """只执行系统 DNS 展示清理。"""
    actions = clear_suspicious_dns_display()
    if not quiet:
        for action in actions or ["No suspicious system DNS values found"]:
            print(action)
    return 0


def build_parser() -> argparse.ArgumentParser:
    """构建参数解析器。"""
    parser = argparse.ArgumentParser(description="CC-check skill orchestrator")
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("inspect", "fix-local", "fix-vpn", "verify", "full"):
        subparser = subparsers.add_parser(name)
        subparser.add_argument("--vpn-root", help="Override VPN project root")
        subparser.add_argument("--clash-dir", help="Override Clash Verge support directory")
        subparser.add_argument("--public-subscription-url", help="Override public subscription URL")
        subparser.add_argument("--json", action="store_true", help="Print findings as JSON")
    dns_parser = subparsers.add_parser("fix-system-dns-display")
    dns_parser.add_argument("--vpn-root", help="Override VPN project root")
    dns_parser.add_argument("--clash-dir", help="Override Clash Verge support directory")
    dns_parser.add_argument("--public-subscription-url", help="Override public subscription URL")
    dns_parser.add_argument("--quiet", action="store_true", help="Suppress normal output")
    return parser


def main() -> int:
    """程序入口。"""
    parser = build_parser()
    args = parser.parse_args()
    context = make_context(args)
    try:
        if args.command == "inspect":
            return command_inspect(context, args.json)
        if args.command == "fix-local":
            return command_fix_local(context)
        if args.command == "fix-vpn":
            return command_fix_vpn(context)
        if args.command == "verify":
            return command_verify(context, args.json)
        if args.command == "full":
            return command_full(context, args.json)
        if args.command == "fix-system-dns-display":
            return command_fix_system_dns_display(context, args.quiet)
        parser.error(f"Unknown command: {args.command}")
        return 1
    except Exception as error:
        print(f"CC-check failed: {error.__class__.__name__}: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
