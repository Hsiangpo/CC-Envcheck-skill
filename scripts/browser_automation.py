#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""浏览器自动化探测与执行辅助。"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.request import urlopen


LOCAL_BROWSER_ENV = ".cc-check-browser"


def resolve_playwright_module_specifier(scripts_dir: Path) -> str | None:
    """解析可供 Node runner 动态导入的 Playwright 模块路径。"""
    project_root = scripts_dir.parent
    candidates = [
        project_root / LOCAL_BROWSER_ENV / "node_modules" / "playwright" / "index.js",
        project_root / "node_modules" / "playwright" / "index.js",
    ]
    extra_dir = os.environ.get("CC_CHECK_BROWSER_NODE_DIR", "").strip()
    if extra_dir:
        candidates.insert(0, Path(extra_dir) / "node_modules" / "playwright" / "index.js")

    for candidate in candidates:
        if candidate.exists():
            return candidate.resolve().as_uri()
    return None


def _probe_playwright_command() -> str:
    """返回用于探测 Playwright 的 Node.js 代码。"""
    return (
        "try {"
        " require.resolve('playwright');"
        " process.stdout.write('ok');"
        "} catch (error) {"
        " process.stderr.write(error && error.message ? error.message : 'playwright not found');"
        " process.exit(1);"
        "}"
    )


def _normalize_reason(reason: str) -> str:
    """把底层探测错误转成更稳定的用户提示。"""
    lower = reason.lower()
    if "cannot find module 'playwright'" in lower or "playwright not found" in lower:
        return "playwright package not found in current Node environment"
    return reason.strip() or "playwright unavailable"


def _detect_cdp_endpoint(explicit: str | None = None) -> str | None:
    """探测现有浏览器的 CDP 入口。"""
    candidates = []
    if explicit:
        candidates.append(explicit.strip())
    env_candidate = os.environ.get("CC_CHECK_BROWSER_CDP_URL", "").strip()
    if env_candidate and env_candidate not in candidates:
        candidates.append(env_candidate)
    if "http://127.0.0.1:9222" not in candidates:
        candidates.append("http://127.0.0.1:9222")

    for candidate in candidates:
        if not candidate:
            continue
        if candidate.startswith(("ws://", "wss://")):
            return candidate
        probe = candidate.rstrip("/")
        if not probe.endswith("/json/version"):
            probe = f"{probe}/json/version"
        try:
            with urlopen(probe, timeout=2) as response:
                payload = json.loads(response.read().decode("utf-8", errors="ignore"))
        except (URLError, TimeoutError, OSError, json.JSONDecodeError):
            continue
        if payload.get("webSocketDebuggerUrl"):
            return candidate.rstrip("/")
    return None


def detect_playwright_support(scripts_dir: Path, browser_cdp_url: str | None = None) -> dict[str, Any]:
    """检测当前环境是否具备 Playwright 自动化能力。"""
    node_path = shutil.which("node")
    runner_path = scripts_dir / "browser_automation_runner.mjs"
    module_specifier = resolve_playwright_module_specifier(scripts_dir)
    bootstrap_hint = "run browser_bootstrap.py install to prepare local Playwright"
    if not node_path:
        return {
            "available": False,
            "provider": "playwright",
            "reason": "node not found",
            "runner": str(runner_path),
        }
    if not runner_path.exists():
        return {
            "available": False,
            "provider": "playwright",
            "reason": "runner script missing",
            "runner": str(runner_path),
        }
    if not module_specifier:
        completed = subprocess.run(
            [node_path, "-e", _probe_playwright_command()],
            cwd=str(scripts_dir.parent),
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        if completed.returncode != 0:
            reason = _normalize_reason(completed.stderr or completed.stdout or "playwright package not found")
            return {
                "available": False,
                "provider": "playwright",
                "reason": f"{reason}; {bootstrap_hint}",
                "runner": str(runner_path),
            }
        module_specifier = "playwright"
    cdp_url = _detect_cdp_endpoint(browser_cdp_url)
    if cdp_url:
        return {
            "available": True,
            "provider": "cdp",
            "reason": "",
            "runner": str(runner_path),
            "node": node_path,
            "module_specifier": module_specifier or "playwright",
            "cdp_url": cdp_url,
        }
    return {
        "available": True,
        "provider": "playwright",
        "reason": "",
        "runner": str(runner_path),
        "node": node_path,
        "module_specifier": module_specifier or "playwright",
    }


def execute_playwright_runner(scripts_dir: Path, timeout: int = 120, browser_cdp_url: str | None = None) -> dict[str, Any]:
    """执行 Playwright runner 并返回原始 JSON 结果。"""
    capability = detect_playwright_support(scripts_dir, browser_cdp_url=browser_cdp_url)
    if not capability.get("available"):
        return {
            "ok": False,
            "provider": capability.get("provider", "playwright"),
            "reason": capability.get("reason", "playwright unavailable"),
            "executed_tests": [],
            "results": {},
            "errors": [capability.get("reason", "playwright unavailable")],
        }

    completed = subprocess.run(
        [capability["node"], capability["runner"]],
        cwd=str(scripts_dir.parent),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        env={
            **os.environ,
            "CC_CHECK_PLAYWRIGHT_MODULE": capability.get("module_specifier", "playwright"),
            "CC_CHECK_BROWSER_CDP_URL": capability.get("cdp_url", ""),
        },
    )
    if completed.returncode != 0:
        reason = _normalize_reason(completed.stderr or completed.stdout or "runner failed")
        return {
            "ok": False,
            "provider": capability.get("provider", "playwright"),
            "reason": reason,
            "executed_tests": [],
            "results": {},
            "errors": [reason],
        }

    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        return {
            "ok": False,
            "provider": capability.get("provider", "playwright"),
            "reason": f"runner returned invalid JSON: {error}",
            "executed_tests": [],
            "results": {},
            "errors": [f"runner returned invalid JSON: {error}"],
        }

    payload.setdefault("ok", True)
    payload.setdefault("provider", capability.get("provider", "playwright"))
    payload.setdefault("executed_tests", payload.get("executedTests", []))
    payload.setdefault("results", {})
    payload.setdefault("errors", [])
    return payload
