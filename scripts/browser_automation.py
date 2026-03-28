#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""浏览器自动化探测与执行辅助。"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any


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


def detect_playwright_support(scripts_dir: Path) -> dict[str, Any]:
    """检测当前环境是否具备 Playwright 自动化能力。"""
    node_path = shutil.which("node")
    runner_path = scripts_dir / "browser_automation_runner.mjs"
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
            "reason": reason,
            "runner": str(runner_path),
        }
    return {
        "available": True,
        "provider": "playwright",
        "reason": "",
        "runner": str(runner_path),
        "node": node_path,
    }


def execute_playwright_runner(scripts_dir: Path, timeout: int = 120) -> dict[str, Any]:
    """执行 Playwright runner 并返回原始 JSON 结果。"""
    capability = detect_playwright_support(scripts_dir)
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
