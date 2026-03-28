#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Browser automation artifact helpers for CC-Check."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ARTIFACT_DIR_NAME = "artifacts"


def default_artifact_dir(project_root: Path) -> Path:
    """返回浏览器自动化证据目录。"""
    return project_root / ".cc-check-browser" / ARTIFACT_DIR_NAME


def _artifact_filename() -> str:
    """生成带时间戳的证据文件名。"""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"browser-leaks-{stamp}.json"


def save_browser_artifact(payload: dict[str, Any], raw_results: dict[str, Any] | None, artifact_dir: Path) -> str:
    """保存浏览器检测证据文件并返回路径。"""
    artifact_dir.mkdir(parents=True, exist_ok=True)
    path = artifact_dir / _artifact_filename()
    content = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "payload": payload,
        "raw_results": raw_results or {},
    }
    path.write_text(json.dumps(content, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return str(path)
