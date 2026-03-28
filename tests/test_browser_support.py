#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Browser support tests for scoring and bootstrap diagnostics."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import browser_bootstrap as bboot
import browser_artifacts as barts
import browser_leaks as bleaks
import browser_scoring as bscore


class TestBrowserScoring(unittest.TestCase):
    """验证浏览器自动化评分行为。"""

    def test_browser_score_weights_sum_to_100(self):
        self.assertEqual(sum(bscore.WEIGHTS.values()), 100)

    def test_compute_browser_score_mixed_statuses(self):
        findings = [
            bleaks.BrowserFinding("webrtc", "webrtc-leak", "pass", "ok"),
            bleaks.BrowserFinding("javascript", "js-locale", "warn", "warn"),
            bleaks.BrowserFinding("webgl", "webgl-renderer", "fail", "bad"),
        ]

        report = bscore.compute_browser_score(findings)

        self.assertEqual(report.max_score, 32)
        self.assertEqual(report.total_score, 22)
        self.assertEqual(report.grade, "D")

    def test_payload_includes_browser_score_when_automation_used(self):
        findings = [
            bleaks.BrowserFinding("webrtc", "webrtc-leak", "pass", "ok"),
            bleaks.BrowserFinding("ip", "browser-python-egress-alignment", "pass", "aligned"),
        ]
        meta = {
            "mode": "playwright-automation-plus-python-baseline",
            "automation_supported": True,
            "automation_used": True,
            "provider": "playwright",
            "executed_tests": ["webrtc"],
            "browser_score": bscore.build_browser_score_payload(bscore.compute_browser_score(findings)),
        }

        payload = bleaks.build_report_payload(findings, meta)

        self.assertIsNotNone(payload["browser_score"])
        self.assertEqual(payload["browser_score"]["max_score"], 28)

    def test_build_browser_recommendations_from_findings(self):
        findings = [
            bleaks.BrowserFinding("webrtc", "webrtc-leak", "fail", "bad"),
            bleaks.BrowserFinding("fonts", "china-fonts", "warn", "fonts"),
            bleaks.BrowserFinding("ip", "browser-python-egress-alignment", "fail", "mismatch"),
        ]

        recommendations = bleaks.build_browser_recommendations(findings, {
            "automation_used": True,
            "reason": "",
        })

        keys = [item["key"] for item in recommendations]
        self.assertEqual(keys, ["webrtc-leak", "browser-python-egress-alignment", "china-fonts"])

    def test_build_browser_recommendations_bootstrap_hint_when_automation_unavailable(self):
        recommendations = bleaks.build_browser_recommendations([], {
            "automation_used": False,
            "reason": "playwright package not found in current Node environment; run browser_bootstrap.py install to prepare local Playwright",
        })

        self.assertEqual(recommendations[0]["key"], "automation-bootstrap")

    def test_refine_webrtc_findings_downgrades_proxy_only_candidate(self):
        findings = [
            bleaks.BrowserFinding("webrtc", "webrtc-leak", "fail", "raw"),
            bleaks.BrowserFinding("webrtc", "webrtc-local-ip", "pass", "ok"),
        ]

        refined = bleaks.refine_webrtc_findings(
            findings,
            {"publicCandidates": ["104.254.211.203"]},
            {"endpoints": {"ipify": "104.254.211.203"}},
        )

        self.assertEqual(refined[0].status, "warn")
        self.assertIn("proxy egress candidate", refined[0].summary)

    def test_refine_webrtc_findings_ignores_zero_placeholder(self):
        findings = [
            bleaks.BrowserFinding("webrtc", "webrtc-leak", "pass", "raw"),
            bleaks.BrowserFinding("webrtc", "webrtc-local-ip", "pass", "ok"),
        ]

        refined = bleaks.refine_webrtc_findings(
            findings,
            {"publicCandidates": ["0.0.0.0"]},
            {"endpoints": {"ipify": "104.247.120.78"}},
        )

        self.assertEqual(refined[0].status, "pass")


class TestBrowserBootstrapStatus(unittest.TestCase):
    """验证本地 Playwright 引导状态输出。"""

    def test_build_status_payload_reports_missing_tools(self):
        with tempfile.TemporaryDirectory() as tmpdir, patch("browser_bootstrap.collect_tool_status", return_value={"node": "", "npm": "", "npx": ""}):
            payload = bboot.build_status_payload(Path(tmpdir))

        self.assertFalse(payload["installed"])
        self.assertEqual(payload["missing_tools"], ["node", "npm", "npx"])
        self.assertTrue(any("missing tools" in item for item in payload["recommendations"]))

    def test_build_status_payload_exposes_proxy_env(self):
        with tempfile.TemporaryDirectory() as tmpdir, patch.dict(os.environ, {"HTTPS_PROXY": "http://127.0.0.1:7897"}, clear=False):
            payload = bboot.build_status_payload(Path(tmpdir))

        self.assertEqual(payload["proxy_env"]["HTTPS_PROXY"], "http://127.0.0.1:7897")
        self.assertEqual(len(payload["install_commands"]), 2)


class TestBrowserArtifacts(unittest.TestCase):
    """验证浏览器证据文件保存。"""

    def test_save_browser_artifact_writes_json_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = barts.save_browser_artifact(
                {"mode": "test"},
                {"ip": {"endpoints": {"ipify": "1.1.1.1"}}},
                Path(tmpdir),
            )

            saved = Path(path)
            self.assertTrue(saved.exists())
            payload = json.loads(saved.read_text(encoding="utf-8"))
            self.assertEqual(payload["payload"]["mode"], "test")
            self.assertEqual(payload["raw_results"]["ip"]["endpoints"]["ipify"], "1.1.1.1")


if __name__ == "__main__":
    unittest.main()
