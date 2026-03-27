---
name: cc-check
description: Use when auditing or repairing Claude Code, Clash Verge, system DNS display, or GPTeam VPN subscription and deployment state across Macs, especially after network drift, anti-detect setup changes, or VPN subscription updates.
---

# CC Check

## Overview

Use this skill to run a reusable Claude/Clash/VPN anti-detect workflow across Macs. The default mode is: inspect first, repair only failing items, then verify again.

## When to Use

Use this skill when any of these are true:

- Claude Code starts failing after proxy, DNS, or locale changes
- A new Mac needs to be aligned with the target VPN environment
- Clash Verge shows suspicious DNS values such as `114.114.114.114`
- You updated the GPTeam VPN subscription and need to confirm local + public + remote state
- You want one redacted end-to-end report instead of ad hoc shell checks

Do not use this skill for browser anti-detect work, app UI spoofing, or unrelated VPN providers.

## Workflow

1. Run the bundled script in `inspect` mode first.
2. Review the grouped findings:
   - `pass` means no action needed
   - `fail` means repair is expected
   - `warn` means low-risk or preference-sensitive; do not auto-fix unless the script explicitly supports it
3. If local items fail, run `fix-local`.
4. If VPN project or remote deployment items fail, run `fix-vpn`.
5. Always run `verify` after any fix pass.

Use `full` only when you want the whole inspect -> repair -> verify sequence in one run.

## Commands

Run the orchestrator directly:

```bash
python3 <path-to-skill>/scripts/cc_check.py inspect
python3 <path-to-skill>/scripts/cc_check.py fix-local
python3 <path-to-skill>/scripts/cc_check.py fix-vpn
python3 <path-to-skill>/scripts/cc_check.py verify
python3 <path-to-skill>/scripts/cc_check.py full
```

Useful overrides:

```bash
python3 <path-to-skill>/scripts/cc_check.py inspect --json
python3 <path-to-skill>/scripts/cc_check.py inspect --vpn-root /custom/path/My_VPN
python3 <path-to-skill>/scripts/cc_check.py full --public-subscription-url "https://example.com/subscription.yaml"
```

## What the Script Checks

- Claude settings, telemetry/session residue, and preference-sensitive fields
- Locale, timezone, proxy env, and global git identity
- Current macOS input source
- Clash Verge runtime mode, active profile, actual DNS path, and system DNS display drift
- The local DNS cleanup watchdog for Clash Verge display-only overrides
- `My_VPN` source consistency, generated outputs, public subscription content, and remote service status

## Fix Policy

`fix-local` may safely mutate:

- `~/.zprofile`
- `~/.zshrc`
- `~/.claude/`
- discovered Clash Verge support files under the current user’s Library
- a generated LaunchAgent used to clear system-DNS display drift when needed
- manual DNS display values for network services that were overwritten by Clash Verge with suspicious public Chinese resolvers

`fix-vpn` may safely mutate:

- generated files in the detected VPN project root
- public subscription state via the detected deploy script
- remote GPTeam VPN service state on the configured host

## Low-Risk Findings

These should be reported as `warn`, not auto-fixed by default:

- Claude settings language is Chinese
- Active input method is SCIM / Pinyin
- Google DNS whoami returns a Cloudflare/anycast Asia PoP instead of a US PoP, as long as the actual DNS path is no longer using China ISP resolvers

## Privacy Rules

- Never print or persist raw passwords, tokens, private keys, or subscription secrets in normal output.
- Never dump full secret-bearing config files.
- Summaries must redact sensitive values as `***`.
- Remote deployment logs must be captured and sanitized before any failure output is shown.

## References

- Audit matrix and grouped checks: `references/check-matrix.md`
- Repair rationale and low-risk exceptions: `references/rationale.md`
