---
name: cc-check
description: Use when auditing or repairing Claude Code proxy alignment, DNS leaks, system fingerprint, public IP quality, package mirrors, or VPN state, especially on macOS and in environments that use Clash Verge or a compatible VPN project.
---

# CC Check

## Overview

Claude Code environment auditor and hardener. It inspects the current machine first, derives a target profile from the public IP when possible, and only repairs items that inspection marks as failed.

Current reality:

- macOS support is the most complete
- Linux and Windows have partial inspection coverage
- VPN project checks work only for supported project layouts, otherwise they cleanly skip

## When to Use

- Claude Code starts failing after proxy, DNS, or locale changes
- A new machine needs to be aligned with the target VPN environment
- Clash Verge shows suspicious DNS values such as `114.114.114.114`
- You want a redacted end-to-end audit with a score, not ad hoc shell checks
- You updated a VPN subscription or node and need to confirm local + public + remote state
- You want to check if any package managers (npm/pip/brew) are using China mirrors
- You need to verify Node.js runtime timezone/locale alignment

Do NOT use this skill for:
- Browser anti-detect work (use dedicated fingerprint browser tools)
- App UI spoofing
- Unrelated VPN providers

## Workflow

1. **Inspect**: Run `inspect` to get a full audit with 100-point score.
2. **Review**: Pass / Fail / Warn / Skip grouped by category.
3. **Fix**: Run `fix-local` for local items, `fix-vpn` for VPN/remote items.
4. **Verify**: Run `verify` to confirm repairs.
5. **Full**: Or run `full` for the complete inspect → fix → verify cycle.

Use `--dry-run` on any fix command to preview changes without applying them.

## Commands

```bash
# Inspect with score
python3 <path>/scripts/cc_check.py inspect

# Inspect with JSON output
python3 <path>/scripts/cc_check.py inspect --json

# Preview fixes without applying
python3 <path>/scripts/cc_check.py fix-local --dry-run

# Apply fixes
python3 <path>/scripts/cc_check.py fix-local

# Full cycle
python3 <path>/scripts/cc_check.py full

# With overrides
python3 <path>/scripts/cc_check.py inspect \
  --target-timezone America/Los_Angeles \
  --target-locale en_US.UTF-8 \
  --proxy-url http://127.0.0.1:7897 \
  --expected-ip-type residential
```

## Audit Groups

The skill currently groups checks into:

- `network`: public IP, multi-source IP, IPv6 leakage
- `ip-quality`: residential / proxy / hosting confidence
- `dns`: actual DNS path and displayed DNS state
- `system`: timezone, locale, proxy env, input method, hostname and related machine signals
- `nodejs`: Node runtime timezone and locale when Node is available
- `packages`: npm / pip / brew mirror checks
- `privacy`: telemetry residue and privacy env
- `identity`: git identity
- `clash`: process, mode, TUN, runtime markers, DNS watchdog
- `claude`: Claude settings
- `vpn`: supported VPN project and remote deployment checks when a compatible project is detected

## Scoring

Each check has a weight. The total is aggregated into a percentage and letter grade.

```
╔════════════════════════════════════════════╗
║  CC-Check Score:  87 / 100  Grade: B  (87.0%)  ║
╠════════════════════════════════════════════╣
║  network      8/15   ████████░░  85.0%  ║
║  dns         16/16   ██████████ 100.0%  ║
║  system      25/25   ██████████ 100.0%  ║
║  ...                                      ║
╚════════════════════════════════════════════╝
```

## Fix Policy

### `fix-local` may safely mutate:
- Shell profile files (`~/.zprofile`, `~/.zshrc`, `~/.bashrc`, `~/.bash_profile`, or PowerShell `$PROFILE`)
- `~/.claude/` telemetry data
- Global git config (`user.name`, `user.email`)
- System DNS display values for services with suspicious Chinese DNS
- DNS cleanup watchdog (macOS LaunchAgent)

### `fix-vpn` may safely mutate:
- Generated files in the detected VPN project root
- Public subscription state via detected deploy script
- Remote VPN service state on configured host

Both fix commands only touch items that inspection marked as `fail`.

## Low-Risk Findings (reported as `warn`, not auto-fixed)

- Claude settings language is Chinese
- Active input method is Pinyin / SCIM
- Google DNS whoami returns Cloudflare Asia PoP
- IP quality uncertain but not flagged
- Shell history contains China domain references
- System measurement units / time format mismatch

## Privacy Rules

- Never print passwords, tokens, private keys, or subscription secrets
- Never dump full secret-bearing config files
- Summaries must redact sensitive values as `***`
- Remote deployment logs are sanitized before output

## Cross-Platform Notes

- **macOS**: fullest inspection and repair support
- **Linux**: inspection support is broader than repair support
- **Windows**: inspection support exists for selected checks, repair support is limited

Do not promise full parity across platforms unless the implementation actually has it.

## Architecture

```
scripts/
├── cc_check.py        # Main orchestrator & CLI
├── ip_quality.py      # Multi-channel IP quality assessment
├── platform_ops.py    # Cross-platform abstraction layer
└── scoring.py         # 100-point scoring system
```

## References

- Audit matrix and grouped checks: `references/check-matrix.md`
- Repair rationale and low-risk exceptions: `references/rationale.md`
