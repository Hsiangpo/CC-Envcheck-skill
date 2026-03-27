# CC-check Rationale

## Why this skill exists

This skill exists to turn an ad hoc Claude/Clash/VPN anti-detect workflow into one repeatable workflow that can be reused on different Macs.

## Important repair logic

### Actual DNS vs displayed DNS are different problems

`scutil --dns` or `networksetup -getdnsservers` may show a suspicious resolver even when actual DNS requests are already being hijacked and proxied correctly by Clash Verge.

Treat these as separate checks:

- Actual DNS path:
  - authoritative for real leakage risk
- Displayed DNS path:
  - important for hygiene and consistency
  - can be repaired without changing the working proxy chain

### Why the skill does not auto-fix every warning

Some findings were proven to be low-risk or preference-sensitive:

- Claude settings language
- active Chinese IME
- Google DNS anycast PoP outside the US, when the resolver is still Cloudflare/DoH rather than China ISP DNS

These are reported, but not changed by default.

### Why VPN deploy logs must be redacted

The VPN project contains:

- SSH host credentials
- panel credentials
- Shadowsocks passwords

The skill may use those files locally, but normal output must never expose them.

## Current stable end-state

The stable end-state this skill is trying to preserve is:

- public egress aligned with the active GPTeam host
- actual DNS path no longer routed through China ISP resolvers
- Clash Verge runtime config contains hardened DNS/TUN settings
- public subscription serves the hardened config
- active remote listener on `8388` belongs to Xray `gpteam-ss`
- system DNS display no longer shows `114.114.114.114`
