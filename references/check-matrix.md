# CC-check Matrix

This file groups the audit surface that `CC-check` should cover.

## Network

- Public egress IP
- IP geo alignment
- IP quality classification from multiple reputable channels
- DNS actual path
- DNS display path
- proxy env vars
- IPv6 consistency
- public subscription URL freshness

## System

- `TZ`
- locale and `LC_*`
- macOS language preference
- active input method
- `hostname`
- `/etc/hosts` cleanliness

## Node / package manager

- Node timezone
- Node locale
- npm proxy
- registry sanity
- absence of China-specific mirrors when they are unintended

## Privacy / telemetry

- Claude telemetry residue
- Claude session residue
- telemetry disable flags
- nonessential traffic disable flag

## Identity

- global git user.name / user.email
- shell history for obvious China-only remnants

## Clash Verge

- process running
- runtime mode is not `direct`
- selected proxy group points to expected node
- runtime config contains `dns-hijack`
- runtime config contains `respect-rules`
- runtime config contains `proxy-server-nameserver`
- runtime config contains expected `hosts`
- system DNS display cleanup watchdog installed

## VPN project and remote state

- detected VPN repo exists
- unit tests pass
- generated subscription contains the hardened DNS/TUN config
- public subscription matches hardened output
- deploy script points to the active host and expected SSH port
- remote VPN service is active
- remote `8388` is owned by Xray, not legacy `ss-server`
