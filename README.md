<p align="center">
  <img src="docs/banner.svg" alt="BLANC — white noise for Android telemetry" width="100%">
</p>

<h1 align="center">BLANC</h1>

<p align="center"><em>a modern anti-telescreen tool to block telemetry and data exfiltration URLs.</em></p>

<p align="center">
  <a href="LICENSE"><img alt="MIT" src="https://img.shields.io/badge/license-MIT-111111"></a>
  <img alt="Go" src="https://img.shields.io/badge/Go-1.24+-111111">
  <img alt="status" src="https://img.shields.io/badge/status-alpha-8a8a8a">
</p>

BLANC turns a [NOIR](https://github.com/Verlintas/NOIR) audit into app-scoped block rules for Mihomo, sing-box and DNS filters, then offers a reversible ADB quarantine for the worst offenders.

This README is intentionally short. The code, tests, and generated manifest are the documentation.

> [!WARNING]
> BLANC is not a telescreen-proof phone, and a blocked domain is not privacy.
> NOIR only sees what is visible in APKs; it cannot see vendor-preinstalled
> system services, lower-level frameworks, baseband, or system processes that
> report data. Rules can also break apps. If you need real assurance, move to a
> trusted device and a trusted operating system as soon as you can.

## Build

```sh
git clone <this-repo> blanc
cd blanc
go build -trimpath -o blanc ./cmd/blanc
```

Requires Go 1.24+. No CGO, no external runtime.

## Quick start

```sh
noir scan --out noir-out
./blanc init
./blanc compile --report noir-out/report.json --policy blanc.yaml --out blanc-out
./blanc serve --dir blanc-out --lan
```

`blanc compile` writes:

| file | use |
|---|---|
| `singbox.json` | app-scoped source rule-set (sing-box 1.11+) |
| `singbox-route.json` | route fragment that rejects the rule-set |
| `mihomo.rules.yaml` | logical rules to paste into Mihomo's `rules:` |
| `mihomo-provider.yaml` | global domains, importable as a classical rule-provider |
| `adguard.txt`, `hosts.txt` | global DNS filters |
| `blocked-domains.txt` | every blocked domain, app scope discarded |
| `manifest.json` | decisions, evidence, hashes, quarantine plan |
| `SUMMARY.md` | the short human-readable version |

The default policy is **app-scoped**: a tracker is rejected only for the app that
was caught carrying it. DNS filters cannot express app scope; they stay empty
until you set `compile.globalize` in `blanc.yaml`. Read `docs/policy.md` before
you do.

## Commands

| command | purpose |
|---|---|
| `blanc init` | write a commented `blanc.yaml` |
| `blanc compile` | audit → rules, lists and manifest |
| `blanc tui` | review and override decisions in the terminal |
| `blanc serve` | serve rules over LAN with a QR code and hot rebuild |
| `blanc arm` | restrict background data for selected apps over ADB |
| `blanc disarm` | undo the latest arm journal |

`arm` only uses `cmd netpolicy` and never edits Private DNS, appops, or
uninstalls anything. The plan is printed before execution; `--apply` is
required. Shared-UID and system apps are skipped unless you opt in.

## Import

Mihomo (Android, TUN mode, `find-process-mode: always`):

```yaml
rule-providers:
  blanc:
    type: file
    behavior: classical
    path: ./blanc/mihomo-provider.yaml

rules:
  - RULE-SET,blanc,REJECT
  # paste the entries from mihomo.rules.yaml here
  - MATCH,DIRECT
```

sing-box:

```json
{
  "route": {
    "rule_set": [
      {
        "tag": "blanc",
        "type": "local",
        "format": "source",
        "path": "./blanc/singbox.json"
      }
    ],
    "rules": [{ "rule_set": "blanc", "action": "reject" }]
  }
}
```

AdGuard Home / NextDNS: import `adguard.txt` or `hosts.txt`. This blocks the
domains for every app, so it is opt-in.

## Why Go

The proxies are Go, the single binary is Go, and the ADB client speaks the
server protocol directly instead of spawning a process per command. The TUI is
[Bubble Tea](https://github.com/charmbracelet/bubbletea); the rest is standard
library.

## Notes

- BLANC never phones home.
- Reports contain package names, UIDs and domains. Review before sharing.
- `serve --lan` exposes those rules to your local network. Use `--token`.
- The generated rules are only as good as the NOIR report they came from.
- Upstream: [Verlintas/NOIR](https://github.com/Verlintas/NOIR), MIT.

<p align="center">
  <a href="https://trendshift.io"><img src="docs/ai-slop-67.svg" alt="AI-slop Of The Day #67" width="250"></a>
</p>

<p align="center"><sub>MIT · made for people who prefer a quiet phone</sub></p>
