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

BLANC is a small companion to [NOIR](https://github.com/Verlintas/NOIR). NOIR finds the endpoints; BLANC turns them into app-scoped rules for Mihomo, sing-box and DNS filters. It does not scan, run as a daemon, or touch the device.

> [!WARNING]
> A blocked URL is not privacy. NOIR only sees what is visible in APKs; it
> cannot see vendor-preinstalled services, lower-level frameworks, baseband or
> system processes that report data. Rules can break apps. If you need real
> assurance, move to a trusted device and a trusted operating system as soon as
> you can.

## Build

```sh
go build -trimpath -o blanc ./cmd/blanc
```

Go 1.24+. No CGO, no runtime. The only direct dependency is `gopkg.in/yaml.v3`.

## Quick start

```sh
noir scan --out noir-out
./blanc init
./blanc compile --report noir-out/report.json --out blanc-out
```

Review `blanc-out/SUMMARY.md` and `blanc-out/manifest.json` before importing anything.

## Artifacts

| file | use |
|---|---|
| `singbox.json`, `singbox-route.json` | app-scoped source rule-set + route fragment |
| `mihomo.rules.yaml` | logical rules to paste into Mihomo's `rules:` |
| `mihomo-provider.yaml` | global domains only, importable as a classical provider |
| `adguard.txt`, `hosts.txt`, `global-domains.txt` | DNS fallback; empty by default |
| `quarantine.sh`, `rollback.sh`, `quarantine-plan.json` | optional, review before running |
| `manifest.json`, `SUMMARY.md`, `decisions.json` | decisions, evidence and hashes |
| `blocked-domains.txt`, `review-domains.txt`, `review-endpoints.txt` | audit lists |

The default is **app-scoped**: a tracker is rejected only for the app that was seen carrying it. `blocked-domains.txt` is the union of every block and loses app scope; do not import it blindly. DNS filters cannot express app scope. They stay empty until you set `compile.globalize` in `blanc.yaml`; at that point app scope is gone for those domains.

`review-domains.txt` lists tracker hits left in review. `review-endpoints.txt`
lists upload-looking endpoints that BLANC did not auto-block, including unknown
hosts. Both are for reading, not for import.

## Import

Mihomo (Android, TUN mode, `find-process-mode: always`): paste the entries from
`mihomo.rules.yaml` under your existing `rules:` key, before `MATCH`. Logical
`AND` rules work in the main list, not inside a rule-provider.

If you want auto-updating global domains only, add the provider:

```yaml
rule-providers:
  blanc:
    type: file
    behavior: classical
    path: ./blanc-out/mihomo-provider.yaml

rules:
  - RULE-SET,blanc,REJECT
  - MATCH,DIRECT
```

App-scoped entries still need to be pasted inline; the provider cannot express
the nested `AND` rules.

sing-box (1.11+):

```json
{
  "route": {
    "rule_set": [
      {
        "tag": "blanc",
        "type": "local",
        "format": "source",
        "path": "./blanc-out/singbox.json"
      }
    ],
    "rules": [{ "rule_set": "blanc", "action": "reject" }]
  }
}
```

AdGuard Home / NextDNS: set `compile.globalize: trackers`, then import `adguard.txt` or `hosts.txt`. `global-domains.txt` is the plain-domain form. This blocks the domains for every app.

## Policy

`blanc init` writes a commented `blanc.yaml`. The defaults are conservative:

- functional endpoints (push, login, update, payment, cloud sync) are never blocked automatically;
- unknown domains are review, not block;
- only apps with sensitive data or a sensitive category produce tracker blocks;
- domain overrides are global; app overrides are scoped.

See [docs/policy.md](docs/policy.md) for fields, precedence and examples, or
[examples/blanc.yaml](examples/blanc.yaml) for a fuller policy.
`blanc compile --decisions decisions.json` applies per-finding allow/block/review overrides without editing YAML.

## Optional quarantine

BLANC can write `quarantine.sh` and `rollback.sh` for apps with tracker hits. It never executes them, and it does not use root, Private DNS, a VPN or appops by default.

`quarantine.sh` uses `cmd netpolicy` to restrict **metered background** traffic and `am force-stop` to close the current process. It is not a firewall. System apps and shared UIDs are skipped unless the policy opts in. Read the script, then run it yourself; `rollback.sh` reverses the netpolicy changes. The scripts are POSIX `sh`; use Git Bash or WSL on Windows.

## Notes

- BLANC never phones home.
- NOIR reports contain package names, UIDs and domains. Review before sharing.
- Rules are static evidence applied to a static report; rescan when apps change.
- This is a compiler for NOIR, not a replacement for a trusted device.
- Upstream: [Verlintas/NOIR](https://github.com/Verlintas/NOIR), MIT.
- Compatibility details: [docs/compatibility.md](docs/compatibility.md).

## Why Go

The proxies are Go, the output is deterministic, and a single static binary is enough. There is deliberately no TUI, daemon or server: the rule file is the interface.

<p align="center">
  <a href="https://trendshift.io"><img src="docs/ai-slop-67.svg" alt="AI-slop Of The Day #67" width="250"></a>
</p>

<p align="center"><sub>MIT · made for people who prefer a quiet phone</sub></p>
