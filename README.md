<p align="center">
  <img src="docs/banner.svg" alt="BLANC" width="100%">
</p>

<h1 align="center">BLANC</h1>

<p align="center"><em>noir2rules: a modern anti-telescreen tool to block telemetry and data exfiltration URLs.</em></p>

<p align="center">
  <a href="LICENSE"><img alt="MIT" src="https://img.shields.io/badge/license-MIT-111111"></a>
  <img alt="Go" src="https://img.shields.io/badge/Go-1.24+-111111">
  <img alt="status" src="https://img.shields.io/badge/status-unreleased-111111">
</p>

<p align="center">
  <img src="docs/ai-slop-67.svg" alt="AI-slop Of The Day #67" width="250" height="55">
  &nbsp;
  <img src="docs/trendshit-69.svg" alt="TRENDSHIT #69 Repository Of The Day" width="250" height="55">
</p>

BLANC is a small companion to [NOIR](https://github.com/Verlintas/NOIR). It turns a
NOIR scan into Mihomo and sing-box reject rules, checks that your proxy config
actually applies them, and tells you why a host is blocked when an app breaks.
It does not scan, run as a daemon, or touch the device.

What it adds over importing NOIR's `domains-trackers.txt` by hand:

- **Every tracker, every app.** Each NOIR tracker host and its subdomains are
  rejected for all apps, including apps the scan never saw.
- **Exceptions without side effects.** "Allow this tracker for my bank app" is
  folded into the reject rule (`AND … NOT PROCESS-NAME …`), so it never
  overrides your own `DIRECT`/`PROXY` routing.
- **Survives real NOIR output.** Template URLs such as `%s.umeng.com` and URL
  noise such as `host)` or `user@host` are skipped or trimmed, never fatal.
- **A doctor that knows why rules silently fail:** rule order, missing
  sniffer/fake-ip (HTTPDNS apps bypass domain rules), sing-box `reject` placed
  before `sniff`, process matching turned off.
- **`blanc explain`** answers "why is this blocked" and prints the line to add.

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

On Windows, use `-o blanc.exe`. Go 1.24+. No CGO, no runtime. The only direct
dependency is `gopkg.in/yaml.v3`.

## Quick start

```sh
noir scan --out noir-out
blanc compile
blanc doctor --config ~/.config/mihomo/config.yaml
```

`compile` reads `noir-out/` (`report.json` plus `domains-trackers.txt`,
`domains-functional.txt`, `domains-other.txt`) and `./blanc.yaml` if present,
and writes `blanc-out/`. Use `--noir <dir>`, `--policy <file>` and
`--out <dir>` to change the paths. `report.json` is optional; without it,
shared-UID packages cannot be detected and `SUMMARY.md` has no per-app
evidence.

No `blanc.yaml` is needed to start. When an app breaks:

```sh
blanc explain push.example.cn --app com.example.bank
```

It prints the verdict, the entry that decided it, the rule that implements it
and the `blanc.yaml` lines that change it. Add them, run `blanc compile` again.

## Output

| file | use |
|---|---|
| `mihomo.rules.yaml` | paste at the top of `rules:` |
| `singbox.json` | source rule-set, version 3 |
| `singbox-route.json` | route fragment: `sniff`, then `reject` the rule-set |
| `SUMMARY.md` | rules, exceptions, notes, which scanned apps use which hosts |
| `manifest.json` | full evidence, decisions, input hashes |

## Mihomo

Paste the entries from `mihomo.rules.yaml` at the top of `rules:`, before
`GEOSITE,cn`, `GEOIP`, `MATCH` and before any `PROCESS-NAME` routing:

```yaml
sniffer:
  enable: true
  parse-pure-ip: true
  sniff:
    TLS: {ports: [443, 8443]}
    HTTP: {ports: [80, 8080-8880]}
    QUIC: {ports: [443]}
rules:
  - DOMAIN-SUFFIX,alog.umeng.com,REJECT
  - AND,((DOMAIN-SUFFIX,metrics.example.jp),(NOT,((PROCESS-NAME,com.example.reader)))),REJECT
  - GEOSITE,cn,DIRECT
  - MATCH,PROXY
```

The rules match domain names, so the core must know them. Many apps resolve
through HTTPDNS or connect to hard-coded IPs; only the sniffer recovers those.
`fake-ip` DNS alone covers apps that use the system resolver.

Rules that name an app need process matching: on Android, the client's
VPN/TUN mode and `find-process-mode` other than `off` (the default `strict` is
fine). Rules without app names also work on desktop.

## sing-box 1.11+

Merge `singbox-route.json` into `route`:

```json
{
  "route": {
    "rule_set": [
      { "tag": "blanc", "type": "local", "format": "source", "path": "./blanc-out/singbox.json" }
    ],
    "rules": [
      { "action": "sniff" },
      { "rule_set": "blanc", "action": "reject" }
    ]
  }
}
```

The `reject` rule must come **after** a `sniff` rule: before sniffing, TUN
connections are bare IPs and no domain rule can match. Keep a single `sniff`
rule, and keep `reject` before any rule that routes the same traffic. The
`path` follows `--out`; rewrite it if the rule-set lives elsewhere on the
device.

`singbox.json` writes each host twice, `domain` for the host and `.host` in
`domain_suffix` for its subdomains; one field alone misses one of the two.

## Doctor

```sh
blanc doctor --config config.yaml   # Mihomo
blanc doctor --config config.json   # sing-box
```

The format is detected from the file. Checks:

- the BLANC rules are present and current (Mihomo) or the rule-set is
  referenced and rejected (sing-box);
- no earlier rule takes BLANC's traffic. Mihomo `DOMAIN*`, `PROCESS-NAME`,
  `AND/OR/NOT` and `MATCH` rules are evaluated against BLANC's domains and
  apps; `GEOSITE`, `GEOIP` without `no-resolve`, `RULE-SET` and port rules are
  reported as risks;
- domain names are visible: sniffer with TLS/QUIC and `parse-pure-ip`, or
  fake-ip; for sing-box, a `sniff` rule before BLANC;
- process matching and TUN, only when some rule names an app.

It exits non-zero on a `fail`. It cannot expand rule providers or GEOSITE
data, and a client app can override DNS and sniffer settings outside the file.

## Policy

```yaml
version: 2
allow: [umeng.com]            # never block, any app
block: [api.example.cn]       # block for every app
apps:
  com.example.bank: allow     # exempt one app from every block
  com.example.shop:
    allow: [login.example.cn] # exceptions for one app
    block: [ads.example.cn]   # extra blocks for one app
```

App entries beat global entries, global entries beat NOIR, and the longest
matching domain wins within a tier. Packages that share a UID cannot be told
apart by any proxy, so their `apps:` entries are ignored with a warning. See
[docs/policy.md](docs/policy.md) and [examples/blanc.yaml](examples/blanc.yaml).

## Notes

- BLANC never phones home.
- NOIR reports contain package names and domains. Review before sharing.
- NOIR exports only hosts of upload-looking URLs, so most endpoints in
  `report.json` are outside the export; that is expected.
- Rescan when apps change; rules are static evidence applied to a static report.
- This is a compiler for NOIR, not a replacement for a trusted device.
- Upstream: [Verlintas/NOIR](https://github.com/Verlintas/NOIR), MIT.

## Why Go

The proxies are Go and a single static binary is enough. The rule files are
deterministic; the manifest records a timestamp and input hashes. There is
deliberately no TUI, daemon or server: the rule file, the doctor and `explain`
are the interface.

<p align="center"><sub>MIT · made for people who prefer a quiet phone</sub></p>
