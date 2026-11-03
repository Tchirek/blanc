# Compatibility

## NOIR input

BLANC reads `report.json` from a NOIR scan. It uses `device`, and for each app:
`package`, `uid`, `system`, `sharedUid`, `category`, `score`, `dataTypes`,
`permissions` and `endpoints`. `dataTypes` is preferred; when it is empty,
BLANC derives data classes from the granted permissions.

Endpoints are reduced to hosts. IP literals, localhost, test/staging hosts and
documentation/infrastructure hosts are ignored. The manifest records what was
ignored and why. Endpoint paths are kept as evidence; unknown hosts with
upload-looking paths are listed in `review-endpoints.txt`. Path alone never
promotes an unknown host to tracker.

Policy data types and categories accept NOIR's Chinese labels or stable slugs.

## Mihomo

`mihomo.rules.yaml` contains logical rules:

```text
AND,((PROCESS-NAME,com.example.app),(DOMAIN-SUFFIX,tracker.example)),REJECT
```

- Use Mihomo/Clash Meta for Android with TUN enabled and
  `find-process-mode: always`. Package-name matching depends on the client's
  process resolver.
- Logical `AND` rules must be in the main `rules:` list. A rule-provider expands
  into that list; it cannot be nested inside an `AND`.
- `mihomo-provider.yaml` is only the global domain part. It is valid as a
  classical provider, but app-scoped rules still need to be pasted inline.
- The rules only emit `REJECT`. They do not define proxy groups or DNS.

## sing-box

`singbox.json` is a source rule-set, version 3, requiring sing-box 1.11+.
Each host is emitted twice: `domain` for the exact host and `.host` in
`domain_suffix` for subdomains, so the bare host matches across sing-box
versions. Each app rule matches `package_name` **and** the domain group;
separate fields in a sing-box rule are conjunctive, while domain fields inside
the group are OR. `singbox-route.json` rejects the rule-set with
`action: reject`.

The `path` in the route fragment is `./blanc-out/singbox.json`, relative to the
sing-box config. Move or rewrite it if your directory layout differs.

## DNS filters

`adguard.txt`, `hosts.txt` and `global-domains.txt` contain only global domains.
They are empty by default. DNS filters cannot express app scope, so enabling
`compile.globalize` intentionally trades precision for broad coverage. Functional
signals are still excluded.

## Quarantine scripts

`quarantine.sh` is a plain shell script for the host, not a daemon. It requires
Android platform-tools and an already authorized device. It uses:

- `cmd netpolicy add restrict-background-blacklist <uid>` (metered background);
- optional `cmd appops set <pkg> RUN_IN_BACKGROUND ignore`;
- optional `am force-stop <pkg>`.

`rollback.sh` reverses the netpolicy and appops changes. Force-stop needs no
rollback. `restrict-background-blacklist` is a platform shell command, not a
public app API; behavior varies by OEM and Android version. It is not a firewall.
For hardcoded IPs, foreground traffic or vendor system services, it is not
enough.

## Deliberate non-goals

- **No scanner.** NOIR owns discovery. BLANC does not pull APKs or run dumpsys.
- **No daemon, TUI or HTTP server.** The generated rule file is the interface.
- **No automatic Private DNS changes.** Private DNS is global, has no app scope,
  and can strand a device without connectivity.
- **No `.srs` / `.mrs` binary compilation.** Source rules are auditable and the
  consumers compile them. Binary formats add coupling and hide the decisions.
- **No root, VPN or firewall.** This is a small graft on NOIR, not a replacement
  for a trusted device.

## Limits

The report is static evidence, not proof of transmission. Vendor-preinstalled
services, lower-level frameworks, baseband and system processes can report data
outside the APK view. A blocked URL is not privacy.
