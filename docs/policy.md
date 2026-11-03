# Policy

`blanc init` writes the default policy. `blanc compile` accepts `--policy`; when
omitted, the compiled-in default is used. Unknown fields, unknown data types and
invalid packages/domains are rejected rather than ignored.

## Defaults

- App scope: a tracker is blocked only for the app that was seen carrying it.
- Functional signals win: `push`, `login`, `update`, `pay`, `cloud`, `sync`,
  `oauth`, `firebase`, `googleapis` and similar hosts are allow.
- Unknown hosts are review. They are visible in `SUMMARY.md`,
  `review-endpoints.txt` and the manifest, but never emitted as rules.
- A tracker is blocked only when the app has sensitive data or a sensitive
  category. This is the `sensitive` gate.
- System apps are compiled, but excluded from quarantine scripts by default.
- Shared UIDs are excluded from quarantine scripts by default.

## Fields

```yaml
version: 1

compile:
  globalize: none
  include_system: true

sensitive:
  require: true
  data_types: [location, contacts, sms, calls, mic, camera, screen, apps, identity, files, calendar, accounts]
  categories: [telemetry, ads, location, security, system]
  min_score: 0

apps:
  com.example.reader: allow
  com.example.shop:
    mode: block
    block: [qa.analytics.widgets.cn]
    allow: [login.widgets.cn]

domains:
  shared.analytics.widgets.cn: allow
  consent.analytics.widgets.cn:
    action: block

quarantine:
  min_blocked_domains: 1
  include_system: false
  include_shared_uid: false
  background_restrict: true
  appops_background: false
  force_stop: true
```

`compile.globalize`:

- `none` — no global rules; DNS lists are empty. This is the default.
- `trackers` — tracker blocks also become global domain blocks.
- `all` — every block also becomes a global domain block. Use with care.

`sensitive.require: false` blocks every tracker regardless of the app's data
types. `sensitive.min_score` gates automatic blocks by NOIR's score; explicit
app/domain overrides still win.

Data type and category values accept either the slugs above or NOIR's Chinese
labels (`位置`, `通讯录`, `遥测/统计`, …).

`apps` overrides:

- scalar: `allow`, `review`, `block` (block applies to tracker findings only);
- mapping: `mode`, `block` (scoped blocklist), `allow` (scoped allowlist).

`domains` overrides are global:

- scalar: `allow`, `review`, `block`;
- mapping: `action`.

## Precedence

1. `domains.<host>: allow`
2. `domains.<host>: review`
3. `domains.<host>: block` (global)
4. app `allow` list
5. app `block` list
6. app mode `allow` / `review`
7. functional endpoint allow
8. app mode `block` (trackers only)
9. system and `min_score` gates
10. tracker block when sensitive (or when `require` is false)
11. review otherwise

A global `domains` block wins over a scoped app allow. Use an app `block` list
when precision matters.

## Decisions

`decisions.json` exists so findings can be overridden without rewriting YAML:

```json
{
  "version": 1,
  "decisions": {
    "com.nightmarket.shop|alog.umeng.com": "allow",
    "jp.quietreader.app|api.quietreader.jp": "block"
  }
}
```

Pass it with `blanc compile --decisions <file>`. Global findings are locked:
a scoped decision cannot undo a global rule. Edit the policy instead.

## Quarantine

The quarantine section only controls the optional scripts. BLANC never calls
ADB, never changes Private DNS, and never uninstalls anything.

- `min_blocked_domains` — minimum number of blocked domains for a candidate.
- `include_system` — allow system apps in `quarantine-plan.json`; rollback is
  still generated.
- `include_shared_uid` — allow apps sharing a UID. The restriction then affects
  the whole UID, not one package.
- `background_restrict` — emit `cmd netpolicy add restrict-background-blacklist`.
  This affects metered background traffic only.
- `appops_background` — optionally emit `RUN_IN_BACKGROUND ignore`; this can
  break notifications.
- `force_stop` — optionally emit `am force-stop`.

Set all three actions to `false` to disable quarantine output. Review both
scripts before running them.
