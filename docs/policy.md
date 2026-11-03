# Policy

`blanc init` writes the default. `blanc compile --policy` loads a different file.
Unknown fields, unknown data types and invalid domains are rejected.

## Authority

Host classification comes from NOIR's `domains-trackers.txt`,
`domains-functional.txt` and `domains-other.txt`. BLANC does not classify again.
A host that is not in those files is ignored unless an app `block` list names it
explicitly.

## Defaults

- App scope: a tracker is rejected only for the app that carries it.
- Functional hosts from NOIR are allowed.
- Review hosts from NOIR are review.
- A tracker is blocked only when the app has a sensitive data capability or a
  sensitive category.
- System apps are included by default; set `include_system: false` to review
  their tracker hits instead.

## Fields

```yaml
version: 1

sensitive:
  data_types: [location, contacts, sms, calls, mic, camera, screen, apps, identity, files, calendar, accounts]
  categories: [telemetry, ads, location, security, system]

include_system: true

apps:
  com.example.reader:
    mode: allow
  com.example.shop:
    mode: block
    allow: [login.widgets.cn]
    block: [qa.analytics.widgets.cn]
```

`data_types` and `categories` accept the slugs above or NOIR's Chinese labels
(`位置`, `通讯录`, `遥测/统计`, …).

`apps` is optional. A scalar is shorthand for `mode`:

- `mode: allow` — allow all hosts not covered by the app `block` list.
- `mode: review` — review all hosts not covered by the app allow/block lists.
- `mode: block` — block tracker-classified hosts not covered by the app allow/block lists; functional/review stay put.
- `allow` — app-scoped allowlist, wins over everything else.
- `block` — app-scoped blocklist, wins over mode and can block a host that NOIR
  did not classify.

`allow` and `block` cannot contain the same host.

## Precedence

1. app `allow` list
2. app `block` list
3. app mode `allow`
4. app mode `review`
5. NOIR functional
6. NOIR review / unclassified
7. app mode `block` (trackers only)
8. `include_system` filter
9. tracker + sensitive app capability → block
10. tracker without sensitive capability → review

The reason on every block is either `app blocklist`, `app mode block`, or
`tracker + app capability: data:<slug>` / `category:<slug>`. The last form is an
app-capability statement, not a claim that this particular host received that
data.
