# Policy

`blanc.yaml` is optional. Without it, BLANC rejects every host in NOIR's
`domains-trackers.txt` (and its subdomains) for every app. The policy only
adds exceptions and extra blocks. `blanc compile` picks up `./blanc.yaml`
automatically; `--policy` loads another file. Unknown fields and invalid
domains are rejected with the file name and line.

## Fields

```yaml
version: 2

allow: [umeng.com]            # never block these, for any app
block: [api.example.cn]       # block these for every app

apps:
  com.example.bank: allow     # exempt one app from every block
  com.example.shop:
    allow: [login.example.cn] # exempt hosts for this app only
    block: [ads.example.cn]   # extra blocks for this app only
```

Every domain entry covers the host and all of its subdomains. A leading `+.`
is accepted and ignored. `allow: all` is the long form of `<package>: allow`.

## Precedence

For a connection from app `P` to host `H`, the first tier that has an
opinion decides:

1. `apps.P.allow` / `apps.P.block`: the longest entry covering `H` wins.
2. `apps.P: allow` (allow all).
3. Global `allow` / `block`: the longest entry covering `H` wins.
4. NOIR: the longest listed host covering `H` wins. A tracker blocks; a
   functional or review host does not.
5. Anything else is not blocked.

So an app entry beats a global entry, a global entry beats NOIR, and a more
specific domain beats a broader one inside the same tier. The same domain in
both `allow` and `block` of one tier is an error.

`blanc explain <host> --app <package>` prints the tier and entry that decided,
the rule that implements it and the line to add to change it.

## How exceptions become rules

Exceptions are folded into the reject rules instead of being emitted as
`DIRECT` rules, so they never override your own proxy routing:

```yaml
- DOMAIN-SUFFIX,alog.umeng.com,REJECT
- AND,((DOMAIN-SUFFIX,metrics.example.jp),(NOT,((PROCESS-NAME,com.example.reader)))),REJECT
- AND,((DOMAIN-SUFFIX,ads.example.cn),(PROCESS-NAME,com.example.shop)),REJECT
```

Rules without app names work without process matching, on desktop too. Rules
that name apps need the Android client's VPN/TUN mode and `find-process-mode`
other than `off`.

## Shared UIDs

Android attributes traffic to a UID, not a package. Packages that share a UID
(`sharedUid`, for example `android.uid.system`) cannot be told apart: Mihomo
sees one name for the UID and sing-box matches every package on it. When the
NOIR report marks a package in `apps:` as shared, BLANC ignores that entry and
says so; use a global `allow` or `block` instead.

## Version 1

Version 1 blocked a tracker only inside apps that held "sensitive"
permissions, which left trackers open everywhere else. It is rejected with a
migration hint: delete `sensitive` and `include_system`, turn `mode: allow`
into `<package>: allow`, keep the `allow`/`block` lists and set `version: 2`.
