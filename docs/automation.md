---
layout: default
title: Automation and safety
---

# Automation and safety

## Prefer JSON for scripts

Tables are intended for people. Add `--output json` when another program consumes results:

```sh
nbxcli get dcim.devices --filter site=tokyo --output json
nbxcli auth profile show production --output json
```

Resource filters are passed through to NetBox, so validate external input before constructing a command line.

## Make the target explicit

Use `--profile` in automation rather than relying on the interactive user's current profile:

```sh
nbxcli get ipam.prefixes --profile production --output json
```

For mutations, use a specific resource and record ID. `delete`, token rotation, and token revocation refuse non-interactive execution unless the relevant `--yes` flag is supplied.

## Keep secrets out of logs

Only `auth token show` intentionally writes a token. Avoid command substitution, shell tracing, terminal history, and CI logs around it. Prefer your CI system's secret storage and pass credentials only where their output cannot be captured.

## Review changes before applying them

For updates, keep JSON payloads in reviewed files and use ETag conflicts as a signal to re-read the latest record before retrying. For destructive operations, consider querying the target in JSON first, then supply its confirmed ID with `--yes`.
