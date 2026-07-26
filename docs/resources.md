---
layout: default
title: Query and manage resources
---

# Query and manage resources

First, ask the connected NetBox instance which first-party resources are available:

```sh
nbxcli resources
```

Use the returned `application.resource` name for all resource commands.

## Read records

```sh
nbxcli get dcim.devices --search edge --filter site=tokyo --limit 25
nbxcli get ipam.prefixes 42
```

Lists support free-text search, repeatable `--filter key=value`, and a positive result limit. When retrieving a single ID, list-only flags are rejected. Add `--output json` to receive complete API records.

## Create and update

Supply a JSON object inline or a path prefixed with `@`:

```sh
nbxcli create dcim.devices --data '{"name":"leaf-01","device_type":12,"role":4,"site":3}'
nbxcli update dcim.devices 42 --data @device-update.json --output json
```

Updates are partial `PATCH` requests. nbxcli reads the record first and uses its ETag to protect against overwriting a concurrent change. An instance without ETag support cannot be updated through this command.

## Delete

Deletion is intentionally interactive:

```sh
nbxcli delete dcim.devices 42
nbxcli delete dcim.devices 42 --yes
```

Use `--yes` only after the target has been established by your automation. Mutations always address one discovered first-party resource at a time.
