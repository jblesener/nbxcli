---
layout: default
title: Authenticate with NetBox
---

# Authenticate with NetBox

Start an interactive login to create a NetBox token and save it under a named profile:

```sh
nbxcli auth login
```

The prompt collects the profile name, NetBox URL, username, and password. The token is stored in the operating-system credential manager; the local configuration contains only the URL, token version, TLS setting, and selected profile.

<div class="callout">
Use the insecure TLS retry only for a trusted private environment. Certificate verification remains enabled by default.
</div>

## Profiles

Use profiles to separate environments and switch the default target:

```sh
nbxcli auth profile list
nbxcli auth profile show production --output json
nbxcli auth profile use production
```

Most resource commands accept `--profile NAME`, so an explicit target can be used without changing the current profile.

## Token handling

`auth token show` writes only the saved token plus a newline, which makes it suitable for carefully controlled scripts:

```sh
nbxcli auth token show --profile production
```

Treat that output as a secret. It is never printed by interactive login. Use the token lifecycle commands in the [command reference](reference/nbxcli_auth_token.html) to rotate or revoke compatible saved tokens; they require confirmation unless `--yes` is supplied.
