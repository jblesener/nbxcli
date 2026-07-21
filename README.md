# nbxcli

`nbxcli` is a command-line client for [NetBox](https://netbox.dev/). Its first feature securely provisions and stores a NetBox API token using an interactive login.

## Install

```sh
go install github.com/jblesener/nbxcli@latest
```

Or build from a checkout:

```sh
go build ./...
```

## Authenticate

```sh
nbxcli auth login
```

The command prompts for a profile name, NetBox URL, username, and password. It calls NetBox's token-provisioning endpoint, saves the token in the operating system credential store, and saves only non-secret connection settings under the OS user config directory.

If certificate validation fails, login can explicitly retry without verification for that profile. This should be used only with a trusted private development environment.

To display a saved token, invoke the explicit reveal command and confirm the warning:

```sh
nbxcli auth token show
```

Tokens are never printed by `auth login`. Re-running login for a profile creates another token in NetBox and replaces only the token held locally by `nbxcli`.
