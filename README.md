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

## Development

With Node.js 24 or later installed, enable the commit-message hook once:

```sh
npm install
```

Commits follow the Conventional Commits format, for example `fix: handle empty API responses` or `feat(auth): support profile import`. Pull requests validate every commit message. Merges to `main` automatically create GitHub releases from eligible commits using unprefixed semantic-version tags such as `1.0.0`.

## Authenticate

```sh
nbxcli auth login
```

The command prompts for a profile name, NetBox URL, username, and password. It calls NetBox's token-provisioning endpoint, saves the token in the operating system credential store, and saves only non-secret connection settings under the OS user config directory.

If certificate validation fails, login can explicitly retry without verification for that profile. This should be used only with a trusted private development environment.

To write a saved token for use in a script, invoke the explicit reveal command:

```sh
nbxcli auth token show --profile production
```

The command writes only the token and a trailing newline to standard output. Treat its output as a secret. Tokens are never printed by `auth login`. Re-running login for a profile creates another token in NetBox and replaces only the token held locally by `nbxcli`.

Rotate a saved v2 token without exposing it. The replacement is stored before
the prior remote token is revoked; if the final revocation fails, the new token
remains usable and the command reports that the old token still needs cleanup.

```sh
nbxcli auth token rotate --profile production
nbxcli auth token rotate --profile production --yes
```

Revoke a saved v2 token remotely and remove its local profile and keychain
credential. Both lifecycle commands prompt before revoking a token, or require
`--yes` when standard input is non-interactive. Legacy v1 tokens cannot be
identified safely for lifecycle actions; log in again to create a v2 token.

```sh
nbxcli auth token revoke --profile retired-lab
```

## Query NetBox resources

List the first-party model resources exposed by the current NetBox instance:

```sh
nbxcli resources
```

Query a resource using its `application.resource` name:

```sh
nbxcli get dcim.devices --search edge --filter site=tokyo --limit 25
nbxcli get ipam.prefixes 42
```

The default output is a compact `ID`, `DISPLAY`, and `STATUS` table. Use `--output json` for complete API records suitable for scripts. Add `--profile NAME` to query a saved profile other than the current one; repeat `--filter key=value` to pass additional NetBox list filters through to the API. List-only flags (`--search`, `--filter`, and `--limit`) cannot be used when retrieving an individual record.

## Manage NetBox resources

Create a resource with an inline JSON object or a JSON file prefixed with `@`:

```sh
nbxcli create dcim.devices --data '{"name":"leaf-01","device_type":12,"role":4,"site":3}'
nbxcli create ipam.prefixes --data @prefix.json --output json
```

Apply a partial update to one record:

```sh
nbxcli update dcim.devices 42 --data '{"status":"active"}'
```

Updates first read the record and use its NetBox ETag to prevent overwriting a
concurrent change. An instance that does not return ETags cannot be updated by
this command.

Delete one record after a confirmation prompt. Use `--yes` only when an
automation workflow has made the deletion intentional:

```sh
nbxcli delete dcim.devices 42
nbxcli delete dcim.devices 42 --yes
```

Creation and updates use the same `--output table|json` formatting as `get`.
All mutation commands target one resource at a time and support only the
first-party resources listed by `nbxcli resources`.

## Manage profiles

Saved profile metadata never includes the token. Inspect and switch profiles
without logging in again:

```sh
nbxcli auth profile list
nbxcli auth profile show production --output json
nbxcli auth profile use production
```

Remove a profile and its OS-keychain token with a confirmation prompt (or
explicitly use `--yes` for automation):

```sh
nbxcli auth profile remove retired-lab
```

## License

This project is licensed under the [MIT License](LICENSE).
Copyright © 2026 John Blesener.
