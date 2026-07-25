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

To display a saved token, invoke the explicit reveal command and confirm the warning:

```sh
nbxcli auth token show
```

Tokens are never printed by `auth login`. Re-running login for a profile creates another token in NetBox and replaces only the token held locally by `nbxcli`.

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

## License

This project is licensed under the [MIT License](LICENSE).
Copyright © 2026 John Blesener.
