# Complete Core CRUD and Profile Management

## Summary

Complete the CLI's generic first-party NetBox workflows with JSON-backed create,
update, and delete operations, plus lifecycle management for saved profiles.
Keep tokens in the OS credential store and retain the current resource-discovery
and table/JSON output conventions.

## Key Changes

- Add `create`, `update`, and `delete` commands for individual discovered
  resources. Create and update accept a JSON object inline or from an
  `@`-prefixed file path.
- Use `POST`, `PATCH`, and `DELETE` against the resource collection/detail
  endpoints. Updates first fetch the detail record and require its ETag, then
  submit it as `If-Match`; instances without ETag support fail safely.
- Require a delete confirmation unless `--yes` is supplied; reject an
  unconfirmed non-interactive delete.
- Add `auth profile list`, `show`, `use`, and `remove` commands. Profile output
  contains non-secret metadata only. Removing a current profile clears it and
  cleans up the stored token after configuration is safely persisted.
- Document payload usage, ETag conflict behavior, delete safety, and profile
  commands in the README.

## Test Plan

- Cover command parsing, inline/file payload validation, output modes, delete
  confirmations, and secret-safe profile output.
- Cover client HTTP methods, authentication, JSON payloads, ETag preflight and
  conflicts, deletes, and API errors.
- Cover profile selection/removal and configuration/keychain failure paths.
- Run `go test ./...`.

## Assumptions

- The milestone targets one record per mutation; bulk operations are deferred.
- Updates are partial `PATCH` requests.
- Only first-party resources discovered by the existing command are mutable.
