---
layout: default
title: NetBox from the terminal
description: Install, authenticate, query, and safely manage NetBox resources with nbxcli.
---

<p class="eyebrow">NetBox command-line client</p>

# NetBox from the terminal, without losing the guardrails

<p class="lead">nbxcli stores API tokens in your operating system credential store and gives operators a focused interface for NetBox discovery, queries, and single-record changes.</p>

```sh
brew tap jblesener/tools
brew install nbxcli
nbxcli auth login
nbxcli resources
```

<div class="callout">
Tokens are never saved in the profile file. Commands that expose, remove, or change data require an explicit action and protect non-interactive use.
</div>

## Start here

- [Install nbxcli](installation.html) using Homebrew, Go, or a release archive.
- [Authenticate and manage profiles](authentication.html) without putting tokens in shell history.
- [Query and manage resources](resources.html) using NetBox `application.resource` names.
- Read [automation and safety guidance](automation.html) before using JSON output or mutation commands in scripts.

## What it supports

nbxcli discovers the first-party model resources offered by the connected NetBox instance. It lists and retrieves records, then creates, partially updates, or deletes one record at a time. Table output is optimized for a terminal; JSON output preserves complete API records for automation.

For every command and flag, use the generated [command reference](reference/).
