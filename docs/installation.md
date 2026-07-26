---
layout: default
title: Install nbxcli
---

# Install nbxcli

## Homebrew

Homebrew is the quickest supported installation path on macOS and Linux.

```sh
brew tap jblesener/tools
brew install nbxcli
```

## Go

With Go 1.24 or newer installed, install the latest release directly:

```sh
go install github.com/jblesener/nbxcli@latest
```

Ensure Go's binary directory is on your `PATH`, then confirm the installation:

```sh
nbxcli --help
```

## Release archives

[GitHub Releases](https://github.com/jblesener/nbxcli/releases) contain checksums and prebuilt archives for macOS, Linux, and Windows on the supported architectures. Download the archive matching your platform, verify it against `checksums.txt`, and place the extracted binary on your `PATH`.

## Build from source

To build a checkout:

```sh
git clone https://github.com/jblesener/nbxcli.git
cd nbxcli
go build ./...
```
