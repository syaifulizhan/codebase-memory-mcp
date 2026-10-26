# About this fork

This repository is a hardened fork of
[DeusData/codebase-memory-mcp](https://github.com/DeusData/codebase-memory-mcp),
used under the original [MIT License](LICENSE). All credit for the project goes
to DeusData and its contributors. This fork is a drop-in replacement: same MCP
tools, same defaults, same purpose. It only adds secret-leak protection.

## What is different

| Area | Upstream | This fork |
|---|---|---|
| Secret files (`.env*`, `*.pem`, `*.key`, `id_rsa*`, `.npmrc`, `credentials.json`, `secrets.y*ml`, ...) | Indexed when tracked by git, so their contents can reach `search_code` / `get_code_snippet` | Never indexed. Templates (`.env.example`, `.sample`, `.template`, `.dist`) stay indexable |
| Hardcoded secrets in source files (private key blocks, cloud/SaaS API tokens, JWTs, `password = "..."` style literals) | Returned verbatim to agents | Replaced with `[REDACTED:<kind>]` before any source text is returned. Line structure is preserved. `CBM_NO_REDACT=1` disables it for debugging |
| `update` command | Replaces the binary with the stock release | Off by default; the fork tracks upstream via `scripts/fork-rebuild.sh`. `CBM_ALLOW_UPSTREAM_UPDATE=1` restores the stock updater |

## Staying in sync with upstream

Upstream improvements are merged regularly (merge, never rebase, so public
history is not rewritten). Every merge is built, tested (including the
`discover` and `secret_redact` suites) and checked against a fake-secret leak
test before a binary is installed. Fork patches are kept small and isolated so
they rarely conflict, and fixes that help everyone are proposed upstream.

## Install or update

After a fork release has been published, install it in Claude Code with:

macOS / Linux:
```sh
curl -fsSL https://raw.githubusercontent.com/syaifulizhan/codebase-memory-mcp/hoki-fork/scripts/install-fork.sh | bash
```

Windows PowerShell:
```powershell
irm https://raw.githubusercontent.com/syaifulizhan/codebase-memory-mcp/hoki-fork/scripts/install-fork.ps1 | iex
```

Run the same command again to install the latest fork release. The installer verifies the downloaded archive against the release `checksums.txt` and configures detected coding agents. Restart Claude Code after installation.

To publish a release, open **Actions → Hardened fork release → Run workflow** on branch `hoki-fork` and enter a new `vX.Y.Z` version. The workflow builds the platform archives and publishes them with checksums. It does not run the upstream VirusTotal candidate scan because this fork does not have that upstream secret configured.

The release CodeQL scan covers all first-party source and any vendored source changed in this fork. Unchanged vendored parsers are compiled without tracing; they remain covered by the upstream full scan. `graph-ui/tools` contains local smoke and hand-test harnesses and is not included in release archives, so it is excluded; UI source under `graph-ui/src` remains in scope.

## Build locally

```sh
scripts/fork-rebuild.sh            # merge upstream/main, build, test, install
scripts/fork-rebuild.sh --no-pull  # rebuild the current tree only
```

## Reporting

Security issues in the upstream code: see [SECURITY.md](SECURITY.md).
Issues specific to this fork's patches: open an issue in this repository.
