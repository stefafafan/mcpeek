# package-unpinned

[Rule guide](../README.md) | [CLI reference](../../README.md)

Default severity: **warning**.

Flags explicitly selected npm or Python packages without an exact version. An omitted version, mutable tag, or range allows the selected package version to change between launches.

## Triggering example

```json
{
  "mcpServers": {
    "docs": {
      "command": "npx",
      "args": [
        "-y",
        "@example/mcp-server@latest"
      ]
    }
  }
}
```

Running `mcpeek .mcp.json` on this input prints:

```text
.mcp.json:$.mcpServers.docs.args: warning package-unpinned: package version is not pinned
```

With default options and no exceptions, the exit code is `1`.

## Example without this finding

Select an exact version that you have reviewed. Package names and versions here illustrate syntax; they do not identify a verified package.

```json
{
  "mcpServers": {
    "docs": {
      "command": "npx",
      "args": [
        "-y",
        "@example/mcp-server@1.2.3"
      ]
    }
  }
}
```

This complete example produces no findings and exits `0`. That result only
covers the scanner's supported checks; it does not certify the server as safe.

## Detection boundaries

Both direct package selection and explicit selectors are checked:

| Launcher arguments | Result for this rule |
| --- | --- |
| `npx server` | Warning |
| `npx server@^1.2.3` | Warning |
| `npx server@1.2.3` | No finding |
| `npx --package=server@1.2.3 server` | No finding |
| `uvx server` | Warning |
| `uvx server@latest` | Warning |
| `uvx server>=1.2` | Warning |
| `uvx server==1.2.3` | No finding |
| `uvx --from=server==1.2.3 server` | No finding |
| `uvx --with=dependency server==1.2.3` | Warning for the dependency |

These rows show argument tokens, not shell commands to execute. In an MCP config,
put each argument in its own `args` entry. Supported npm pins have three numeric
components, with optional prerelease/build identifiers. Python pins accept the
[documented version forms](../../README.md#package-launches), including extras.

Arguments after the selected package/command belong to the server. For example,
`npx server@1.2.3 --package other` does not select a second npm package for this
check. Shell wrappers, Git/URL/local-path packages, and unknown launcher options
are unassessed, producing exit 2 rather than a clean result. Transitive
dependencies and package contents are outside the scope; a pin is not a trust check.

## Accepted exceptions

For an intentional exception scoped to this server and input:

```sh
mcpeek --ignore package-unpinned:docs .mcp.json
```

For a persistent exception with a reason, use the
[JSONC exception config](../../README.md#exceptions). Suppressed findings remain
visible in JSON output, and incomplete analysis still exits `2`.

`--fail-on error` keeps this warning visible but does not fail solely because of
it. It does not suppress the finding.

