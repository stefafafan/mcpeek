# package-unpinned

[Rule guide](../README.md) | [CLI reference](../../README.md)

Default severity: **warning**.

Flags explicitly selected npm or Python registry packages without an exact version.
An omitted version, mutable tag, or range allows the selected package version to
change between launches. Supported Git references pinned to a full commit SHA
also count as pinned.

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
check. Shell wrappers, unsupported Git references, archive URLs, local-path
packages, and unknown launcher options are unassessed, producing exit 2 rather
than a clean result. Transitive
dependencies and package contents are outside the scope; a pin is not a trust check.

## Git commit pins

For npm, a Git revision follows `#`. This complete example is assessed without
findings and exits `0`:

```json
{
  "mcpServers": {
    "docs": {
      "command": "npx",
      "args": [
        "-y",
        "github:example/mcp-server#0123456789abcdef0123456789abcdef01234567"
      ]
    }
  }
}
```

For uv, a Git revision follows `@` in the repository URL path. This complete
example also exits `0`:

```json
{
  "mcpServers": {
    "docs": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/example/mcp-server.git@0123456789abcdef0123456789abcdef01234567",
        "mcp-server"
      ]
    }
  }
}
```

These repositories and commits are illustrative. The scanner checks syntax only;
it never fetches a repository or verifies that a commit exists.

Supported explicit Git schemes are `git+https`, `git+http`, and `git+ssh`; npm
additionally supports `git://`, GitHub shorthand, and HTTP/HTTPS GitHub URLs ending
in `.git`. Use an explicit Git scheme for other hosts. An arbitrary HTTP URL
ending in `.git` could be an archive URL and remains unassessed.
GitHub URLs must use a plain owner/repository path. Web paths such as `/tree/main`
are rejected because npm may use that branch instead of the SHA fragment.

The full SHA must contain exactly 40 hexadecimal characters. Abbreviations,
branches, tags, omitted revisions, SHA-256 object IDs, and other revision syntax
remain unassessed and exit `2`, even when the Git revision appears stable. This
extension only assesses full SHA-1 references. Registry `server@<40-hex-tag>`
remains an unpinned tag because it does not identify a Git source.

uv accepts Git sources directly as the positional tool source or through `--from`
and `--with`. Named requirements such as `server[cli] @ git+https://HOST/REPO.git@SHA`
and `#subdirectory=packages/server` are supported. Subdirectory components may
contain letters, digits, underscores, dots, and hyphens; absolute paths and `.` or
`..` components are not supported. Query strings, encoded path/fragment syntax,
unknown fragments, and environment markers remain unassessed.

See the upstream [npm package reference](https://docs.npmjs.com/cli/v11/using-npm/package-spec/)
and [uv tool source examples](https://docs.astral.sh/uv/guides/tools/#requesting-different-sources)
for launcher syntax. A commit pin does not pin transitive dependencies, establish
trust in the repository, or assess transport security.

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
