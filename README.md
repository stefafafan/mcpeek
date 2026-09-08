# mcpeek

A static security checker for MCP configuration files. Plain diagnostics, structured output, and predictable exit codes for local development and CI.

mcpeek highlights configuration risks based on GMO Flatt Security's MCP security guidance. It does not start MCP servers, make network requests, resolve secrets, or modify configuration files. It is an independent project, not an official Flatt Security tool.

## Usage

Build with Go 1.27.1:

```sh
go build -o mcpeek .
./mcpeek --help
```

Or install with `go install github.com/stefafafan/mcpeek@latest` once a version
is published. Development builds print `dev`; set a release version with
`go build -ldflags '-X main.version=v0.1.0' .`.

```sh
mcpeek .mcp.json
cat .mcp.json | mcpeek -
mcpeek --format json .mcp.json | jq '.findings[]'
mcpeek --config mcpeek.jsonc .mcp.json
mcpeek --ignore sensitive-mount:filesystem .mcp.json
```

One input file is required per invocation. Use `-` to read standard input. The first version targets JSON configurations with a top-level `mcpServers` object. Additional client formats are outside the initial scope.

## Output

Text is the default, with one finding per line:

```text
.mcp.json:$.mcpServers.files.args: error docker-socket: host Docker socket is mounted
.mcp.json:$.mcpServers.docs.args: warning package-unpinned: package version is not pinned
```

## Options

```text
mcpeek [options] FILE
```

| Option | Behavior |
| --- | --- |
| `--format text\|json` | Output format; default `text`. |
| `--config PATH` | Load an explicit JSONC config file. No automatic discovery. |
| `--ignore RULE:SERVER` | Suppress one rule for one server in this input; repeatable. |
| `--fail-on warning\|error` | Minimum severity causing failure; default `warning`. |
| `-h`, `--help` | Print usage. |
| `--version` | Print the version. |

## Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | Analysis completed within the supported scope; no unsuppressed findings meet the failure threshold. |
| `1` | Analysis completed; unsuppressed findings meet the failure threshold. |
| `2` | Invalid arguments or config, unreadable/invalid input, or unsupported configuration preventing complete analysis. |

An incomplete analysis takes precedence over findings and returns `2`. A zero exit code does not certify that an MCP server is safe. In a shell pipeline, use the shell's `pipefail` support when the scanner's failure must propagate through a
downstream formatter such as `jq`.

## Initial Rules

All nine rules are implemented. The [rule guide](docs/README.md) explains each
check with triggering examples, alternatives, diagnostics, and detection limits.
The [official guidance mapping](docs/security-guidance.md) relates these checks
to MCP security recommendations and identifies what mcpeek cannot assess.
The supported syntax and recognition boundaries are listed below; this is static
configuration analysis, not a scan of server code or transitive dependencies.

| Rule | Default severity | Condition |
| --- | --- | --- |
| [secret-literal](docs/rules/secret-literal.md) | Warning | A recognized credential field contains a suspected literal secret rather than a supported variable reference. Credential values are never included in output. |
| [package-unpinned](docs/rules/package-unpinned.md) | Warning | A supported `npx` or `uvx` registry package omits an exact version or uses a mutable tag/range. Supported full-SHA Git references count as pinned. |
| [image-unpinned](docs/rules/image-unpinned.md) | Warning | A Docker image is not pinned by digest. Version tags can move too. |
| [docker-privileged](docs/rules/docker-privileged.md) | Error | A Docker launch enables `--privileged`. |
| [docker-socket](docs/rules/docker-socket.md) | Error | A Docker socket is mounted into the container, including read-only mounts. |
| [sensitive-mount](docs/rules/sensitive-mount.md) | Warning | Docker mounts `/`, the user's home directory, or recognized credential directories such as `.ssh` and `.aws`. |
| [host-namespace](docs/rules/host-namespace.md) | Warning | Docker explicitly shares the host network, PID, or IPC namespace. |
| [remote-http](docs/rules/remote-http.md) | Warning | A remote MCP endpoint uses plaintext HTTP. Loopback HTTP is excluded from this rule, not certified secure. |
| [tls-verification-disabled](docs/rules/tls-verification-disabled.md) | Error | A command's environment or Docker env option explicitly sets `NODE_TLS_REJECT_UNAUTHORIZED=0`. |

Command arguments must be parsed structurally. An unrelated argument containing the text `--privileged` must not trigger a Docker finding. Unsupported wrappers or launch syntax must be reported as unassessed rather than guessed at.

## Exceptions

Keep scoped exceptions in a separate JSONC config file:

```jsonc
{
  // File paths are relative to this config file.
  "ignore": [
    {
      "rule": "sensitive-mount",
      "file": ".mcp.json",
      "server": "filesystem",
      "reason": "Intentional access to this development workspace."
    }
  ]
}
```

```sh
mcpeek --config mcpeek.jsonc .mcp.json
```

The config accepts `//` line comments and `/* ... */` block comments, using a
string-aware comment lexer followed by Go's `encoding/json` parser. Trailing
commas, duplicate object keys, unknown exception fields, and non-string exception
values are rejected. An empty config object or `"ignore": []` is valid.

Config exceptions match the exact rule, configuration file, and server. A nonempty reason is required. Matching findings do not contribute to exit `1`, but remain visible in JSON output. Exceptions cannot suppress parsing failures or incomplete analysis.

For a one-off exception:

```sh
mcpeek --ignore sensitive-mount:filesystem .mcp.json
```

This flag applies only to the supplied input. Its suppression is recorded as a command-line override. File-scoped config exceptions do not match stdin input; use explicit `--ignore` overrides when reading stdin.

An exception records an accepted risk or false positive. It does not prove that the configuration is safe.

Paths are compared as cleaned absolute paths without resolving symlinks or
case-folding. No glob matching is performed. CLI overrides take precedence over
config exceptions; the first matching config exception supplies the reason.
Options must precede the input filename; use `--` before a filename starting with
`-`. Rule IDs are validated even when no findings match them.

## Supported Analysis

Input is strict JSON, with duplicate keys rejected and nesting limited to 100
levels. `mcpServers` must be an object. Each server must be an object with exactly
one nonempty `command` or literal HTTP/HTTPS `url`. Recognized fields are
`command`, `args` (string array), `env` and `headers` (string maps), `url`, and
`type`. Omitted `args` means no arguments. A command's optional type is `stdio`;
a URL's optional type is `http`, `sse`, or `streamable-http`. Unknown server
fields, incompatible transport fields, and other launchers are unassessed.
Other top-level client settings are outside the scan.

### Package Launches

- `npx [-y|--yes[=true|false]] [-p PACKAGE|--package[=]PACKAGE]... [--] PACKAGE_OR_COMMAND [ARGS...]`
- `uvx [--from[=]PACKAGE] [--with[=]PACKAGE]... [--] PACKAGE_OR_COMMAND [ARGS...]`

Executable paths are recognized by basename, including `npx.cmd` and `uvx.exe`.
`npx -pPACKAGE` is also supported. An explicit package selector requires a command
after the launcher options. Arguments after that command/package are server
arguments and are not interpreted as launcher options.

Npm registry names, including `@scope/name`, are recognized. Exact pins use a
three-component version, optionally with prerelease/build identifiers; omitted
versions, tags, wildcards, and ranges produce `package-unpinned`. Python registry
names may include extras. Pins use `==VERSION` or `@VERSION`, with numeric release
components and optional `a`, `b`, `rc`, `.post`, `.dev`, or local-version suffixes.
Python ranges/wildcards and `@latest` are unpinned.

Git references with a full 40-hex commit SHA also count as pinned:

- npm: `git+https://HOST/REPO.git#SHA`, `git+http://HOST/REPO.git#SHA`,
  `git+ssh://git@HOST/REPO.git#SHA`, `git://HOST/REPO.git#SHA`,
  `github:OWNER/REPO#SHA`, and `OWNER/REPO#SHA`.
- npm also recognizes `https://github.com/OWNER/REPO.git#SHA` and its HTTP form.
  GitHub URLs must name the repository directly; paths such as `/tree/main` are
  unassessed. Arbitrary HTTP archive URLs are not treated as Git references.
- uv: `git+https://HOST/REPO.git@SHA`, `git+http://HOST/REPO.git@SHA`, and
  `git+ssh://git@HOST/REPO.git@SHA`, used directly or with `--from` or `--with`. Named
  requirements such as `server[cli] @ git+https://HOST/REPO.git@SHA` are supported,
  as is a `#subdirectory=packages/server` fragment with simple relative components.

Git branches, tags, omitted revisions, abbreviated SHAs, and other Git syntax
remain unassessed (exit `2`); this Git support is limited to full SHA-1 references.
No repository is contacted and commit existence is not verified. An npm registry
selector such as `server@<40-hex-tag>` is still an unpinned tag, not a Git pin.
Other version forms, archive URLs, local-path packages, shell command modes, and
unknown launcher options are unassessed. Pinning applies to explicitly selected
packages, not their dependencies.

### Docker Launches

Supports `docker run` and `docker container run`, including executable paths and
`docker.exe`. Parsing stops at the image; the container command is outside the
scope. Supported options before the image are:

| Options | Accepted form |
| --- | --- |
| `--privileged`, `--rm`, `--interactive`, `--tty`, `--detach`, `--read-only`, `--init` | Boolean flag or `=true`/`=false` |
| `-i`, `-t`, `-d` | Boolean flags; combinations such as `-it` |
| `-v`, `--volume`, `--mount`, `-e`, `--env` | Separate value or `=value`; short attached values such as `-v/src:/dst` |
| `--network`, `--net`, `--pid`, `--ipc` | Separate value or `=value` |
| `--name`, `--user`/`-u`, `--workdir`/`-w`, `--entrypoint`, `--label`/`-l`, `--publish`/`-p`, `--platform`, `--pull` | Consumed structurally as options taking one value |

Images must use a registry-style name; only `@sha256:` followed by 64 lowercase
hex digits counts as a digest pin. Invalid digests and variable image names are
unassessed. Scalar privilege/namespace options use their final supplied value.
Docker global options, Compose, external env files, inherited volumes, unknown
options, and unsupported mount options are unassessed.

Volumes support `SOURCE:TARGET[:OPTIONS]` and anonymous `TARGET` volumes. Options
are `ro`, `rw`, `z`, `Z`, `cached`, `delegated`, `consistent`, `private`, `rprivate`,
`shared`, `rshared`, `slave`, `rslave`, and `nocopy`. `--mount` is parsed as CSV
with `type`, `source`/`src`, `target`/`dst`/`destination`, `readonly`/`ro`, and
`bind-propagation`. Supported types are `bind`, `volume` (the default), and
`tmpfs`. Bind mounts need a source and target; all mounts need an absolute target.
Named/anonymous volumes are not treated as host paths.

Host paths are normalized lexically. Recognition covers `/`, drive roots,
`/root`, `/home/USER`, `/Users/USER`, Windows `DRIVE:/Users/USER`, path components
`.ssh`, `.aws`, `.kube`, `.docker`, `.gnupg`, and `.config/gcloud`. Home references
`~`, `$HOME`, `${HOME}`, `${env:HOME}`, and the equivalent `USERPROFILE` forms are
recognized symbolically. Unknown path variables and relative bind sources are
unassessed. Socket recognition covers host paths ending in `docker.sock` and the
Docker engine named-pipe path. Read-only mounts still trigger these rules.
Symlinks, custom home locations, and the contents of mounted directories are not
inspected; mounting a socket's parent directory does not trigger `docker-socket`.

### Credentials and Endpoints

Credential names are case-insensitive with hyphens treated as underscores.
Recognized names are `AUTHORIZATION`, `PROXY_AUTHORIZATION`, `COOKIE`, `SET_COOKIE`,
`PASSWORD`, `PASSWD`, `SECRET`, `TOKEN`, `API_KEY`, `APIKEY`, `ACCESS_KEY`, and
`PRIVATE_KEY`; suffixes `_TOKEN`, `_SECRET`, `_PASSWORD`, `_PASSWD`, `_API_KEY`,
`_APIKEY`, `_ACCESS_KEY`, `_ACCESS_KEY_ID`, and `_PRIVATE_KEY` are also recognized.
Checks cover `env`, `headers`, Docker `-e`/`--env` assignments, URL passwords, and
recognized URL query keys. Arbitrary server arguments and unrecognized names are
not secret-scanned. Empty values and inherited Docker env names are excluded.

Whole-value `$NAME`, `${NAME}`, `${env:NAME}`, and `${input:ID}` references are
excluded, optionally after a `Bearer ` or `Basic ` prefix. Variable names use
letters, digits, and underscores (starting with a letter or underscore); input
IDs additionally allow hyphens. Literal suffixes/defaults are not excluded.
Recognition does not assert that a particular MCP client expands that syntax.
Credential values, raw arguments, and endpoints are never included in diagnostics.
File paths, server names, field names, and exception reasons remain visible.

`remote-http` excludes literal loopback IPs (including IPv4-mapped IPv6) and
`localhost`, case-insensitively, with an optional trailing dot. Private-network
addresses, `0.0.0.0`, and lookalike hostnames are not excluded. DNS is never queried.

### TLS Verification

`tls-verification-disabled` recognizes the exact name
`NODE_TLS_REJECT_UNAUTHORIZED` with the exact string value `0` in command `env`
maps and Docker `-e`/`--env` options before the image. Repeated Docker assignments
use their final value. Inherited or variable values, HTTP headers, URL-only
server environments, arbitrary arguments, and other TLS settings are not checked.
This detects a configured bypass, not whether the launched code uses Node's TLS.

## JSON Output

JSON is written to stdout as one object, including for input/config errors when
valid CLI arguments select JSON. Invalid CLI arguments are reported on stderr.
Text findings go to stdout; text analysis errors go to stderr. Suppressed findings
are omitted from text output and retained in JSON:

```json
{
  "file": ".mcp.json",
  "complete": true,
  "findings": [
    {
      "rule": "remote-http",
      "severity": "warning",
      "server": "docs",
      "path": "$.mcpServers.docs.url",
      "message": "remote endpoint uses plaintext HTTP",
      "suppression": {"source": "command-line", "reason": "command-line override"}
    }
  ],
  "diagnostics": []
}
```

Unsuppressed findings omit `suppression`. Config suppressions use `source: config`
and the supplied reason. Diagnostics contain `code`, `path`, `message`, and,
when applicable, `server`. Diagnostic codes are `input-error`, `config-error`,
and `unassessed`; they cannot be ignored. Findings already identified remain
available when another server or field is unassessed. Servers and map keys are
processed in sorted order for deterministic output. Non-identifier JSON keys use
bracket notation; control characters are escaped in text diagnostics.

## Development

```sh
go test -race -cover ./...
go vet ./...
go tool govulncheck ./...
go build ./...
```

The implementation was developed test-first, with table-driven rule and CLI
contract tests. GitHub Actions runs formatting, golangci-lint, govulncheck, race
tests, and build checks with Go 1.27.1 on Ubuntu. Runtime code uses only the standard
library and has no network or process-execution dependencies.

govulncheck is recorded as a tool dependency in `go.mod`. `go tool govulncheck`
uses that version locally and in CI; it downloads vulnerability data when run.
To update it, run `go get -tool golang.org/x/vuln/cmd/govulncheck@VERSION`.

## References

The checklist is informed by the following guidance. The rule selection and CLI
design are this project's interpretation, not a certification of compliance.
See the [rule-to-guidance mapping](docs/security-guidance.md) for coverage and limits.

- [Official MCP Security Best Practices (2026-07-28)](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)
- [Official MCP Authorization Security Considerations (2026-07-28)](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations)
- [Official MCP Streamable HTTP: Security & Endpoint (2026-07-28)](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#security--endpoint)

- [GMO Flatt Security: MCP security considerations, part 1](https://blog.flatt.tech/entry/mcp_security_first)
- [GMO Flatt Security: MCP security considerations, part 2](https://blog.flatt.tech/entry/mcp_security_second)
