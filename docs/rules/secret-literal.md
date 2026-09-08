# secret-literal

[Rule guide](../README.md) | [CLI reference](../../README.md)

Default severity: **warning**.

Flags suspected credentials stored directly in recognized configuration fields. A literal credential can be exposed when a configuration is committed, shared, or logged. The rule recognizes field names and variable-reference syntax; it does not validate whether a value is a working secret.

## Triggering example

```json
{
  "mcpServers": {
    "docs": {
      "url": "https://example.com/mcp",
      "headers": {
        "Authorization": "Bearer example-not-a-real-token"
      }
    }
  }
}
```

Running `mcpeek .mcp.json` on this input prints:

```text
.mcp.json:$.mcpServers.docs.headers.Authorization: warning secret-literal: suspected literal credential
```

With default options and no exceptions, the exit code is `1`.

## Example without this finding

Supply the credential through a variable mechanism supported by your MCP client. The example token above is deliberately fictitious.

```json
{
  "mcpServers": {
    "docs": {
      "url": "https://example.com/mcp",
      "headers": {
        "Authorization": "Bearer ${env:API_TOKEN}"
      }
    }
  }
}
```

This complete example produces no findings and exits `0`. That result only
covers the scanner's supported checks; it does not certify the server as safe.

## Detection boundaries

Checks cover `env`, `headers`, Docker `-e`/`--env` assignments, URL passwords,
and recognized URL query parameters. Examples of recognized names include
`Authorization`, `X-Api-Key`, `GITHUB_TOKEN`, and `AWS_SECRET_ACCESS_KEY`.
Names are case-insensitive and hyphens are treated as underscores. See the
[full credential-name list](../../README.md#credentials-and-endpoints).

Empty values and whole-value `$NAME`, `${NAME}`, `${env:NAME}`, and
`${input:ID}` references are excluded, including after a `Bearer ` or `Basic `
prefix. A value such as `${TOKEN:-literal-default}` or `${TOKEN}literal-suffix`
still triggers the rule. Docker `-e API_TOKEN` inherits a value and is excluded.

Variable recognition does not guarantee that your client expands that syntax.
Arbitrary server arguments and unrecognized field names are not secret-scanned.
Finding messages never include credential values; URL credentials use the message
`suspected literal URL credential`. File paths, server names, field
names, and exception reasons remain visible.

## Accepted exceptions

For an intentional exception scoped to this server and input:

```sh
mcpeek --ignore secret-literal:docs .mcp.json
```

For a persistent exception with a reason, use the
[JSONC exception config](../../README.md#exceptions). Suppressed findings remain
visible in JSON output, and incomplete analysis still exits `2`.

`--fail-on error` keeps this warning visible but does not fail solely because of
it. It does not suppress the finding.
