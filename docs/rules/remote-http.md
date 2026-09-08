# remote-http

[Rule guide](../README.md) | [CLI reference](../../README.md)

Default severity: **warning**.

Flags a remote MCP endpoint using plaintext HTTP, except for recognized loopback addresses. HTTP does not provide transport encryption for requests, responses, or credentials sent over the connection.

## Triggering example

```json
{
  "mcpServers": {
    "docs": {
      "url": "http://example.com/mcp"
    }
  }
}
```

Running `mcpeek .mcp.json` on this input prints:

```text
.mcp.json:$.mcpServers.docs.url: warning remote-http: remote endpoint uses plaintext HTTP
```

With default options and no exceptions, the exit code is `1`.

## Example without this finding

Use an HTTPS endpoint configured by the service operator. Changing the URL scheme in a config only works when that endpoint actually supports HTTPS.

```json
{
  "mcpServers": {
    "docs": {
      "url": "https://example.com/mcp"
    }
  }
}
```

This complete example produces no findings and exits `0`. That result only
covers the scanner's supported checks; it does not certify the server as safe.

## Detection boundaries

Examples of endpoint classification:

| URL | Result for this rule |
| --- | --- |
| `http://example.com/mcp` | Warning |
| `http://192.168.1.2/mcp` | Warning, even on a private network |
| `http://0.0.0.0:3000/mcp` | Warning |
| `http://localhost.evil.test/mcp` | Warning |
| `http://localhost:3000/mcp` | No finding: loopback exclusion |
| `http://LOCALHOST.:3000/mcp` | No finding: loopback exclusion |
| `http://127.1.2.3/mcp` | No finding: loopback exclusion |
| `http://[::1]:3000/mcp` | No finding: loopback exclusion |
| `http://[::ffff:127.0.0.1]/mcp` | No finding: loopback exclusion |
| `https://example.com/mcp` | No finding |

Loopback HTTP is excluded from this rule, not certified secure. DNS is never
queried: a custom hostname that resolves to loopback is still flagged when it
uses HTTP. Private-network addresses are not an exception.

The URL must be a literal HTTP/HTTPS endpoint. An endpoint such as
`${MCP_URL}`, a malformed URL, or an unsupported scheme is unassessed and
produces exit 2. HTTPS URLs can still produce [secret-literal](secret-literal.md)
findings for embedded credentials. Certificates, redirects, endpoint behavior,
and server authorization are not inspected.

## Accepted exceptions

For an intentional exception scoped to this server and input:

```sh
mcpeek --ignore remote-http:docs .mcp.json
```

For a persistent exception with a reason, use the
[JSONC exception config](../../README.md#exceptions). Suppressed findings remain
visible in JSON output, and incomplete analysis still exits `2`.

`--fail-on error` keeps this warning visible but does not fail solely because of
it. It does not suppress the finding.

