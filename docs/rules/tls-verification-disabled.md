# tls-verification-disabled

[Rule guide](../README.md) | [CLI reference](../../README.md)

Default severity: **error**.

Flags an explicit `NODE_TLS_REJECT_UNAUTHORIZED=0` assignment. Node.js documents
that this disables TLS certificate validation, allowing an HTTPS connection
without verifying the peer's certificate. See the [Node.js reference](https://nodejs.org/api/cli.html#node_tls_reject_unauthorizedvalue)
and [official guidance mapping](../security-guidance.md).

## Example

```json
{
  "mcpServers": {
    "docs": {
      "command": "npx",
      "args": ["@example/mcp-server@1.2.3"],
      "env": {"NODE_TLS_REJECT_UNAUTHORIZED": "0"}
    }
  }
}
```

```text
.mcp.json:$.mcpServers.docs.env.NODE_TLS_REJECT_UNAUTHORIZED: error tls-verification-disabled: TLS certificate verification is explicitly disabled
```

This exits `1`, including with `--fail-on error`. Remove the bypass and configure
the appropriate trusted CA certificates instead. Removing `env` from this
example produces no findings; it does not certify server safety.

## Scope

- Checks command `env` maps and Docker `-e`/`--env` assignments before the image.
- Requires the exact, case-sensitive name and string value `0`; `false`, empty values, and whitespace-padded values do not match.
- Uses the final Docker assignment for each name. Inherited values and variable references are not resolved.
- Does not inspect headers, URL-only server environments, arbitrary arguments, external configuration files, or other TLS bypass settings.
- Reports the configured bypass even if the command is unassessed. It does not determine whether the process actually uses Node.js TLS.

Docker findings point to `args`; command environment findings point to the field.
Unsupported syntax still takes precedence with exit `2`.

For an accepted risk, use `--ignore tls-verification-disabled:docs` or a scoped
[config exception](../../README.md#exceptions). Suppressed findings remain in JSON.
