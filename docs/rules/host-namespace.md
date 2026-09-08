# host-namespace

[Rule guide](../README.md) | [CLI reference](../../README.md)

Default severity: **warning**.

Flags explicit sharing of the host network, PID, or IPC namespace. Sharing these namespaces reduces separation between the MCP server's container and host resources.

## Triggering example

```json
{
  "mcpServers": {
    "files": {
      "command": "docker",
      "args": [
        "run",
        "--network=host",
        "example/mcp@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      ]
    }
  }
}
```

Running `mcpeek .mcp.json` on this input prints:

```text
.mcp.json:$.mcpServers.files.args: warning host-namespace: Docker shares the host network namespace
```

With default options and no exceptions, the exit code is `1`.

## Example without this finding

Use an isolated namespace when the server does not require host sharing. The alternative uses Docker's bridge network. Remove `--pid=host` and `--ipc=host` if those are unnecessary.

```json
{
  "mcpServers": {
    "files": {
      "command": "docker",
      "args": [
        "run",
        "--network=bridge",
        "example/mcp@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      ]
    }
  }
}
```

This complete example produces no findings and exits `0`. That result only
covers the scanner's supported checks; it does not certify the server as safe.

The all-`a` image digest is illustrative. Replace it with the real digest of your
reviewed image before using the configuration to launch a server.

## Detection boundaries

The following options trigger the rule before the image:

| Option | Diagnostic message |
| --- | --- |
| `--network=host` or `--net host` | `Docker shares the host network namespace` |
| `--pid=host` or `--pid host` | `Docker shares the host PID namespace` |
| `--ipc=host` or `--ipc host` | `Docker shares the host IPC namespace` |

A launch sharing all three namespaces produces three findings. Repeated settings
use the final value for each namespace; `--network=host --network=bridge` does
not trigger the network finding. The `--net` alias shares that same setting.
Arguments after the image are container-command arguments and are not checked
as Docker options.

Variable settings such as `--network=${NETWORK}` are unassessed. The scanner
does not query daemon defaults or assess sharing with other containers. This
rule only detects explicit `host` values in supported launch syntax.

## Accepted exceptions

For an intentional exception scoped to this server and input:

```sh
mcpeek --ignore host-namespace:files .mcp.json
```

For a persistent exception with a reason, use the
[JSONC exception config](../../README.md#exceptions). Suppressed findings remain
visible in JSON output, and incomplete analysis still exits `2`.

`--fail-on error` keeps this warning visible but does not fail solely because of
it. It does not suppress the finding.

