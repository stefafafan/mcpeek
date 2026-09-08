# docker-privileged

[Rule guide](../README.md) | [CLI reference](../../README.md)

Default severity: **error**.

Flags a Docker launch that enables privileged mode. This grants the container substantially broader access to the host than an ordinary container, weakening the intended isolation.

## Triggering example

```json
{
  "mcpServers": {
    "files": {
      "command": "docker",
      "args": [
        "run",
        "--privileged",
        "example/mcp@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      ]
    }
  }
}
```

Running `mcpeek .mcp.json` on this input prints:

```text
.mcp.json:$.mcpServers.files.args: error docker-privileged: Docker launch enables privileged mode
```

With default options and no exceptions, the exit code is `1`.

## Example without this finding

Remove `--privileged` when it is not required. The alternative below launches without enabling privileged mode.

```json
{
  "mcpServers": {
    "files": {
      "command": "docker",
      "args": [
        "run",
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

The rule recognizes `--privileged` and `--privileged=true` before the image.
`--privileged=false` does not trigger it. Repeated scalar options use their final
value, so `--privileged --privileged=false` does not trigger this rule.

Parsing respects argument boundaries: `--label --privileged` consumes
`--privileged` as the label value, and `--privileged` after the image is a
container-command argument. Neither is treated as enabling Docker privilege.
An invalid boolean such as `--privileged=maybe` is unassessed.

This check is not a complete Docker permissions audit. Capabilities, device
access, container contents, and daemon configuration are outside this rule.
Unknown Docker options still produce incomplete analysis. See
[supported Docker syntax](../../README.md#docker-launches).

## Accepted exceptions

For an intentional exception scoped to this server and input:

```sh
mcpeek --ignore docker-privileged:files .mcp.json
```

For a persistent exception with a reason, use the
[JSONC exception config](../../README.md#exceptions). Suppressed findings remain
visible in JSON output, and incomplete analysis still exits `2`.

