# docker-socket

[Rule guide](../README.md) | [CLI reference](../../README.md)

Default severity: **error**.

Flags a recognized host Docker socket mounted into a container. Access to the Docker API can give the server control over the daemon and the containers it manages. A read-only bind mount is not an API authorization boundary.

## Triggering example

```json
{
  "mcpServers": {
    "files": {
      "command": "docker",
      "args": [
        "run",
        "-v",
        "/var/run/docker.sock:/var/run/docker.sock:ro",
        "example/mcp@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      ]
    }
  }
}
```

Running `mcpeek .mcp.json` on this input prints:

```text
.mcp.json:$.mcpServers.files.args: error docker-socket: host Docker socket is mounted
```

With default options and no exceptions, the exit code is `1`.

## Example without this finding

Remove the socket mount when the server does not need Docker API access. A read-only mount still triggers the rule; the alternative below removes it entirely.

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

Both volume and bind-mount syntax are recognized, including:

- `-v /var/run/docker.sock:/socket:ro`
- `--volume=/run/docker.sock:/socket`
- `--mount type=bind,source=/var/run/docker.sock,target=/socket,readonly`

Detection uses the host source, regardless of the container target. Host paths
ending in `docker.sock` are recognized, as is the Docker engine named-pipe path
in supported volume syntax. Paths are normalized lexically.

The scanner does not inspect symlinks or directory contents. A socket with a
custom filename, a symlink to a socket, or a mount of its parent directory can
escape this particular check. For example, mounting `/var/run` does not emit
`docker-socket`. Named volumes are not treated as host socket paths. An absence
of findings does not establish that the container cannot reach a Docker daemon.

## Accepted exceptions

For an intentional exception scoped to this server and input:

```sh
mcpeek --ignore docker-socket:files .mcp.json
```

For a persistent exception with a reason, use the
[JSONC exception config](../../README.md#exceptions). Suppressed findings remain
visible in JSON output, and incomplete analysis still exits `2`.

