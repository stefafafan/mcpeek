# sensitive-mount

[Rule guide](../README.md) | [CLI reference](../../README.md)

Default severity: **warning**.

Flags Docker bind mounts exposing a whole filesystem, a recognized home directory, or recognized credential locations. Such access can expose files unrelated to the server's intended task, including credentials. Read-only access can still reveal their contents.

## Triggering example

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "docker",
      "args": [
        "run",
        "-v",
        "/home/alice/.ssh:/keys:ro",
        "example/mcp@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      ]
    }
  }
}
```

Running `mcpeek .mcp.json` on this input prints:

```text
.mcp.json:$.mcpServers.filesystem.args: warning sensitive-mount: sensitive host path is mounted
```

With default options and no exceptions, the exit code is `1`.

## Example without this finding

Limit the mount to the data needed by the server. The alternative illustrates a project directory outside the recognized sensitive paths; its contents are still your responsibility.

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "docker",
      "args": [
        "run",
        "-v",
        "/workspace/project:/workspace:ro",
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

Recognized paths include:

| Host source | Reason |
| --- | --- |
| `/`, `C:/` | Whole filesystem or drive |
| `/root`, `/home/alice`, `/Users/alice`, `C:/Users/alice` | Recognized home root |
| `~`, `$HOME`, `${HOME}`, `${env:HOME}` | Symbolic home reference |
| `/home/alice/.ssh/id_ed25519` | Credential directory component |
| `/home/alice/.aws`, `/home/alice/.kube` | Credential/configuration directory |
| `/home/alice/.docker`, `/home/alice/.gnupg` | Credential/configuration directory |
| `/home/alice/.config/gcloud` | Cloud credential directory |

Equivalent `USERPROFILE` references are recognized. Both `-v`/`--volume`
and `--mount type=bind` are checked. The source matters, not the target;
`/workspace/project:/root` does not expose the host's root home directory.

Named/anonymous volumes are excluded. Unknown variables such as
`${CUSTOM_PATH}:/data` and relative bind sources are unassessed. No variables,
symlinks, actual home directories, or directory contents are resolved. Custom
home locations and sensitive files outside the recognized paths may be missed.
A normal project subdirectory is not flagged merely for being beneath a home
root, unless it contains a recognized sensitive component.

## Accepted exceptions

For an intentional exception scoped to this server and input:

```sh
mcpeek --ignore sensitive-mount:filesystem .mcp.json
```

For a persistent exception with a reason, use the
[JSONC exception config](../../README.md#exceptions). Suppressed findings remain
visible in JSON output, and incomplete analysis still exits `2`.

`--fail-on error` keeps this warning visible but does not fail solely because of
it. It does not suppress the finding.

