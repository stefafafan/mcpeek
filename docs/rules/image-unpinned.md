# image-unpinned

[Rule guide](../README.md) | [CLI reference](../../README.md)

Default severity: **warning**.

Flags Docker images selected by a name or tag instead of a digest. Even a version tag such as `:1.2.3` can be reassigned; a digest identifies the selected image content.

## Triggering example

```json
{
  "mcpServers": {
    "files": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "example/mcp:1.2.3"
      ]
    }
  }
}
```

Running `mcpeek .mcp.json` on this input prints:

```text
.mcp.json:$.mcpServers.files.args: warning image-unpinned: Docker image is not pinned by digest
```

With default options and no exceptions, the exit code is `1`.

## Example without this finding

Use the actual SHA-256 digest of the image you intend to run. The all-`a` digest below is illustrative and is not an image to deploy.

```json
{
  "mcpServers": {
    "files": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "example/mcp@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      ]
    }
  }
}
```

This complete example produces no findings and exits `0`. That result only
covers the scanner's supported checks; it does not certify the server as safe.

## Detection boundaries

`example/mcp`, `example/mcp:latest`, and `example/mcp:1.2.3` all trigger this
rule. A supported pin ends in `@sha256:` followed by exactly 64 lowercase
hexadecimal digits. A tag may also precede the digest.

Only the image argument in supported `docker run` or `docker container run`
syntax is inspected. Parsing stops at the image; later arguments belong to the
container command. A malformed digest such as `example/mcp@sha256:abc` or an
image variable such as `${IMAGE}` is unassessed and produces exit 2.

The scanner does not contact a registry, pull the image, verify its signature,
check that the digest exists, or inspect image contents. Update reviewed digest
pins deliberately when changing images.

## Accepted exceptions

For an intentional exception scoped to this server and input:

```sh
mcpeek --ignore image-unpinned:files .mcp.json
```

For a persistent exception with a reason, use the
[JSONC exception config](../../README.md#exceptions). Suppressed findings remain
visible in JSON output, and incomplete analysis still exits `2`.

`--fail-on error` keeps this warning visible but does not fail solely because of
it. It does not suppress the finding.

