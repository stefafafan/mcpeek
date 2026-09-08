# Rule guide

Each rule page explains what mcpeek detects, shows complete JSON configurations
with and without the finding, and describes the limits of the check.

| Rule | Severity | Focus |
| --- | --- | --- |
| [secret-literal](rules/secret-literal.md) | Warning | Credentials stored directly in configuration |
| [package-unpinned](rules/package-unpinned.md) | Warning | npm and Python package version selection |
| [image-unpinned](rules/image-unpinned.md) | Warning | Docker image digest pinning |
| [docker-privileged](rules/docker-privileged.md) | Error | Privileged Docker launches |
| [docker-socket](rules/docker-socket.md) | Error | Host Docker socket mounts |
| [sensitive-mount](rules/sensitive-mount.md) | Warning | Filesystem roots, home directories, and credential paths |
| [host-namespace](rules/host-namespace.md) | Warning | Host network, PID, and IPC sharing |
| [remote-http](rules/remote-http.md) | Warning | Plaintext remote MCP endpoints |

## Reading the examples

Each JSON block is a complete input for mcpeek. The diagnostic examples assume
the input filename is `.mcp.json`, text output, the default warning failure
threshold, and no exceptions. The triggering examples each produce one finding
and exit `1`; the alternatives produce no findings and exit `0`.

Names, versions, credentials, endpoints, and all-`a` image digests are illustrative.
They are not verified server deployments or package recommendations. Replace
them with reviewed values before using a configuration to launch a server.
mcpeek itself only reads the configuration and never launches those commands.

An absence of findings only covers supported analysis. Unsupported syntax
produces an unsuppressible diagnostic and exit `2`. Other findings remain
available when analysis is incomplete. See the [CLI reference](../README.md)
for supported launch syntax, output, exit codes, and scoped exceptions.
