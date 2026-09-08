# Official security guidance mapping

[Rule guide](README.md) | [CLI reference](../README.md)

Based on official MCP **2026-07-28** guidance, reviewed **2026-09-08**.
These are configuration checks, not a protocol-compliance audit. Rule names,
severities, pin formats, and recognized paths are mcpeek policy.

| Rule | Related official guidance | Relationship |
| --- | --- | --- |
| [secret-literal](rules/secret-literal.md) | [Token theft][tokens] | Detects one potential credential-storage risk, not overall secret handling. |
| [package-unpinned](rules/package-unpinned.md) | [Local server compromise][local] | Additional supply-chain hardening; exact-version/SHA pinning is not prescribed by this guidance. |
| [image-unpinned](rules/image-unpinned.md) | [Local server compromise][local] | Additional supply-chain hardening; Docker digest pinning is mcpeek policy. |
| [docker-privileged](rules/docker-privileged.md) | [Local server compromise][local] | Applies minimal-privilege recommendations to Docker. |
| [docker-socket](rules/docker-socket.md) | [Local server compromise][local] | Applies restricted host-resource access to Docker socket mounts. |
| [sensitive-mount](rules/sensitive-mount.md) | [Local server compromise][local] | Directly aligns with warnings about sensitive filesystem access. |
| [host-namespace](rules/host-namespace.md) | [Local server compromise][local] | Applies network/system isolation recommendations to Docker. |
| [remote-http](rules/remote-http.md) | [Communication security][https] | Checks MCP endpoint schemes, not OAuth endpoints. The loopback exclusion is mcpeek policy. |
| [tls-verification-disabled](rules/tls-verification-disabled.md) | [Communication security][https] | Flags an explicit Node.js certificate-verification bypass; not a full TLS audit. |

## Limits

mcpeek does not verify OAuth flows, token validation, SSRF defenses, user consent,
or effective sandboxing. It also cannot verify [Origin validation, listening
interfaces, authentication, or header/body consistency][transport]. A missing
`Authorization` header does not prove missing authentication.

Pinning does not establish trust or absence of vulnerabilities. A clean report
or accepted exception does not certify server safety or MCP compliance. See each
rule page for detection limits.

[tokens]: https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations#token-theft
[local]: https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices#local-mcp-server-compromise
[https]: https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations#communication-security
[transport]: https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http
