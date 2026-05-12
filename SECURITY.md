# Security Policy

AgentBOM is a static scanner for reviewing AI agent repositories. It is designed
to run safely against untrusted source trees.

## Supported Versions

Security fixes are prioritized for the latest released version.

| Version | Supported |
| --- | --- |
| 0.5.x | Yes |
| older | Best effort |

## Reporting a Vulnerability

Please report security issues through GitHub private vulnerability reporting if
it is enabled for the repository. If it is not available, open a minimal public
issue that does not include exploit details or private data, and ask for a
private contact path.

Do not include secret values, private repository contents, customer data, or
payloads that execute code.

Useful reports include:

- AgentBOM version
- operating system and Python version
- exact command used
- minimal non-sensitive reproduction files
- expected behavior
- observed behavior

## Security Boundaries

AgentBOM should:

- avoid executing scanned code
- avoid importing scanned modules
- avoid network access during scanning
- avoid following symlink loops
- skip binary-looking and oversized files
- record secret names only, never secret values

Findings are review signals and should not be treated as proof of exploitability
without human review.
