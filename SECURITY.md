# Security policy

keyward is a credential-manager SDK — bugs here are security bugs. Please treat any issue
that could expose, leak, or weaken a stored secret as sensitive.

## Reporting a vulnerability

**Do not open a public issue.** Use GitHub's private vulnerability reporting
(**Security → Report a vulnerability** on this repo), which opens a private advisory with the
maintainer. Include a description, affected version/commit, and a minimal reproduction.

You'll get an acknowledgement within a few days. Please allow a reasonable window for a fix
before any public disclosure.

## In scope

The SDK's handling of secrets: the storage backends, the encrypted-file format, memory
zeroization, constant-time comparison, and the agent/IPC trust boundary.

## Out of scope

The security of the host OS keychain itself, and threats from a root / kernel / hypervisor /
physical-memory attacker. keyward assumes a non-compromised OS and a single-user machine.

For the full trust model — assets, assumptions, what is and isn't defended, and the honest
current hardening status — see [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Supported versions

Pre-1.0: only `main` is supported; fixes land there.
