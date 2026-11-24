# Security Policy

## Supported Versions

| Version | Supported |
| :--- | :--- |
| `0.0.x` | Yes |

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities (such as credential handling bugs, injection flaws, or unsafe redirects).

Instead, report vulnerabilities privately through GitHub's **Security** tab (**Report a vulnerability** / Private Vulnerability Reporting once public), or contact `@qsardor` directly.

Include:
- Steps to reproduce or a minimal proof of concept
- Affected command or module (`src/pypi_cli/cli.py`)
- Expected vs. actual behavior

## Security Design Scope

`pypi-cli` handles PyPI API tokens and remote package metadata with the following invariants:
- Reads/writes credentials only in `~/.pypirc` (`0600` permissions on POSIX)
- Strips `--token` from child process `argv` and forwards credentials strictly via environment variables
- Blocks `https://` to `http://` redirects and bounds compressed/decompressed HTTP payloads
