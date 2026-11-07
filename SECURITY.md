# Security Policy

NoUSB OS Switcher can change how a computer boots, so security reports get priority over feature work.

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Use GitHub's private vulnerability reporting instead: open the repository's **Security** tab and choose **Report a vulnerability**.

Include:

- The affected version or commit, and whether the build used `real-windows-boot`, `real-linux-boot`, or the desktop `real-boot` feature.
- Steps to reproduce, and what changed on the machine (boot entries, ESP files, BCD, partitions).
- Logs from `.nousb/host-boot/` and `nousb diagnostics export`. Remove anything private first.

You should receive an acknowledgement within 7 days. Fixes for issues that can change boot state without the typed confirmation, overwrite existing ESP or boot files, accept an unverified image, or leave a machine unbootable are released before anything else.

## Scope

In scope:

- Bypasses of the typed confirmation gates or the default-build execution block.
- Verification bypasses: accepting an image whose size, SHA-256, or vendor signature does not match the pinned profile.
- Writes outside the paths listed in `nousb boot plan`, or overwrites of existing files.
- Path traversal while extracting ISO contents.
- Leaks of secrets in diagnostic bundles or logs.

Out of scope:

- Problems that need an attacker who already has administrator/root rights on the host.
- Firmware bugs in specific machines. Please still report them as physical-test issues.

## Supported versions

Only the latest release and `main` receive fixes before 1.0. Default builds never enable real boot changes; see [docs/RELEASE.md](docs/RELEASE.md) and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
