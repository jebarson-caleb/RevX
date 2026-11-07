# Packaging Plan

Packaging is planned for Windows installer, Linux deb/rpm/AppImage, and macOS dmg/pkg artifacts. Real packaging must include signed releases, SBOM generation, dependency license review, and smoke tests that do not modify boot configuration.

Today, `v*` tags run `.github/workflows/release.yml`. It builds default-feature `nousb` binaries for Linux and Windows, writes `SHA256SUMS`, attaches SLSA build-provenance attestations, and opens a draft release. Signing, key custody, SBOM, and license-audit steps are specified in `docs/RELEASE.md`.
