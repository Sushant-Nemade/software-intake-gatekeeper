# Changelog

All notable changes are recorded here. The project follows [Semantic Versioning](https://semver.org/);
while the major version is 0, minor releases may change behaviour.

## [0.1.0] - 2026-10-14

First public release and first GitHub Marketplace listing.

### Added

- Read-only scanner for directories, Electron `.asar` archives and executables (PE, ELF, Mach-O).
- Inventories: Go build info (Go 1.18+), npm packages on disk and inside ASAR, NuGet `.deps.json`
  packages and runtime packs, .NET `runtimeconfig.json` frameworks, Electron runtime version.
- Electron hardening: fuse-wire decoding (9 fuses) and `webPreferences` rules with line, column and snippet evidence.
- Opt-in OSV.dev lookup: batching, pagination, retries, alias grouping, GHSA severity resolution and nearest fixed version.
- Policy file with thresholds, rule overrides and expiring, component-scoped waivers. APPROVE / REVIEW / REJECT decision; blocking coverage gaps prevent APPROVE.
- Reports: JSON, CycloneDX 1.6, SARIF 2.1.0 (paths relative to the working directory for code scanning) and Markdown.
- Composite GitHub Action with hash-pinned dependencies, job summary and `decision`, `sarif` and `sbom` outputs.

### Known limitations

- Version-level matching, not reachability analysis.
- No Rust `cargo auditable`, Python wheel, Java or native C/C++ inventories yet.
- Electron code rules detect literal settings only.

[0.1.0]: https://github.com/Sushant-Nemade/software-intake-gatekeeper/releases/tag/v0.1.0
