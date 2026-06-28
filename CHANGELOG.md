# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to the project-wide date-based versioning scheme
(`YYYY.MM.DD.N`).

## [Unreleased]

## [0.0.1]

### Note

This was the version stamped in the `VERSION` file before the date-based
scheme was adopted in `2026-06-27`. It is recorded here only as a marker
for the historical baseline; no per-feature release notes were maintained
prior to this point. See `git log` for granular history before the
adoption of this changelog.

Notable history (most recent first, sourced from `git log`):

- `2026-06-27` — Handed `capture_traffic.sh` (script + 109-line README) and
  `screenshot.sh` (script + 85-line README) over to `pentest_setup`. These
  were the only two files in the repo that the rest of the stack actually
  consumed; everything else here is standalone one-off utilities.
- `2025-09-11` — Introduced `compile.sh` CI/release wrapper (later replaced
  by `make ci` / `make release-today`).
- `2024-12-08` — Initial collection of Bash one-off utilities.

Subsequent releases use date-based versioning and carry per-release notes.
