# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-04-05

### Added

- `--no-color` global CLI flag to disable colored output
- Automatic color disabling when `NO_COLOR` environment variable is set (per https://no-color.org/)
- Automatic color disabling when stdout is not a TTY (piped output)

## [0.2.0] - 2025-06-01

### Fixed

- Reduced false positives by skipping dist/build directories, safe install scripts, and stricter child_process regex
- Cache tests use temp dirs to avoid race conditions in CI
- Correct binary name in release workflow (aegis to aegis-scan)

### Changed

- Added permissions block to quality workflow
