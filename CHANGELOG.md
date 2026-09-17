# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0] - 2026-09-17
### Added
- `ConnectionTimeoutError` and working `timeout` enforcement on all `ClamdAsyncClient` calls (the constructor argument was previously accepted but never applied)
- Optional `max_size` parameter on `instream()` to cap stream size client-side, instead of relying solely on clamd's own `StreamMaxLength`
- `Dockerfile` bundling `clamd` with this package for local dev/integration testing
- PyPI Trusted Publishing (OIDC) for the publish workflows

### Changed
- Bumped minimum supported Python to 3.9
- Switched packaging from Poetry to standard `setuptools`/`build`
- `recv_response()` now bounds the amount of data read from clamd instead of reading until EOF unconditionally
- `instream()` no longer blocks the event loop while reading from the source buffer

### Fixed
- `import aioclamd` no longer breaks on environments without `pkg_resources` (switched to `importlib.metadata`)
- `SCAN`/`CONTSCAN`/`MULTISCAN` now reject file paths containing embedded newlines
- Missing `writer.drain()` calls in the `instream` upload loop

## [1.0.0] - 2022-09-16
### Added
- Wrote the first implementation
- Added Tests
- Added README 
- Added this changelog
- Added MIT License

[Unreleased]: https://github.com/hbldh/aioclamd/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/hbldh/aioclamd/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/hbldh/aioclamd/releases/tag/v1.0.0