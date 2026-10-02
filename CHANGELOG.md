# Changelog

All notable changes to `attackmap-analyzer-php-web` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed — AttackMap#253

- **Repo walking now uses `attackmap.sdk.fs`.** `detect()` and `analyze()` walk with `iter_repo_files` and read with `read_source`. Skip dirs are matched by repo-relative name and pruned, so a repo checked out under a `vendor/` directory is analyzed instead of yielding no PHP files.
- **Symlinked files pointing outside the repo are not analyzed**, unreadable files no longer raise out of `analyze()`, and cp1252/latin-1 PHP sources are decoded instead of silently dropped. AttackMap's own report directories are skipped.
- `detect()` stops at the first `.php` file and no longer walks `vendor/` or `node_modules/`.

### Changed

- Skip list is now the SDK's `DEFAULT_SKIP_DIRS` (was `vendor`, `.git`, `node_modules`; adds `build`, `dist`, `out`, `target`, virtualenvs and caches).
- Signal `file` paths are always POSIX-style (`src/routes.php`), including on Windows.
- Requires an AttackMap core that ships `attackmap.sdk.fs`.

## [0.1.0] - 2026-06-04

### Added

- Initial public release. Broad PHP web analyzer plugin for AttackMap
- Registered under the `attackmap.analyzers` entry-point group so the core
  AttackMap CLI auto-discovers this analyzer once installed.
- Emits Signal-v2 records (`file:line` citation, evidence text, and confidence
  score) for every signal.

[Unreleased]: https://github.com/mlaify/attackmap-analyzer-php-web/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/mlaify/attackmap-analyzer-php-web/releases/tag/v0.1.0
