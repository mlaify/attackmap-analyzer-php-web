# Changelog

All notable changes to `attackmap-analyzer-php-web` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed — false positives on ordinary PHP (#2)

- **`$obj->get('key')` is no longer a route.** Slim-style `$x->get(...)` routes need a path that starts with `/` and a router receiver. That means `$app`, `$router`, `$route`, `$group` or `$r`, a variable assigned from `AppFactory::create()` / `Bridge::create()` / `new App` / `new RouteCollector`, or a parameter typed `RouteCollectorProxy` / `RouteCollector` / `App` (route-group closures). `$request->get('id')`, `$cache->get('user:…')`, `$config->get(…)` and `$session->get(…)` are no longer GET routes.
- **Config `'path' =>` routes need a routes table.** They are only read from files that declare a `'routes'` or `'router'` key, and the path must start with `/`. Laravel's `config/logging.php` no longer yields `ANY /var/log/laravel.log`.
- **`DB_*` / `API_*` settings are not secrets.** Secret env names must contain `SECRET`, `TOKEN`, `KEY`, `PASSWORD` or `PASSWD`, matched case-sensitively. `getenv('DB_HOST')` and `getenv('API_URL')` no longer match. `DB_PASSWORD`, `API_KEY` and `API_TOKEN` still do.
- **`jwt` needs a JWT library.** The case-insensitive `JWT` substring matched any `$jwtSecret` variable or comment. The hint now needs `Firebase\JWT\JWT`, `JWT::decode/encode`, `Lcobucci\JWT`, `tymon/jwt-auth` or `JWTAuth::`.
- **`auth` needs Laravel's facade or helper.** `\bauth\s*\(` matched any `auth(` function or method. The hint now needs `Auth::` or a chained `auth()->…` / `auth('guard')->…`. `->middleware('auth:sanctum')` (a guard suffix) now counts as `auth_middleware`.
- **`detect()` no longer fires on any repo with `src/`.** A `src/`, `app/`, `module/`, `public/` or `config/` directory alone used to make php-web run on Python, Go and Java repos. It now needs `composer.json` or a `.php` file outside `vendor/` and the other shared skip dirs.

### Changed — typed signals instead of overloaded `AuthHint`s (AttackMap#258)

- **`http_client` is now a `FrameworkHint`, not an `AuthHint`.** A Guzzle / `symfony/http-client` entry in `composer.json` says the app *can* make outbound HTTP calls; it isn't an auth signal, and it isn't an `ExternalCall` either (there's no target, and core would draw a fake peer from it). It is emitted as `FrameworkHint(hint="http_client", file="composer.json")` pointing at the package's line. `auth_hints` now carries only auth signals (`session`, `password_hash`, `password_verify`, `jwt`, `auth_middleware`, `auth`); `firebase/php-jwt` in `composer.json` stays a `jwt` `AuthHint`.
- **Every signal now cites a line and quotes it.** Routes, external calls, databases, auth/framework hints and secret hints carry `line` and (where the model has it) `evidence_text` via `attackmap.sdk.line_of` / `line_snippet`. Composer-declared signals point at the package's line in `composer.json`.
- New `tests/test_signal_conformance.py` asserts every emitted `AuthHint.hint` is in an explicit auth allow-list and every signal has an in-range `line` and evidence.

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
