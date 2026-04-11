# attackmap-analyzer-php-web

Broad PHP web analyzer for [AttackMap](https://gitlab.com/matthewd.xyzAI/attackmap).

This repository is intentionally separate from AttackMap core. It focuses only on extracting structured signals from PHP repositories:

- routes
- outbound HTTP calls
- datastore hints
- auth hints
- secret and env usage

It does not render reports and does not own global severity policy.

## Analyzer identity

- `name`: `php-web`
- `display_name`: `PHP Web Analyzer`
- `version`: `0.1.0`
- `experimental`: `true`
- `enabled_by_default`: `false`

## Scope

This analyzer is broad and heuristic. It is meant to map common PHP web application surfaces before framework-specific analyzers (for example `php-laminas` or `omeka-s`) are added.

## Detection strategy

`detect(repo_path)` uses lightweight signals:

- `composer.json` present
- at least one `.php` file
- common PHP app layout (`src/`, `app/`, `module/`, `public/`)

## Extraction strategy

`analyze(repo_path)` scans `.php` files and emits structured signals using regular-expression heuristics.

Route extraction currently includes patterns such as:

- `Route::get(...)`/`Route::post(...)` style calls
- `$app->get(...)` style calls
- PHP attributes like `#[Route("/path", methods: ["GET"]) ]`
- basic config-style `"path" => "/..."`

Outbound calls currently include patterns such as:

- `curl_init("https://...")`
- `file_get_contents("https://...")`
- common HTTP client calls such as `->request(...)`, `->get(...)`, `->post(...)`

Datastore/auth/secret hints are similarly heuristic and intended as first-pass signals.

## Installation

```bash
pip install attackmap-analyzer-php-web
```

For local development:

```bash
pip install -e .[dev]
```

## Contract alignment with AttackMap core

This package targets the current AttackMap analyzer contract:

- analyzer exposes metadata via `metadata`
- analyzer implements `detect(repo_path)` and `analyze(repo_path)`
- `analyze` returns AttackMap-style structured scan data (`ScanResult` shape)

The package includes a small compatibility layer so tests can run even if AttackMap core is not installed.

## Future core discovery (documented, not implemented here)

AttackMap core can discover this analyzer later via one of these options:

1. entry points (preferred long-term)
2. explicit configured analyzer list
3. namespace/package scanning in `matthewd.xyzAI/attackmap-analyzers`

This repository does not implement core-side discovery logic.

## Limitations

- regex-based extraction (not AST)
- limited config route parsing
- no framework-specific deep parsing yet
- no dataflow or reachability modeling inside this analyzer

These are deliberate to keep this first external analyzer incremental and maintainable.
