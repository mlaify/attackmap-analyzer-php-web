# attackmap-analyzer-php-web

> [!IMPORTANT]
> **Active development, slow pace.** AttackMap is under active development, but
> progress may be slow until more contributors or co-maintainers join. Help is
> very welcome with the core engine, an analyzer, the macOS app, or the docs —
> see [CONTRIBUTING.md](CONTRIBUTING.md) or open an issue on
> [mlaify/AttackMap](https://github.com/mlaify/AttackMap/issues) to say hello.
> Security reports are still welcome at [security@mlaify.io](mailto:security@mlaify.io).

Broad PHP web analyzer for [AttackMap](https://github.com/mlaify/AttackMap).

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

- `composer.json` present, or
- at least one `.php` file outside `vendor/` (and the other shared skip dirs)

A `src/`, `app/` or `config/` directory on its own is not enough, since Python, Go and Java repos have those too.

## Extraction strategy

`analyze(repo_path)` scans `.php` files and emits structured signals using regular-expression heuristics.

Route extraction currently includes patterns such as:

- `Route::get(...)`/`Route::post(...)` style calls
- `$app->get('/path', ...)` style calls. The path must start with `/`, and the receiver must be `$app`, `$router`, `$route`, `$group` or `$r`, a variable assigned from `AppFactory::create()` / `new RouteCollector` / `new App`, or a parameter typed `RouteCollectorProxy` / `RouteCollector` / `App`. This keeps `$request->get('id')` and `$cache->get('k')` out.
- PHP attributes like `#[Route("/path", methods: ["GET"]) ]`
- config-style `"path" => "/..."`, only in files that also declare a `'routes'` / `'router'` key (so Laravel's `config/logging.php` paths aren't routes)

Outbound calls currently include patterns such as:

- `curl_init("https://...")`
- `file_get_contents("https://...")`
- common HTTP client calls such as `->request(...)`, `->get(...)`, `->post(...)`

Datastore/auth/secret hints are similarly heuristic and intended as first-pass signals. Secret hints are env var names (`getenv`, `$_ENV`, `$_SERVER`) containing `SECRET`, `TOKEN`, `KEY`, `PASSWORD` or `PASSWD`. `DB_HOST`-style connection settings are not secrets. `jwt` needs a JWT library (`Firebase\JWT\JWT`, `JWT::decode/encode`, `Lcobucci\JWT`, `tymon/jwt-auth`), and `auth` needs the `Auth::` facade or a chained `auth()->…` helper.

## Installation

```bash
pip install git+https://github.com/mlaify/attackmap-analyzer-php-web.git
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
3. namespace/package scanning in `github.com/mlaify`

This repository does not implement core-side discovery logic.

## Limitations

- regex-based extraction (not AST)
- limited config route parsing
- no framework-specific deep parsing yet
- no dataflow or reachability modeling inside this analyzer

These are deliberate to keep this first external analyzer incremental and maintainable.
