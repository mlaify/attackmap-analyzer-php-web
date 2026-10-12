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

- Laravel `Route::get|post|put|patch|delete|options|head|any(...)`, array-first `Route::match(['get', 'post'], ...)`, and a scope chained before the verb (`Route::middleware('auth')->get(...)`). `Route::resource` / `apiResource` / `resources` / `apiResources` expand to their REST routes (7 / 5 actions; `update` is `PUT` and `PATCH`), honouring `->only()` / `->except()` / `->shallow()`, an `['only' => ...]` options array and nested `photos.comments` names.
- Laravel groups: `Route::prefix('admin')->middleware(...)->group(function () { ... })` and `Route::group(['prefix' => ..., 'middleware' => ...], fn)` join their prefixes onto the routes inside, at any nesting depth up to 32. `Route::controller(C::class)->group(...)` dispatches bare method names to `C`.
- Laravel route files take the prefix and middleware of the group that loads them: `->group(base_path('routes/admin.php'))`, `require base_path(...)` / `$this->loadRoutesFrom(__DIR__.'/...')` inside a group, and `withRouting(api: ... | [...], apiPrefix: ...)` in `bootstrap/app.php`. `routes/api.php` defaults to `/api` when nothing mounts it. A `config('file.key')` prefix is read from `config/file.php` (a literal or an `env()` default), and any other non-literal prefix becomes a `{prefix}` segment.
- `$app->get('/path', ...)` / `$app->map(['GET', 'POST'], '/path', ...)` Slim calls. The path must start with `/`, and the receiver must be `$app`, `$router`, `$route`, `$group` or `$r`, a variable assigned from `AppFactory::create()` / `new RouteCollector` / `new App`, or a parameter typed `RouteCollectorProxy` / `RouteCollector` / `App`. This keeps `$request->get('id')` and `$cache->get('k')` out. Slim `$app->group('/v1', ...)` and Lumen `$router->group(['prefix' => 'api'], ...)` prefixes are joined.
- Symfony `#[Route('/path', methods: ['GET'])]` (or `path:`) attributes, joined onto the class-level `#[Route('/prefix')]` (whose `methods` merge in). A class-level route is a route of its own only on a controller with no routed actions (`__invoke`).
- Symfony route config: `config/routes.yaml`, `config/routes/*.yaml` / `*.xml` and `app/config/routing.yml` `path` / `methods` entries, and `resource` imports with a `prefix`, applied to attribute controllers under the imported directory (or `routing.controllers`, i.e. `src/`) or to an imported local route file. A later import of the same controllers or route file replaces the earlier one (Symfony keys routes by name), so each route is reported once, under the last prefix. A localized prefix map becomes a `{prefix}` segment. Localized path maps and `when@dev` / `when@test` blocks are skipped.
- config-style `"path" => "/..."`, only in files that also declare a `'routes'` / `'router'` key (so Laravel's `config/logging.php` paths aren't routes)

Brackets are matched in one string-, comment- and heredoc-aware pass per file, so a commented-out `Route::get(...)` is not a route and a `}` inside a string doesn't end a group.

Each route carries `auth`, `guards` and `guard_evidence` (AttackMap#256):

| State | When |
|---|---|
| `required` | Laravel `->middleware('auth'…)` on the route, an enclosing `Route::middleware([...])->group(...)` / `Route::group(['middleware' => ...], ...)`, or the controller's `$this->middleware('auth')` (honouring `->only()` / `->except()`); Slim `->add($authMiddleware)` / `->add(new JwtAuthentication(...))` on the route or an enclosing `->group(...)`; Symfony `#[IsGranted]` / `#[Security]` on the action or its class, or a matching `security.yaml` `access_control` rule |
| `anonymous` | Laravel `->withoutMiddleware('auth')` on the route or a group, or a controller `->except([...])` naming the action; Symfony `#[IsGranted('PUBLIC_ACCESS')]` or an `access_control` rule granting `PUBLIC_ACCESS` — when nothing else requires auth |
| `unknown` | anything else |

`access_control` is only applied to rules with literal `^/prefix` paths. A rule with `ips`, `host`, `allow_if` or a regex path stops resolution for the routes after it. Rules are matched against the full path (class and import prefixes joined); attribute routes under an import prefix that can't be read (a localized prefix map) are skipped. Laravel 11 `HasMiddleware::middleware()` controllers, Slim app-wide `$app->add(...)` and `can:` middleware aren't resolved.

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
- limited config route parsing; the Symfony YAML/XML readers cover the shapes Symfony's docs and recipes use, not full YAML/XML
- Laravel route names (`->name()` / `'as'`), `Route::view` / `Route::redirect` / `Route::singleton`, and resource `->parameters([...])` renames aren't modelled
- no framework-specific deep parsing yet
- no dataflow or reachability modeling inside this analyzer

These are deliberate to keep this first external analyzer incremental and maintainable.
