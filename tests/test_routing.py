"""Route paths: Laravel groups/prefixes/resources/mounts, Slim/Lumen group
prefixes, Symfony class and import prefixes and YAML/XML route config (#3)."""

from __future__ import annotations

import random
import time
from pathlib import Path

import pytest

from attackmap_analyzer_php_web import PhpWebAnalyzer
from attackmap_analyzer_php_web import laravel_routes as lr
from attackmap_analyzer_php_web import route_auth as ra
from attackmap_analyzer_php_web import symfony_routes as sf

FIXTURES = Path(__file__).parent / "fixtures"


def _routes(root: Path) -> dict:
    return {f"{r.method} {r.path}": r for r in PhpWebAnalyzer().analyze(root).routes}


def _write(root: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


# ---------- Laravel ----------


def test_issue_fixture_prefix_match_and_resources() -> None:
    routes = _routes(FIXTURES / "laravel_routing_repo")
    api = {key for key, r in routes.items() if r.file == "routes/api.php"}
    users = routes["GET /api/admin/users"]
    assert users.auth == "required"
    assert users.guards == ["auth:sanctum"]
    assert {"GET /api/both", "POST /api/both"} <= api
    photos = {key for key in api if "/photos" in key}
    assert photos == {
        "GET /api/photos",
        "GET /api/photos/create",
        "POST /api/photos",
        "GET /api/photos/{photo}",
        "GET /api/photos/{photo}/edit",
        "PUT /api/photos/{photo}",
        "PATCH /api/photos/{photo}",  # update is PUT|PATCH: 7 actions, 8 routes
        "DELETE /api/photos/{photo}",
    }
    posts = {key for key in api if "/posts" in key}
    assert posts == {
        "GET /api/posts",
        "POST /api/posts",
        "GET /api/posts/{post}",
        "PUT /api/posts/{post}",
        "PATCH /api/posts/{post}",
        "DELETE /api/posts/{post}",
    }
    # Nothing un-prefixed leaks out of api.php.
    assert all(key.split(" ", 1)[1].startswith("/api/") for key in api)


def test_resource_actions_use_controller_constructor_guards() -> None:
    routes = _routes(FIXTURES / "laravel_routing_repo")
    # PhotoController: `$this->middleware('auth')->except(['index', 'show'])`.
    assert routes["GET /api/photos"].auth == "anonymous"
    assert routes["GET /api/photos/{photo}"].auth == "anonymous"
    assert routes["POST /api/photos"].auth == "required"
    assert routes["DELETE /api/photos/{photo}"].guards == ["auth"]


def test_groups_join_prefixes_and_apply_middleware() -> None:
    routes = _routes(FIXTURES / "laravel_routing_repo")
    # Legacy `Route::group(['prefix' => ..., 'middleware' => [...]])`.
    assert routes["GET /dashboard"].auth == "required"
    assert routes["GET /dashboard"].guard_evidence == "'middleware' => ['web', 'auth']"
    # A nested fluent group: prefixes join, the trailing slash is trimmed.
    assert routes["GET /dashboard/reports/{report}"].auth == "required"
    # `withoutMiddleware` inside the group: a brace and quote in a string
    # comment between don't end the group early.
    assert routes["POST /dashboard/reports/export"].auth == "anonymous"
    # Scope chained before a verb.
    assert routes["DELETE /account"].auth == "required"
    assert routes["DELETE /account"].guards == ["auth"]
    assert routes["GET /v1/status"].auth == "unknown"


def test_resource_options_nesting_and_plural_form() -> None:
    routes = _routes(FIXTURES / "laravel_routing_repo")
    web = {key for key, r in routes.items() if r.file == "routes/web.php"}
    assert {k for k in web if "/invoices" in k} == {"GET /invoices", "GET /invoices/{invoice}"}
    assert {k for k in web if "/tags" in k} == {
        "GET /tags",
        "POST /tags",
        "GET /tags/{tag}",
        "PUT /tags/{tag}",
        "PATCH /tags/{tag}",
        "DELETE /tags/{tag}",
    }
    # `photos.comments` nested, shallow members, `->only('index', 'update')`.
    assert {k for k in web if "comments" in k} == {
        "GET /photos/{photo}/comments",
        "PUT /comments/{comment}",
        "PATCH /comments/{comment}",
    }
    assert len({k for k in web if "/teams" in k}) == 8  # Route::resources([...])


def test_controller_group_dispatches_bare_method_names() -> None:
    routes = _routes(FIXTURES / "laravel_routing_repo")
    # Route::controller(ReportController::class)->group(... Route::get('/archive', 'archive'))
    # and ReportController guards `->only(['archive'])`.
    assert routes["GET /archive"].auth == "required"


def test_commented_out_and_heredoc_routes_are_not_routes() -> None:
    routes = _routes(FIXTURES / "laravel_routing_repo")
    paths = {key.split(" ", 1)[1] for key in routes}
    assert "/commented-out" not in paths
    assert "/also-commented" not in paths
    assert "/in-heredoc" not in paths
    # The heredoc's unbalanced `) ( }` doesn't swallow what follows.
    assert "GET /after-heredoc" in routes


def test_route_files_inherit_the_mount_prefix_and_middleware() -> None:
    routes = _routes(FIXTURES / "laravel_routing_repo")
    # RouteServiceProvider: middleware(['web', 'auth'])->prefix('admin')->group(base_path('routes/admin.php')).
    audit = routes["GET /admin/audit"]
    assert audit.file == "routes/admin.php"
    assert audit.auth == "required"
    # web.php `require __DIR__.'/auth.php'`: mounted, no prefix.
    assert routes["POST /login"].file == "routes/auth.php"


def test_routes_api_php_defaults_to_api_prefix(tmp_path: Path) -> None:
    _write(tmp_path, {"routes/api.php": "<?php\nRoute::get('user', fn () => 1)->middleware('auth:sanctum');\n"})
    routes = _routes(tmp_path)
    assert list(routes) == ["GET /api/user"]
    assert routes["GET /api/user"].auth == "required"


def test_bootstrap_app_api_prefix(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "routes/api.php": "<?php\nRoute::get('/user', fn () => 1);\n",
            "routes/web.php": "<?php\nRoute::get('/', fn () => 1);\n",
            "bootstrap/app.php": (
                "<?php\nreturn Application::configure(basePath: dirname(__DIR__))\n"
                "    ->withRouting(\n"
                "        web: __DIR__.'/../routes/web.php',\n"
                "        api: __DIR__.'/../routes/api.php',\n"
                "        apiPrefix: 'api/v2',\n"
                "    )->create();\n"
            ),
        },
    )
    assert set(_routes(tmp_path)) == {"GET /api/v2/user", "GET /"}


def test_provider_mount_replaces_the_default_api_prefix(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "routes/api.php": "<?php\nRoute::post('/sync', fn () => 1);\n",
            "app/Providers/RouteServiceProvider.php": (
                "<?php\nRoute::group(['prefix' => 'v3', 'middleware' => 'auth:api'], function () {\n"
                "    require base_path('routes/api.php');\n});\n"
            ),
        },
    )
    routes = _routes(tmp_path)
    assert list(routes) == ["POST /v3/sync"]
    assert routes["POST /v3/sync"].guards == ["auth:api"]


def test_package_load_routes_from_claims_routes_api_php(tmp_path: Path) -> None:
    # A package provider loads its own routes/api.php with no prefix.
    _write(
        tmp_path,
        {
            "routes/api.php": "<?php\nRoute::get('/status', fn () => 1);\n",
            "src/PackageServiceProvider.php": (
                "<?php\nclass PackageServiceProvider {\n    public function boot() {\n"
                "        $this->loadRoutesFrom(__DIR__.'/../routes/api.php');\n    }\n}\n"
            ),
        },
    )
    assert list(_routes(tmp_path)) == ["GET /status"]


def test_config_prefix_is_read_from_the_config_file(tmp_path: Path) -> None:
    # Laravel Cashier: Route::group(['prefix' => config('cashier.path')], ...).
    _write(
        tmp_path,
        {
            "config/cashier.php": "<?php\nreturn [\n    'path' => env('CASHIER_PATH', 'stripe'),\n];\n",
            "src/CashierServiceProvider.php": (
                "<?php\nRoute::group([\n    'prefix' => config('cashier.path'),\n    'as' => 'cashier.',\n"
                "], function () {\n    $this->loadRoutesFrom(__DIR__.'/../routes/web.php');\n});\n"
            ),
            "routes/web.php": "<?php\nRoute::post('webhook', 'WebhookController@handleWebhook')->name('webhook');\n",
        },
    )
    assert list(_routes(tmp_path)) == ["POST /stripe/webhook"]


def test_unreadable_prefix_is_a_placeholder_not_a_wrong_path(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "routes/web.php": (
                "<?php\nRoute::prefix(LaravelLocalization::setLocale())->group(function () {\n"
                "    Route::get('/about', fn () => 1);\n});\n"
                "Route::prefix(config('missing.key'))->group(function () {\n"
                "    Route::get('/faq', fn () => 1);\n});\n"
            ),
        },
    )
    assert set(_routes(tmp_path)) == {"GET /{prefix}/about", "GET /{prefix}/faq"}


def test_mount_cycle_does_not_recurse(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "routes/a.php": "<?php\nRoute::prefix('a')->group(base_path('routes/b.php'));\nRoute::get('/x', fn () => 1);\n",
            "routes/b.php": "<?php\nRoute::prefix('b')->group(base_path('routes/a.php'));\nRoute::get('/y', fn () => 1);\n",
        },
    )
    routes = _routes(tmp_path)
    assert set(routes) == {"GET /{prefix}/x", "GET /{prefix}/y"}
    assert all(r.auth == "unknown" for r in routes.values())


def test_with_routing_api_array_prefixes_every_file(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "routes/api.php": "<?php\nRoute::get('/user', fn () => 1);\n",
            "routes/api_admin.php": "<?php\nRoute::delete('/users/{id}', fn () => 1);\n",
            "bootstrap/app.php": (
                "<?php\nreturn Application::configure(basePath: dirname(__DIR__))\n"
                "    ->withRouting(\n"
                "        api: [__DIR__.'/../routes/api.php', __DIR__.'/../routes/api_admin.php'],\n"
                "        apiPrefix: 'api/v1',\n"
                "    )->create();\n"
            ),
        },
    )
    assert set(_routes(tmp_path)) == {"GET /api/v1/user", "DELETE /api/v1/users/{id}"}


def test_route_controller_beats_the_enclosing_group_controller(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "routes/web.php": (
                "<?php\nRoute::controller(A::class)->group(function () {\n"
                "    Route::controller(B::class)->delete('/x', 'destroy');\n"
                "    Route::get('/y', 'destroy');\n});\n"
            ),
            "app/A.php": "<?php\nclass A {\n    public function __construct() {\n        $this->middleware('auth');\n    }\n}\n",
            "app/B.php": "<?php\nclass B {\n    public function __construct() {\n        $this->middleware('auth')->except(['destroy']);\n    }\n}\n",
        },
    )
    routes = _routes(tmp_path)
    assert routes["DELETE /x"].auth == "anonymous"  # B's except, not A's guard
    assert routes["GET /y"].auth == "required"  # the group's A


def _mount_graph(tmp_path: Path, edges: dict[str, list[str]]) -> None:
    files = {}
    for source, targets in edges.items():
        body = "".join(f"require base_path('routes/{t}.php');\n" for t in targets)
        files[f"routes/{source}.php"] = f"<?php\nRoute::prefix('{source}')->group(function () {{\n{body}}});\n" + (
            f"Route::get('/{source}', fn () => 1);\n"
        )
    _write(tmp_path, files)


def test_dense_mutual_mounts_stay_fast(tmp_path: Path) -> None:
    names = [f"f{i}" for i in range(16)]
    _mount_graph(tmp_path, {n: [m for m in names if m != n] for n in names})
    start = time.perf_counter()
    result = PhpWebAnalyzer().analyze(tmp_path)
    assert time.perf_counter() - start < 5.0
    assert len(result.routes) >= len(names)


def test_deep_layered_mounts_stay_fast(tmp_path: Path) -> None:
    layers = [[f"l{d}n{i}" for i in range(9)] for d in range(12)]
    edges = {name: (layers[d + 1] if d + 1 < len(layers) else []) for d, layer in enumerate(layers) for name in layer}
    _mount_graph(tmp_path, edges)
    start = time.perf_counter()
    routes = _routes(tmp_path)
    assert time.perf_counter() - start < 5.0
    # Layer 1 is mounted only under layer 0's groups.
    assert any(key.startswith("GET /l0n0/l1n0") for key in routes)


def test_many_mount_refs_and_with_routing_calls_stay_fast(tmp_path: Path) -> None:
    content = "<?php\n" + "->withRouting(api: __DIR__.'/../routes/api.php')\n" * 6000 + (
        "require base_path('routes/x.php');\n" * 12000
    )
    _write(tmp_path, {"bootstrap/app.php": content, "routes/api.php": "<?php\nRoute::get('/u', fn () => 1);\n"})
    start = time.perf_counter()
    PhpWebAnalyzer().analyze(tmp_path)
    assert time.perf_counter() - start < 5.0


def test_singular_and_resource_expansion() -> None:
    assert [lr.singular(w) for w in ("photos", "categories", "boxes", "news-items", "status")] == [
        "photo",
        "category",
        "box",
        "news_item",
        "status",
    ]
    assert lr.resource_routes("admin/users", True, {"show"}, set(), False) == [
        ("GET", "admin/users/{user}", "show")
    ]
    assert lr.resource_routes("", False, None, set(), False) == []
    assert lr.resource_routes("...", False, None, set(), False) == []


# ---------- Slim / Lumen ----------


def test_slim_map_and_group_prefixes(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "app.php": (
                "<?php\n$app = AppFactory::create();\n"
                "$app->map(['GET', 'POST'], '/form', function ($req, $res) { return $res; });\n"
                "$app->group('/v1', function (RouteCollectorProxy $group) {\n"
                "    $group->group('/users', function (RouteCollectorProxy $users) {\n"
                "        $users->delete('/{id}', function ($req, $res) { return $res; });\n"
                "    });\n"
                "});\n"
                "$app->group($base, function (RouteCollectorProxy $g) {\n"
                "    $g->get('/dyn', function ($req, $res) { return $res; });\n"
                "});\n"
            ),
            "lumen.php": (
                "<?php\n$router->group(['prefix' => 'api/', 'middleware' => 'auth'], function () use ($router) {\n"
                "    $router->get('/books', 'BookController@index');\n});\n"
            ),
        },
    )
    assert set(_routes(tmp_path)) == {
        "GET /form",
        "POST /form",
        "DELETE /v1/users/{id}",
        "GET /{prefix}/dyn",
        "GET /api/books",
    }


# ---------- Symfony ----------


def test_symfony_class_and_import_prefixes() -> None:
    routes = _routes(FIXTURES / "symfony_routing_repo")
    # config/routes.yaml imports src/Controller/ under /app; #[Route('/blog')] on the class.
    assert routes["GET /app/blog/"].file == "src/Controller/BlogController.php"
    assert "GET /app/blog/{slug}" in routes  # `path:` named argument, `methods: 'GET'`
    assert "POST /app/blog/comment" in routes  # after a `#[` inside a comment
    # The class-level #[Route] is a prefix, not a route of its own.
    assert not any(key.endswith(" /app/blog") for key in routes)
    # `#[Route('/admin', methods: ['GET']), IsGranted('ROLE_ADMIN')]` in one group:
    # class methods merge into each action's, and the guard applies.
    assert routes["GET /app/admin/stats"].auth == "required"
    assert routes["GET /app/admin/stats"].guards == ["IsGranted('ROLE_ADMIN')"]
    assert {"GET /app/admin/purge", "POST /app/admin/purge"} <= set(routes)
    # An invokable controller's class route is the route.
    export = routes["POST /app/reports/export"]
    assert export.file == "src/Controller/ReportExportController.php"
    # access_control is matched against the joined path.
    assert export.guards == ["access_control ^/app/reports: ROLE_ANALYST"]


def test_symfony_yaml_and_xml_routes() -> None:
    routes = _routes(FIXTURES / "symfony_routing_repo")
    config = {key: r for key, r in routes.items() if r.file.startswith("config/")}
    assert set(config) == {
        "ANY /",
        "POST /legacy/export",
        "PUT /legacy/export",
        "POST /partners/sync",  # partners.yaml imported with prefix /partners
        "GET /health",
        "HEAD /health",
        "POST /hooks/{provider}",
    }
    assert config["POST /legacy/export"].line == 15
    assert config["POST /legacy/export"].auth == "required"
    assert config["POST /partners/sync"].file == "config/partners.yaml"
    # Not routes: the localized path map, the when@dev route, the XML comment.
    paths = {key.split(" ", 1)[1] for key in routes}
    assert not {"/about-us", "/_dev/tools", "/old-admin"} & paths


def test_symfony_unreadable_import_prefix_skips_access_control(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "config/routes.yaml": (
                "controllers:\n    resource: ../src/Controller/\n    type: attribute\n"
                "    prefix:\n        en: /en\n        nl: /nl\n"
            ),
            "config/packages/security.yaml": "security:\n    access_control:\n        - { path: ^/, roles: PUBLIC_ACCESS }\n",
            "src/Controller/A.php": "<?php\nclass A {\n    #[Route('/a', methods: ['POST'])]\n    public function a() {}\n}\n",
        },
    )
    route = PhpWebAnalyzer().analyze(tmp_path).routes[0]
    # The real path is /en/a or /nl/a: the prefix is marked unknown, and
    # access_control (which would otherwise grant `^/`) isn't matched.
    assert (route.path, route.auth) == ("/{prefix}/a", "unknown")


def test_repeated_imports_of_the_same_target_keep_the_last_prefix(tmp_path: Path) -> None:
    # Symfony keys routes by name: a later import of the same controllers
    # replaces the earlier one, so each route exists once, under the last prefix.
    imports = "".join(
        f"c{i}: {{ resource: ../../src/Controller/, type: attribute, prefix: /p{i} }}\n" for i in range(2000)
    )
    files = {f"config/routes/r{j}.yaml": imports for j in range(16)}
    files["config/routes/zz.yaml"] = "again:\n    resource: ../../src/Controller/\n    type: attribute\n    prefix: /last\n"
    files["config/routes/zz_files.yaml"] = "".join(
        f"f{i}:\n    resource: ../legacy.yaml\n    prefix: /v{i}\n" for i in range(50)
    )
    files["config/legacy.yaml"] = "legacy:\n    path: /old\n"
    files["src/Controller/A.php"] = "<?php\nclass A {\n" + "".join(
        f"    #[Route('/a{i}', methods: ['GET'])]\n    public function a{i}() {{}}\n" for i in range(40)
    ) + "}\n"
    _write(tmp_path, files)
    start = time.perf_counter()
    routes = _routes(tmp_path)
    assert time.perf_counter() - start < 5.0
    attribute = [key for key, r in routes.items() if r.file == "src/Controller/A.php"]
    assert len(attribute) == 40
    assert all(key.startswith("GET /last/a") for key in attribute)
    legacy = [key for key, r in routes.items() if r.file == "config/legacy.yaml"]
    assert len(legacy) == 1


def test_localized_import_prefix_is_a_placeholder(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "config/routes.yaml": (
                "controllers:\n    resource: ../src/Controller/\n    type: attribute\n"
                "    prefix: {en: '', nl: '/nl'}\n"
                "shop:\n    resource: shop.yaml\n    prefix:\n        en: /shop\n        nl: /winkel\n"
            ),
            "config/shop.yaml": "cart:\n    path: /cart\n    methods: [POST]\n",
            "src/Controller/A.php": "<?php\nclass A {\n    #[Route('/a')]\n    public function a() {}\n}\n",
        },
    )
    assert set(_routes(tmp_path)) == {"ANY /{prefix}/a", "POST /{prefix}/cart"}


def test_route_attribute_parsing() -> None:
    assert sf.route_attribute("Route('/x', methods: ['GET', 'post'])") == sf.RouteAttr("/x", ["GET", "POST"])
    assert sf.route_attribute("\\Symfony\\Component\\Routing\\Attribute\\Route(path: \"/y\")") == sf.RouteAttr("/y", [])
    assert sf.route_attribute("Route(['en' => '/a', 'nl' => '/b'])").path is None
    assert sf.route_attribute("Route(name: 'admin_')") == sf.RouteAttr("", [])
    assert sf.route_attribute("IsGranted('ROLE_USER')") is None
    assert sf.route_attribute("Router('/z')") is None


def test_yaml_flow_mapping_entries() -> None:
    entries = sf.parse_yaml_entries(
        "a: { path: '/a', methods: [GET, POST] }\n"
        "b: { resource: ../src/, prefix: {en: '', nl: /nl}, type: attribute }\n"
        "c: { resource: {path: ../src/C/, namespace: App}, prefix: /q }\n"
    )
    assert entries[0].values == {"path": "'/a'", "methods": "[GET, POST]"}
    assert entries[1].nested == {"prefix"} and "prefix" not in entries[1].values
    assert (entries[1].values["resource"], entries[1].values["type"]) == ("../src/", "attribute")
    assert entries[2].values == {"resource.path": "../src/C/", "resource.namespace": "App", "prefix": "/q"}


def test_yaml_when_prod_block_is_read() -> None:
    entries = sf.parse_yaml_entries("when@prod:\n    status:\n        path: /status\nother:\n    path: /o\n")
    assert [(e.name, e.values.get("path")) for e in entries] == [("status", "/status"), ("other", "/o")]


# ---------- robustness ----------

_TOKENS = [
    "Route::", "get(", "group(", "prefix(", "middleware(", "resource(", "match(", "->", "(", ")", "[", "]",
    "{", "}", "'", '"', "/x", "'auth'", "function () ", "<<<EOT\n", "\nEOT;", "/*", "*/", "//", "#", "#[",
    "Route(", "class ", "\n", " ", ",", "base_path('routes/api.php')", "require ", "withRouting(", "api: ",
    "$app->", "map(", "['GET']", "::class", "only(", "except(", "=>", "'prefix'", "config('a.b')",
]
_YAML_TOKENS = ["\n", "    ", "path:", " /x", "resource:", " ../src/", "prefix:", " /p", "when@prod:", "when@dev:",
                "methods:", " [GET, POST]", "type: attribute", "- ", "{", "}", "'", "#", ":", "a"]
_XML_TOKENS = ["<route ", "<import ", 'path="/x" ', 'resource="../src/" ', 'prefix="/p" ', "/>", ">", "<!--",
               "-->", '"', "'", "methods=\"GET|POST\" ", "<", "\n"]


def _garbage(rng: random.Random, tokens: list[str], n: int) -> str:
    return "".join(rng.choice(tokens) for _ in range(n))


def test_fuzz_scanners_never_raise() -> None:
    rng = random.Random(3)
    for _ in range(300):
        php = "<?php\n" + _garbage(rng, _TOKENS, rng.randint(0, 120))
        ra.bracket_pairs.cache_clear()
        scan = lr.scan_file(php, "routes/api.php")
        for route in scan.routes:
            assert isinstance(lr.join_path([], route.uri), str)
        ra.attribute_blocks(php)
        sf.parse_yaml_entries(_garbage(rng, _YAML_TOKENS, rng.randint(0, 80)))
        sf.parse_xml_entries(_garbage(rng, _XML_TOKENS, rng.randint(0, 80)))
        files = {
            "config/routes.yaml": _garbage(rng, _YAML_TOKENS, 60),
            "config/routes/x.xml": _garbage(rng, _XML_TOKENS, 60),
        }
        sf.load_route_config(files.get, lambda d: [k for k in files if k.startswith(d + "/")])


def test_fuzz_analyzer_on_truncated_and_garbled_fixtures(tmp_path: Path) -> None:
    rng = random.Random(7)
    sources = [
        p for name in ("laravel_routing_repo", "symfony_routing_repo", "route_auth_repo")
        for p in sorted((FIXTURES / name).rglob("*")) if p.is_file()
    ]
    for i in range(40):
        repo = tmp_path / f"r{i}"
        for source in sources:
            rel_path = source.relative_to(FIXTURES).parts[1:]
            text = source.read_text(encoding="utf-8")
            cut = rng.randint(0, len(text))
            text = text[:cut] + _garbage(rng, _TOKENS, rng.randint(0, 5)) if i % 2 else text[:cut]
            _write(repo, {"/".join(rel_path): text})
        PhpWebAnalyzer().analyze(repo)  # must not raise


@pytest.mark.parametrize(
    "content",
    [
        "<?php\n" + "Route::prefix('a')->group(function () {\n" * 4000 + "Route::get('/x', 'y');\n" + "});\n" * 4000,
        "<?php\n" + "Route::prefix('a')->group(function () {\n" * 4000 + "Route::get('/x', 'y');",
        "<?php\n" + "Route::group(['prefix' => 'p'], " * 6000,
        "<?php\n" + "Route::get('/x', [A::class, 'b'])->middleware('auth')" * 4000,
        "<?php\n" + "Route::resources([" + "'a' => A::class, " * 8000 + "]);",
        "<?php\n" + "<<<A\n" * 20000,
        "<?php\n" + "Route::middleware('x')/*\n" * 10000,
        "<?php\n" + "#[Route('/a'), " * 8000,
        "<?php\n" + "require base_path('routes/api.php');\n" * 5000,
        "<?php\n" + "Route::prefix(Route::controller(" * 6000 + "'x'" + "))" * 6000 + "->group(fn () => 1);",
        "<?php\n" + "Route::group([" + "'prefix' => 'prefix' => " * 12000 + "], fn () => 1);",
    ],
    ids=["deep-groups", "unbalanced-groups", "unclosed-groups", "long-chains", "huge-resources", "heredocs", "comments", "attrs", "mounts", "nested-args", "repeated-keys"],
)
def test_adversarial_input_stays_fast(tmp_path: Path, content: str) -> None:
    _write(tmp_path, {"routes/api.php": content})
    start = time.perf_counter()
    PhpWebAnalyzer().analyze(tmp_path)
    assert time.perf_counter() - start < 5.0


def test_nesting_past_the_bound_is_a_placeholder(tmp_path: Path) -> None:
    def nested(depth: int) -> str:
        opener = "Route::prefix('a')->middleware('auth')->group(function () {\n"
        return "<?php\n" + opener * depth + "Route::get('/x', 'y');\n" + "});\n" * depth

    _write(tmp_path, {"routes/web.php": nested(ra.MAX_NESTING)})
    route = PhpWebAnalyzer().analyze(tmp_path).routes[0]
    assert (route.path, route.auth) == ("/" + "a/" * ra.MAX_NESTING + "x", "required")
    _write(tmp_path, {"routes/web.php": nested(ra.MAX_NESTING + 1)})
    route = PhpWebAnalyzer().analyze(tmp_path).routes[0]
    assert (route.path, route.auth) == ("/{prefix}/x", "unknown")


def test_adversarial_route_config_stays_fast(tmp_path: Path) -> None:
    yaml = "".join(f"r{i}:\n{' ' * (4 + i % 50)}path: /x{i}\n{' ' * 4}resource: ../src/\n" for i in range(5000))
    xml = "<routes>" + "<!--" * 20000 + '<route path="/x"' * 20000
    _write(tmp_path, {"config/routes.yaml": yaml, "config/routes/a.xml": xml, "src/A.php": "<?php\n"})
    start = time.perf_counter()
    PhpWebAnalyzer().analyze(tmp_path)
    assert time.perf_counter() - start < 5.0
