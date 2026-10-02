import shutil
import sys
from pathlib import Path

import pytest

from attackmap.sdk.contracts import AnalyzerMetadata as SharedAnalyzerMetadata
from attackmap.sdk.models import ScanResult as SharedScanResult
from attackmap_analyzer_php_web.contracts import AnalyzerMetadata, ScanResult
from attackmap_analyzer_php_web import PhpWebAnalyzer

FIXTURES = Path(__file__).parent / "fixtures"


def test_contracts_use_shared_sdk_types() -> None:
    assert AnalyzerMetadata is SharedAnalyzerMetadata
    assert ScanResult is SharedScanResult


def test_metadata_contains_required_fields() -> None:
    analyzer = PhpWebAnalyzer()
    metadata = analyzer.metadata

    assert metadata.name == "php-web"
    assert metadata.display_name == "PHP Web Analyzer"
    assert metadata.version == "0.1.0"
    assert metadata.description
    assert metadata.scope
    assert metadata.targets
    assert metadata.languages == ["php"]
    assert isinstance(metadata.priority, int)
    assert metadata.experimental is True
    assert metadata.enabled_by_default is False


def test_detect_identifies_php_web_project() -> None:
    analyzer = PhpWebAnalyzer()

    assert analyzer.detect(FIXTURES / "php_web_app") is True


def test_detect_identifies_minimal_php_repository() -> None:
    analyzer = PhpWebAnalyzer()

    assert analyzer.detect(FIXTURES / "php_minimal_repo") is True


def test_detect_identifies_composer_based_php_repository() -> None:
    analyzer = PhpWebAnalyzer()

    assert analyzer.detect(FIXTURES / "php_composer_repo") is True


def test_detect_identifies_php_repository_with_common_directories() -> None:
    analyzer = PhpWebAnalyzer()

    assert analyzer.detect(FIXTURES / "php_common_dirs_repo") is True


def test_detect_identifies_php_library_repository() -> None:
    analyzer = PhpWebAnalyzer()

    assert analyzer.detect(FIXTURES / "php_non_web_lib") is True


def test_analyze_extracts_routes_and_http_calls() -> None:
    analyzer = PhpWebAnalyzer()
    result = analyzer.analyze(FIXTURES / "php_web_app")

    route_keys = {(route.path, route.method) for route in result.routes}
    outbound_targets = {call.target for call in result.external_calls}

    assert ("/health", "GET") in route_keys
    assert ("/login", "POST") in route_keys
    assert "https://api.example.com/v1/ping" in outbound_targets
    assert "https://payments.example.com/check" in outbound_targets
    assert "https://hooks.example.com/notify" in outbound_targets


def test_analyze_extracts_datastore_auth_and_secret_hints() -> None:
    analyzer = PhpWebAnalyzer()
    result = analyzer.analyze(FIXTURES / "php_web_app")

    db_hints = {hint.kind for hint in result.databases}
    auth_hints = {hint.hint for hint in result.auth_hints}
    secret_names = {hint.name for hint in result.secret_hints}

    assert "sql" in db_hints
    assert "mysql" in db_hints
    assert "session" in auth_hints
    assert "password_hash" in auth_hints
    assert "password_verify" in auth_hints
    assert "JWT_SECRET" in secret_names
    assert "API_KEY" in secret_names
    assert "ACCESS_TOKEN" in secret_names


def test_http_client_dependency_is_a_framework_hint_not_auth(tmp_path: Path) -> None:
    # Guzzle in composer.json used to be emitted as the AuthHint `http_client`
    # (AttackMap#258). It is a library capability: a FrameworkHint citing the
    # composer.json line. firebase/php-jwt stays a genuine auth signal.
    (tmp_path / "composer.json").write_text(
        '{\n  "require": {\n    "guzzlehttp/guzzle": "^7.8",\n    "firebase/php-jwt": "^6.0"\n  }\n}\n'
    )
    result = PhpWebAnalyzer().analyze(tmp_path)

    assert [h.hint for h in result.auth_hints] == ["jwt"]
    jwt = result.auth_hints[0]
    assert (jwt.file, jwt.line, jwt.evidence_text) == ("composer.json", 4, '"firebase/php-jwt": "^6.0"')
    assert [h.hint for h in result.framework_hints] == ["http_client"]
    client = result.framework_hints[0]
    assert (client.file, client.line, client.evidence_text) == ("composer.json", 3, '"guzzlehttp/guzzle": "^7.8",')


def test_auth_hints_cite_the_matching_line() -> None:
    root = FIXTURES / "php_web_app"
    result = PhpWebAnalyzer().analyze(root)
    assert result.auth_hints
    for hint in result.auth_hints:
        lines = (root / hint.file).read_text().split("\n")
        assert hint.evidence_text == lines[hint.line - 1].strip()


def test_analyze_returns_core_compatible_scan_shape() -> None:
    analyzer = PhpWebAnalyzer()
    result = analyzer.analyze(FIXTURES / "php_web_app")

    assert isinstance(result.root, str)
    assert isinstance(result.files_scanned, int)
    assert isinstance(result.languages, list)
    assert hasattr(result, "routes")
    assert hasattr(result, "external_calls")
    assert hasattr(result, "databases")
    assert hasattr(result, "auth_hints")
    assert hasattr(result, "secret_hints")


# ---------------------------------------------------------------------------
# Repo walking via attackmap.sdk.fs (AttackMap#253)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("parent", ["build/out", "build/vendor"])
def test_repo_checked_out_under_skip_dir_name_is_still_analyzed(tmp_path: Path, parent: str) -> None:
    # Skip dirs used to be matched against absolute path parts, so a repo
    # under any `vendor/` directory yielded no PHP files at all.
    repo = tmp_path / parent / "repo"
    shutil.copytree(FIXTURES / "php_web_app", repo)
    analyzer = PhpWebAnalyzer()
    assert analyzer.detect(repo) is True
    result = analyzer.analyze(repo)
    assert result.files_scanned > 0
    assert result.routes
    assert result.external_calls


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges on Windows")
def test_symlinked_source_outside_repo_is_not_analyzed(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.php").write_text("<?php\nRoute::get('/outside-secret', 'x');\n$k = getenv('OUTSIDE_SECRET_KEY');\n")
    repo = tmp_path / "repo"
    shutil.copytree(FIXTURES / "php_web_app", repo)
    (repo / "src" / "linked.php").symlink_to(outside / "secret.php")

    result = PhpWebAnalyzer().analyze(repo)
    assert "/outside-secret" not in {r.path for r in result.routes}
    assert "OUTSIDE_SECRET_KEY" not in {s.name for s in result.secret_hints}
    assert not any(r.file.endswith("linked.php") for r in result.routes)


# ---------------------------------------------------------------------------
# False positives on ordinary PHP (#2)
# ---------------------------------------------------------------------------


def test_getters_and_config_paths_are_not_routes() -> None:
    # `$request->get('id')`, `$cache->get('k')`, `$config->get('/...')`,
    # `$session->get(...)` and logging's `'path' => '/var/log/...'`.
    result = PhpWebAnalyzer().analyze(FIXTURES / "laravel_like_repo")
    keys = {(r.path, r.method) for r in result.routes}
    assert keys == {("/users/{id}", "GET"), ("/users", "POST")}


def test_db_and_api_connection_settings_are_not_secrets() -> None:
    result = PhpWebAnalyzer().analyze(FIXTURES / "laravel_like_repo")
    names = {s.name for s in result.secret_hints}
    assert "DB_HOST" not in names
    assert "API_URL" not in names
    assert {"DB_PASSWORD", "API_KEY"} <= names


def test_jwt_substring_and_auth_method_are_not_auth_hints() -> None:
    result = PhpWebAnalyzer().analyze(FIXTURES / "laravel_like_repo")
    by_file = {(h.hint, h.file) for h in result.auth_hints}
    controller = "app/Http/Controllers/UserController.php"
    assert ("jwt", controller) not in by_file
    assert ("auth", controller) not in by_file
    # `->middleware('auth:sanctum')` is a real auth middleware.
    assert ("auth_middleware", "routes/web.php") in by_file


def test_firebase_jwt_usage_is_a_jwt_hint() -> None:
    result = PhpWebAnalyzer().analyze(FIXTURES / "slim_symfony_repo")
    assert ("jwt", "src/app.php") in {(h.hint, h.file) for h in result.auth_hints}


def test_slim_symfony_and_config_routes_are_extracted() -> None:
    result = PhpWebAnalyzer().analyze(FIXTURES / "slim_symfony_repo")
    keys = {(r.path, r.method) for r in result.routes}
    assert ("/status", "GET") in keys  # $api = AppFactory::create()
    assert ("/tokens", "POST") in keys  # RouteCollectorProxy $v1 group param
    assert ("/orders/{id}", "GET") in keys  # Symfony #[Route]
    assert ("/orders/{id}", "DELETE") in keys
    assert ("/api/ping", "ANY") in keys  # 'routes' => [['path' => ...]]


def test_detect_ignores_non_php_repo_with_src_dir(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text("print('hi')\n")
    for directory in ("app", "config", "public", "module"):
        (tmp_path / directory).mkdir()
    assert PhpWebAnalyzer().detect(tmp_path) is False


def test_detect_ignores_php_only_under_vendor(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.go").write_text("package main\n")
    (tmp_path / "vendor" / "pkg").mkdir(parents=True)
    (tmp_path / "vendor" / "pkg" / "x.php").write_text("<?php\n")
    assert PhpWebAnalyzer().detect(tmp_path) is False
