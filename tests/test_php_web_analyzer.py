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
