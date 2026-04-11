from __future__ import annotations

import json
import re
from pathlib import Path

from .contracts import AnalyzerMetadata, AuthHint, DatabaseHint, ExternalCall, Route, ScanResult, SecretHint

HTTP_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD")

LARAVEL_ROUTE_PATTERN = re.compile(
    r"\bRoute::(get|post|put|patch|delete|options|head|any|match)\s*\(\s*['\"]([^'\"]+)['\"]",
    re.IGNORECASE,
)
SLIM_ROUTE_PATTERN = re.compile(
    r"\$\w+->(get|post|put|patch|delete|options|head|any|map)\s*\(\s*['\"]([^'\"]+)['\"]",
    re.IGNORECASE,
)
ATTRIBUTE_ROUTE_PATTERN = re.compile(
    r"#\[\s*Route\s*\(\s*['\"]([^'\"]+)['\"](?P<args>.*?)\)\s*\]",
    re.IGNORECASE | re.DOTALL,
)
ATTRIBUTE_METHOD_PATTERN = re.compile(r"['\"](GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)['\"]", re.IGNORECASE)
CONFIG_ROUTE_PATH_PATTERN = re.compile(r"['\"]path['\"]\s*=>\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)

OUTBOUND_PATTERNS = [
    re.compile(r"curl_init\s*\(\s*['\"](https?://[^'\"]+)['\"]", re.IGNORECASE),
    re.compile(r"file_get_contents\s*\(\s*['\"](https?://[^'\"]+)['\"]", re.IGNORECASE),
    re.compile(r"->request\s*\(\s*['\"](?:GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)['\"]\s*,\s*['\"](https?://[^'\"]+)['\"]", re.IGNORECASE),
    re.compile(r"->(?:get|post|put|patch|delete)\s*\(\s*['\"](https?://[^'\"]+)['\"]", re.IGNORECASE),
]

DATABASE_PATTERNS = [
    (re.compile(r"\bnew\s+PDO\s*\(", re.IGNORECASE), "sql"),
    (re.compile(r"\bmysqli_connect\s*\(", re.IGNORECASE), "mysql"),
    (re.compile(r"\bnew\s+mysqli\s*\(", re.IGNORECASE), "mysql"),
    (re.compile(r"Doctrine\\DBAL|Doctrine\\ORM|EntityManager", re.IGNORECASE), "sql"),
    (re.compile(r"\bpg_connect\s*\(", re.IGNORECASE), "postgresql"),
    (re.compile(r"\bRedis\s*::|\bnew\s+Redis\s*\(", re.IGNORECASE), "redis"),
]

AUTH_PATTERNS = [
    (re.compile(r"\bsession_start\s*\(", re.IGNORECASE), "session"),
    (re.compile(r"\$_SESSION\b", re.IGNORECASE), "session"),
    (re.compile(r"\bpassword_hash\s*\(", re.IGNORECASE), "password_hash"),
    (re.compile(r"\bpassword_verify\s*\(", re.IGNORECASE), "password_verify"),
    (re.compile(r"JWT|firebase\\jwt", re.IGNORECASE), "jwt"),
    (re.compile(r"\bmiddleware\s*\(\s*['\"]auth['\"]", re.IGNORECASE), "auth_middleware"),
    (re.compile(r"\bAuth::|\bauth\s*\(", re.IGNORECASE), "auth"),
]

SECRET_PATTERNS = [
    re.compile(r"getenv\s*\(\s*['\"]([A-Z0-9_]*(SECRET|TOKEN|KEY|PASSWORD|API|DB)[A-Z0-9_]*)['\"]", re.IGNORECASE),
    re.compile(r"\$_ENV\s*\[\s*['\"]([A-Z0-9_]*(SECRET|TOKEN|KEY|PASSWORD|API|DB)[A-Z0-9_]*)['\"]\s*\]", re.IGNORECASE),
    re.compile(r"\$_SERVER\s*\[\s*['\"]([A-Z0-9_]*(SECRET|TOKEN|KEY|PASSWORD|API|DB)[A-Z0-9_]*)['\"]\s*\]", re.IGNORECASE),
]


class PhpWebAnalyzer:
    metadata = AnalyzerMetadata(
        name="php-web",
        display_name="PHP Web Analyzer",
        version="0.1.0",
        description="Broad PHP web analyzer that emits structured security-relevant scan signals.",
        scope="Generic PHP web projects using route declarations, web controllers, and common HTTP/database/auth patterns.",
        targets=["php-web"],
        languages=["php"],
        priority=40,
        experimental=True,
        enabled_by_default=False,
    )

    @property
    def name(self) -> str:
        return self.metadata.name

    def detect(self, repo_path: str | Path) -> bool:
        root = Path(repo_path).resolve()
        if not root.exists() or not root.is_dir():
            return False

        composer_signal = (root / "composer.json").exists()
        php_files = list(root.rglob("*.php"))
        if not php_files:
            return False

        structure_signal = any((root / directory).exists() for directory in ("src", "app", "module", "public"))

        if composer_signal and structure_signal:
            return True
        if composer_signal and len(php_files) >= 2:
            return True
        return structure_signal and len(php_files) >= 3

    def analyze(self, repo_path: str | Path) -> ScanResult:
        root = Path(repo_path).resolve()
        result = ScanResult(root=str(root))

        if not root.exists() or not root.is_dir():
            return result

        composer_path = root / "composer.json"
        if composer_path.exists():
            self._extract_composer_signals(composer_path, result)

        for file_path in root.rglob("*.php"):
            if not file_path.is_file():
                continue
            if any(part in {"vendor", ".git", "node_modules"} for part in file_path.parts):
                continue

            result.files_scanned += 1
            if "php" not in result.languages:
                result.languages.append("php")

            content = self._read_text(file_path)
            if content is None:
                continue

            relative = str(file_path.relative_to(root))
            self._extract_routes(content, relative, result)
            self._extract_external_calls(content, relative, result)
            self._extract_datastores(content, relative, result)
            self._extract_auth_hints(content, relative, result)
            self._extract_secret_hints(content, relative, result)

        result.languages.sort()
        return result

    def _extract_composer_signals(self, composer_path: Path, result: ScanResult) -> None:
        try:
            data = json.loads(composer_path.read_text(encoding="utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return

        requirements = {
            **(data.get("require", {}) if isinstance(data.get("require", {}), dict) else {}),
            **(data.get("require-dev", {}) if isinstance(data.get("require-dev", {}), dict) else {}),
        }

        for package in requirements:
            lower = package.lower()
            if "doctrine" in lower:
                self._append_unique_database(result, "sql", "composer.json")
            if "guzzle" in lower or "symfony/http-client" in lower:
                self._append_unique_auth(result, "http_client", "composer.json")
            if "firebase/php-jwt" in lower:
                self._append_unique_auth(result, "jwt", "composer.json")

    def _extract_routes(self, content: str, relative: str, result: ScanResult) -> None:
        for match in LARAVEL_ROUTE_PATTERN.finditer(content):
            method, path = match.group(1).upper(), match.group(2)
            if method == "ANY" or method == "MATCH":
                method = "ANY"
            self._append_unique_route(result, path, method, relative)

        for match in SLIM_ROUTE_PATTERN.finditer(content):
            method, path = match.group(1).upper(), match.group(2)
            if method == "MAP" or method == "ANY":
                method = "ANY"
            self._append_unique_route(result, path, method, relative)

        for match in ATTRIBUTE_ROUTE_PATTERN.finditer(content):
            path = match.group(1)
            args = match.group("args")
            methods = [m.upper() for m in ATTRIBUTE_METHOD_PATTERN.findall(args)]
            if not methods:
                methods = ["ANY"]
            for method in methods:
                self._append_unique_route(result, path, method, relative)

        for match in CONFIG_ROUTE_PATH_PATTERN.finditer(content):
            self._append_unique_route(result, match.group(1), "ANY", relative)

    def _extract_external_calls(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern in OUTBOUND_PATTERNS:
            for match in pattern.finditer(content):
                self._append_unique_external(result, match.group(1), relative)

    def _extract_datastores(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern, kind in DATABASE_PATTERNS:
            if pattern.search(content):
                self._append_unique_database(result, kind, relative)

    def _extract_auth_hints(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern, hint in AUTH_PATTERNS:
            if pattern.search(content):
                self._append_unique_auth(result, hint, relative)

    def _extract_secret_hints(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern in SECRET_PATTERNS:
            for match in pattern.finditer(content):
                self._append_unique_secret(result, match.group(1), relative)

    @staticmethod
    def _read_text(path: Path) -> str | None:
        try:
            return path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            return None

    @staticmethod
    def _append_unique_route(result: ScanResult, path: str, method: str, file: str) -> None:
        key = (path, method, file)
        if any((item.path, item.method, item.file) == key for item in result.routes):
            return
        result.routes.append(Route(path=path, method=method, file=file))

    @staticmethod
    def _append_unique_external(result: ScanResult, target: str, file: str) -> None:
        key = (target, file)
        if any((item.target, item.file) == key for item in result.external_calls):
            return
        result.external_calls.append(ExternalCall(target=target, file=file))

    @staticmethod
    def _append_unique_database(result: ScanResult, kind: str, file: str) -> None:
        key = (kind, file)
        if any((item.kind, item.file) == key for item in result.databases):
            return
        result.databases.append(DatabaseHint(kind=kind, file=file))

    @staticmethod
    def _append_unique_auth(result: ScanResult, hint: str, file: str) -> None:
        key = (hint, file)
        if any((item.hint, item.file) == key for item in result.auth_hints):
            return
        result.auth_hints.append(AuthHint(hint=hint, file=file))

    @staticmethod
    def _append_unique_secret(result: ScanResult, name: str, file: str) -> None:
        key = (name, file)
        if any((item.name, item.file) == key for item in result.secret_hints):
            return
        result.secret_hints.append(SecretHint(name=name, file=file))
