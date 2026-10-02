from __future__ import annotations

import json
import re
from pathlib import Path

from attackmap.sdk import iter_repo_files, line_of, line_snippet, read_source, rel

from .contracts import (
    AnalyzerMetadata,
    AuthHint,
    DatabaseHint,
    ExternalCall,
    FrameworkHint,
    Route,
    ScanResult,
    SecretHint,
)

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

        if (root / "composer.json").exists():
            return True

        if any((root / directory).is_dir() for directory in ("src", "app", "module", "public", "config")):
            return True

        return next(iter_repo_files(root, suffixes={".php"}), None) is not None

    def analyze(self, repo_path: str | Path) -> ScanResult:
        root = Path(repo_path).resolve()
        result = ScanResult(root=str(root))

        if not root.exists() or not root.is_dir():
            return result

        self._extract_composer_signals(root, result)

        # Pruned by repo-relative dir name (vendor, node_modules, .git, ...);
        # symlinks out of the repo are not followed (AttackMap#253).
        for file_path in iter_repo_files(root, suffixes={".php"}):
            result.files_scanned += 1
            if "php" not in result.languages:
                result.languages.append("php")

            content = read_source(file_path)
            if content is None:
                continue

            relative = rel(file_path, root)
            self._extract_routes(content, relative, result)
            self._extract_external_calls(content, relative, result)
            self._extract_datastores(content, relative, result)
            self._extract_auth_hints(content, relative, result)
            self._extract_secret_hints(content, relative, result)

        result.languages.sort()
        return result

    def _extract_composer_signals(self, root: Path, result: ScanResult) -> None:
        text = read_source(root / "composer.json", root=root)
        if text is None:
            return
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return
        if not isinstance(data, dict):
            return

        requirements = {
            **(data.get("require", {}) if isinstance(data.get("require", {}), dict) else {}),
            **(data.get("require-dev", {}) if isinstance(data.get("require-dev", {}), dict) else {}),
        }

        for package in requirements:
            lower = package.lower()
            index = text.find(f'"{package}"')
            offset = index if index >= 0 else 0
            if "doctrine" in lower:
                self._append_unique_database(result, "sql", "composer.json", text, offset)
            if "guzzle" in lower or "symfony/http-client" in lower:
                # An HTTP client *library* is a framework capability, not an
                # outbound call (no target) and not an auth signal (#258).
                self._append_unique_hint(
                    result.framework_hints, FrameworkHint, "http_client", "composer.json", text, offset, 0.9
                )
            if "firebase/php-jwt" in lower:
                self._append_unique_hint(result.auth_hints, AuthHint, "jwt", "composer.json", text, offset)

    def _extract_routes(self, content: str, relative: str, result: ScanResult) -> None:
        for match in LARAVEL_ROUTE_PATTERN.finditer(content):
            method, path = match.group(1).upper(), match.group(2)
            if method == "ANY" or method == "MATCH":
                method = "ANY"
            self._append_unique_route(result, path, method, relative, line_of(content, match.start()))

        for match in SLIM_ROUTE_PATTERN.finditer(content):
            method, path = match.group(1).upper(), match.group(2)
            if method == "MAP" or method == "ANY":
                method = "ANY"
            self._append_unique_route(result, path, method, relative, line_of(content, match.start()))

        for match in ATTRIBUTE_ROUTE_PATTERN.finditer(content):
            path = match.group(1)
            args = match.group("args")
            methods = [m.upper() for m in ATTRIBUTE_METHOD_PATTERN.findall(args)]
            if not methods:
                methods = ["ANY"]
            for method in methods:
                self._append_unique_route(result, path, method, relative, line_of(content, match.start()))

        for match in CONFIG_ROUTE_PATH_PATTERN.finditer(content):
            self._append_unique_route(result, match.group(1), "ANY", relative, line_of(content, match.start()))

    def _extract_external_calls(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern in OUTBOUND_PATTERNS:
            for match in pattern.finditer(content):
                self._append_unique_external(result, match.group(1), relative, content, match.start())

    def _extract_datastores(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern, kind in DATABASE_PATTERNS:
            match = pattern.search(content)
            if match:
                self._append_unique_database(result, kind, relative, content, match.start())

    def _extract_auth_hints(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern, hint in AUTH_PATTERNS:
            match = pattern.search(content)
            if match:
                self._append_unique_hint(result.auth_hints, AuthHint, hint, relative, content, match.start())

    def _extract_secret_hints(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern in SECRET_PATTERNS:
            for match in pattern.finditer(content):
                self._append_unique_secret(result, match.group(1), relative, content, match.start())

    @staticmethod
    def _append_unique_route(result: ScanResult, path: str, method: str, file: str, line: int) -> None:
        key = (path, method, file)
        if any((item.path, item.method, item.file) == key for item in result.routes):
            return
        result.routes.append(Route(path=path, method=method, file=file, line=line))

    @staticmethod
    def _append_unique_external(result: ScanResult, target: str, file: str, content: str, offset: int) -> None:
        key = (target, file)
        if any((item.target, item.file) == key for item in result.external_calls):
            return
        line = line_of(content, offset)
        result.external_calls.append(
            ExternalCall(target=target, file=file, line=line, evidence_text=line_snippet(content, line) or target)
        )

    @staticmethod
    def _append_unique_database(result: ScanResult, kind: str, file: str, content: str, offset: int) -> None:
        key = (kind, file)
        if any((item.kind, item.file) == key for item in result.databases):
            return
        line = line_of(content, offset)
        result.databases.append(
            DatabaseHint(kind=kind, file=file, line=line, evidence_text=line_snippet(content, line) or kind)
        )

    @staticmethod
    def _append_unique_hint(
        bucket: list,
        model: type,
        hint: str,
        file: str,
        content: str,
        offset: int,
        confidence: float | None = None,
    ) -> None:
        """Append an AuthHint/FrameworkHint once per (hint, file), located at ``offset``."""
        if any((item.hint, item.file) == (hint, file) for item in bucket):
            return
        line = line_of(content, offset)
        extra = {"confidence": confidence} if confidence is not None else {}
        bucket.append(
            model(hint=hint, file=file, line=line, evidence_text=line_snippet(content, line) or hint, **extra)
        )

    @staticmethod
    def _append_unique_secret(result: ScanResult, name: str, file: str, content: str, offset: int) -> None:
        key = (name, file)
        if any((item.name, item.file) == key for item in result.secret_hints):
            return
        line = line_of(content, offset)
        result.secret_hints.append(
            SecretHint(name=name, file=file, line=line, evidence_text=line_snippet(content, line) or name)
        )
