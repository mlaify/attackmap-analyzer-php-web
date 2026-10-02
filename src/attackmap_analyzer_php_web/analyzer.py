from __future__ import annotations

import json
import re
from pathlib import Path

from attackmap.sdk import iter_repo_files, line_of, line_snippet, read_source, rel

from . import route_auth as ra
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
# Slim / FastRoute-style `$app->get('/path', ...)`. The same shape is every
# `$request->get('id')`, `$cache->get('k')` and `$config->get(...)`, so the
# path must be rooted (`/...`) and the receiver must be a router: one of
# SLIM_ROUTER_NAMES, a variable assigned from SLIM_ROUTER_ASSIGN_PATTERN, or a
# parameter typed by SLIM_ROUTER_PARAM_PATTERN (route-group closures).
SLIM_ROUTE_PATTERN = re.compile(
    r"\$(\w+)->(get|post|put|patch|delete|options|head|any|map)\s*\(\s*['\"](/[^'\"]*)['\"]",
    re.IGNORECASE,
)
SLIM_ROUTER_NAMES = frozenset({"app", "router", "route", "group", "r"})
SLIM_ROUTER_ASSIGN_PATTERN = re.compile(
    r"\$(\w+)\s*=\s*(?:AppFactory::create(?:FromContainer)?\s*\(|Bridge::create\s*\(|"
    r"new\s+\\?(?:Slim\\)?(?:App|RouteCollector)\b|new\s+\\?FastRoute\\RouteCollector\b)",
)
SLIM_ROUTER_PARAM_PATTERN = re.compile(
    r"\b(?:RouteCollectorProxy(?:Interface)?|RouteCollector|App)\s+\$(\w+)",
)
ATTRIBUTE_ROUTE_PATTERN = re.compile(
    r"#\[\s*Route\s*\(\s*['\"]([^'\"]+)['\"](?P<args>.*?)\)\s*\]",
    re.IGNORECASE | re.DOTALL,
)
ATTRIBUTE_METHOD_PATTERN = re.compile(r"['\"](GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)['\"]", re.IGNORECASE)
# Config-array routes (Mezzio-style `'routes' => [['path' => '/x', ...]]`).
# Only rooted paths in files that declare a `'routes'`/`'router'` key: every
# other `'path' =>` (Laravel `config/logging.php`, filesystem disks, cache
# dirs) is a file path, not a route.
CONFIG_ROUTE_PATH_PATTERN = re.compile(r"['\"]path['\"]\s*=>\s*['\"](/[^'\"]*)['\"]")
CONFIG_ROUTES_KEY_PATTERN = re.compile(r"['\"](?:routes|router)['\"]\s*=>")
# Symfony security config whose `access_control` rules guard attribute routes.
SECURITY_CONFIG_PATHS = (
    "config/packages/security.yaml",
    "config/packages/security.yml",
    "config/security.yaml",
    "app/config/security.yml",
)

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
    # A JWT library, not any "jwt" substring (`$jwtSecret`, comments).
    (
        re.compile(
            r"Firebase\\JWT\\JWT|\bJWT::(?:decode|encode)\b|Lcobucci\\JWT|lcobucci/jwt"
            r"|Tymon\\JWTAuth|tymon/jwt-auth|\bJWTAuth::"
        ),
        "jwt",
    ),
    (re.compile(r"\bmiddleware\s*\(\s*['\"]auth(?::[\w,-]+)?['\"]", re.IGNORECASE), "auth_middleware"),
    # Laravel's Auth facade or the `auth()` / `auth('guard')` helper chained
    # into a guard call, not any function or method named `auth(`.
    (re.compile(r"\bAuth::|(?<![\w$>:\\])auth\s*\(\s*(?:['\"][\w-]*['\"]\s*)?\)\s*->"), "auth"),
]

# Secret-shaped env var names only. `API`/`DB` on their own matched
# `DB_HOST`/`API_URL`; `DB_PASSWORD`/`API_KEY`/`API_TOKEN` still match via
# PASSWORD/KEY/TOKEN. Case-sensitive: env var names are upper-case.
_SECRET_NAME = r"([A-Z0-9_]*(?:SECRET|TOKEN|KEY|PASSWORD|PASSWD)[A-Z0-9_]*)"
SECRET_PATTERNS = [
    re.compile(r"getenv\s*\(\s*['\"]" + _SECRET_NAME + r"['\"]"),
    re.compile(r"\$_ENV\s*\[\s*['\"]" + _SECRET_NAME + r"['\"]\s*\]"),
    re.compile(r"\$_SERVER\s*\[\s*['\"]" + _SECRET_NAME + r"['\"]\s*\]"),
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

        # A `src/`/`app/`/`config/` dir alone says nothing about the language
        # (it matched Python, Go and Java repos): require a PHP source file
        # outside vendor/ (the walker prunes vendor, node_modules, ...).
        return next(iter_repo_files(root, suffixes={".php"}), None) is not None

    def analyze(self, repo_path: str | Path) -> ScanResult:
        root = Path(repo_path).resolve()
        result = ScanResult(root=str(root))

        if not root.exists() or not root.is_dir():
            return result

        self._extract_composer_signals(root, result)
        access_rules = self._load_access_control(root)
        # Laravel routes are resolved after the walk: a controller's
        # constructor middleware lives in another file (route index, scope,
        # action).
        laravel_pending: list[tuple[int, ra.LaravelScope, list[ra.LaravelGroup], tuple[str, str] | None]] = []
        controllers: dict[str, list[ra.ControllerGuard]] = {}

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
            self._extract_routes(content, relative, result, access_rules, laravel_pending)
            for cls, guards in ra.laravel_controller_guards(content).items():
                controllers.setdefault(cls, []).extend(guards)
            self._extract_external_calls(content, relative, result)
            self._extract_datastores(content, relative, result)
            self._extract_auth_hints(content, relative, result)
            self._extract_secret_hints(content, relative, result)

        for index, scope, groups, action in laravel_pending:
            self._set_route_auth(result, index, ra.resolve_laravel(scope, groups, action, controllers))

        result.languages.sort()
        return result

    @staticmethod
    def _load_access_control(root: Path) -> list[ra.AccessRule]:
        for candidate in SECURITY_CONFIG_PATHS:
            if not (root / candidate).is_file():
                continue
            text = read_source(root / candidate, root=root)
            if text is not None:
                return ra.parse_access_control(text)
        return []

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

    def _extract_routes(
        self,
        content: str,
        relative: str,
        result: ScanResult,
        access_rules: list[ra.AccessRule] | None = None,
        laravel_pending: list | None = None,
    ) -> None:
        laravel_matches = list(LARAVEL_ROUTE_PATTERN.finditer(content))
        laravel_groups = ra.laravel_groups(content) if laravel_matches else []
        laravel_enclosing = ra.enclosing(laravel_groups, [m.start() for m in laravel_matches])
        for match, enclosing in zip(laravel_matches, laravel_enclosing):
            method, path = match.group(1).upper(), match.group(2)
            if method == "ANY" or method == "MATCH":
                method = "ANY"
            index = self._append_unique_route(result, path, method, relative, line_of(content, match.start()))
            if index is None or laravel_pending is None or enclosing is None:
                continue
            open_idx = content.find("(", match.start())
            close = ra.matching_close(content, open_idx)
            if close < 0:
                continue
            scope = ra.LaravelScope()
            scope.add_links(ra.parse_chain(content, close + 1))
            laravel_pending.append((index, scope, enclosing, ra.laravel_action(content, open_idx, close)))

        routers = set(SLIM_ROUTER_NAMES)
        routers.update(SLIM_ROUTER_ASSIGN_PATTERN.findall(content))
        routers.update(SLIM_ROUTER_PARAM_PATTERN.findall(content))
        slim_matches = [m for m in SLIM_ROUTE_PATTERN.finditer(content) if m.group(1) in routers]
        slim_groups = ra.slim_groups(content, routers) if slim_matches and "->group" in content else []
        slim_enclosing = ra.enclosing(slim_groups, [m.start() for m in slim_matches])
        for match, enclosing in zip(slim_matches, slim_enclosing):
            method, path = match.group(2).upper(), match.group(3)
            if method == "MAP" or method == "ANY":
                method = "ANY"
            index = self._append_unique_route(result, path, method, relative, line_of(content, match.start()))
            if index is None or enclosing is None:
                continue
            close = ra.matching_close(content, content.find("(", match.start()))
            links = ra.parse_chain(content, close + 1) if close > 0 else []
            self._set_route_auth(result, index, ra.resolve_slim(links, enclosing))

        blocks = ra.attribute_blocks(content) if ATTRIBUTE_ROUTE_PATTERN.search(content) else []
        block_of = {offset: block for block in blocks for offset, _ in block.attributes}
        class_blocks = {block.target_offset: block for block in blocks if block.target == "class"}
        decl_ends = ra.class_decl_ends(content) if blocks else []
        for match in ATTRIBUTE_ROUTE_PATTERN.finditer(content):
            path = match.group(1)
            args = match.group("args")
            methods = [m.upper() for m in ATTRIBUTE_METHOD_PATTERN.findall(args)]
            if not methods:
                methods = ["ANY"]
            block = block_of.get(match.start())
            for method in methods:
                index = self._append_unique_route(result, path, method, relative, line_of(content, match.start()))
                if index is not None:
                    resolution = self._symfony_resolution(
                        block, decl_ends, class_blocks, path, method, access_rules or []
                    )
                    self._set_route_auth(result, index, resolution)

        if not CONFIG_ROUTES_KEY_PATTERN.search(content):
            return
        for match in CONFIG_ROUTE_PATH_PATTERN.finditer(content):
            self._append_unique_route(result, match.group(1), "ANY", relative, line_of(content, match.start()))

    @staticmethod
    def _symfony_resolution(
        block: ra.AttributeBlock | None,
        decl_ends: list[int],
        class_blocks: dict[int, ra.AttributeBlock],
        path: str,
        method: str,
        access_rules: list[ra.AccessRule],
    ) -> ra.Resolution:
        if block is None:
            return ra.Resolution()
        states = [g for _, text in block.attributes if (g := ra.symfony_guard(text))]
        prefixed = block.target == "class"
        if block.target == "function":
            owner = ra.owning_class(decl_ends, class_blocks, block.target_offset)
            if owner is not None:
                states += [g for _, text in owner.attributes if (g := ra.symfony_guard(text))]
                prefixed = any(ATTRIBUTE_ROUTE_PATTERN.match("#[" + text + "]") for _, text in owner.attributes)
        # access_control matches the full path; a class-level #[Route] prefix
        # isn't joined onto method paths here, so skip it for those routes.
        if access_rules and not prefixed:
            rule = ra.resolve_access_control(access_rules, path, method)
            if rule is not None:
                states.append(rule)
        return ra.combine(states)

    @staticmethod
    def _set_route_auth(result: ScanResult, index: int, resolution: ra.Resolution) -> None:
        """Declare a route's auth (AttackMap#256). Older cores ignore the fields."""
        if resolution.auth == ra.UNKNOWN:
            return
        route = result.routes[index]
        if getattr(route, "auth", ra.UNKNOWN) != ra.UNKNOWN:
            return  # the first registration of a duplicate route wins
        # Rebuilt rather than mutated so Route's validators (guard_evidence
        # redaction) run.
        result.routes[index] = Route(
            path=route.path,
            method=route.method,
            file=route.file,
            line=route.line,
            auth=resolution.auth,
            guards=list(resolution.guards),
            guard_evidence=resolution.evidence,
        )

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
    def _append_unique_route(
        result: ScanResult,
        path: str,
        method: str,
        file: str,
        line: int,
        *,
        auth: str = ra.UNKNOWN,
        guards: list[str] | None = None,
        guard_evidence: str | None = None,
    ) -> int | None:
        """Append a route once per (path, method, file); return its index, or
        None when it was already recorded."""
        key = (path, method, file)
        if any((item.path, item.method, item.file) == key for item in result.routes):
            return None
        result.routes.append(
            Route(
                path=path, method=method, file=file, line=line,
                auth=auth, guards=list(guards or []), guard_evidence=guard_evidence,
            )
        )
        return len(result.routes) - 1

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
