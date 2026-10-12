from __future__ import annotations

import json
import re
from pathlib import Path

from attackmap.sdk import iter_repo_files, line_of, line_snippet, read_source, rel

from . import laravel_routes as lr
from . import route_auth as ra
from . import symfony_routes as sf
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

# Slim / FastRoute-style `$app->get('/path', ...)`. The same shape is every
# `$request->get('id')`, `$cache->get('k')` and `$config->get(...)`, so the
# path must be rooted (`/...`) and the receiver must be a router: one of
# SLIM_ROUTER_NAMES, a variable assigned from SLIM_ROUTER_ASSIGN_PATTERN, or a
# parameter typed by SLIM_ROUTER_PARAM_PATTERN (route-group closures).
SLIM_ROUTE_PATTERN = re.compile(
    r"\$(\w+)->(get|post|put|patch|delete|options|head|any|map)\s*\(\s*['\"](/[^'\"]*)['\"]",
    re.IGNORECASE,
)
# Slim `$app->map(['GET', 'POST'], '/path', ...)`: the methods come first.
SLIM_MAP_PATTERN = re.compile(
    r"\$(\w+)->map\s*\(\s*\[([^\]]{0,200})\]\s*,\s*['\"](/[^'\"]*)['\"]",
)
SLIM_MAP_METHOD_PATTERN = re.compile(r"['\"](GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)['\"]", re.IGNORECASE)
SLIM_ROUTER_NAMES = frozenset({"app", "router", "route", "group", "r"})
SLIM_ROUTER_ASSIGN_PATTERN = re.compile(
    r"\$(\w+)\s*=\s*(?:AppFactory::create(?:FromContainer)?\s*\(|Bridge::create\s*\(|"
    r"new\s+\\?(?:Slim\\)?(?:App|RouteCollector)\b|new\s+\\?FastRoute\\RouteCollector\b)",
)
SLIM_ROUTER_PARAM_PATTERN = re.compile(
    r"\b(?:RouteCollectorProxy(?:Interface)?|RouteCollector|App)\s+\$(\w+)",
)
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
# `config('file.key')` route prefixes are read from config/<file>.php:
# `'key' => 'value'` or `'key' => env('NAME', 'default')`.
CONFIG_VALUE_PATTERN = re.compile(
    r"['\"]([\w-]+)['\"]\s*=>\s*(?:env\s*\(\s*['\"][\w-]*['\"]\s*,\s*)?['\"]([^'\"]*)['\"]"
)
CONFIG_NAME_PATTERN = re.compile(r"[\w-]+")

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
        route_config = self._load_route_config(root)
        # Laravel routes are resolved after the walk: a route file's prefix
        # and middleware can come from the provider that mounts it, and a
        # controller's constructor middleware lives in another file.
        laravel_scans: dict[str, tuple[str, lr.FileScan]] = {}
        controllers: dict[str, list[ra.ControllerGuard]] = {}
        seen_routes: dict[tuple[str, str, str], int] = {}

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
            laravel = lr.scan_file(content, relative)
            if laravel.routes or laravel.mounts:
                laravel_scans[relative] = (content, laravel)
            self._extract_routes(content, relative, result, access_rules, route_config, seen_routes)
            for cls, guards in ra.laravel_controller_guards(content).items():
                controllers.setdefault(cls, []).extend(guards)
            self._extract_external_calls(content, relative, result)
            self._extract_datastores(content, relative, result)
            self._extract_auth_hints(content, relative, result)
            self._extract_secret_hints(content, relative, result)

        self._emit_symfony_config_routes(route_config, result, access_rules, seen_routes)
        self._emit_laravel_routes(root, laravel_scans, controllers, result, seen_routes)

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

    @staticmethod
    def _load_route_config(root: Path) -> sf.RouteConfig:
        def read(relative: str) -> str | None:
            path = root / relative
            return read_source(path, root=root) if path.is_file() else None

        def list_dir(relative: str) -> list[str]:
            directory = root / relative
            if not directory.is_dir() or directory.is_symlink():
                return []
            return [f"{relative}/{child.name}" for child in directory.iterdir() if child.is_file()]

        return sf.load_route_config(read, list_dir)

    def _emit_symfony_config_routes(
        self,
        config: sf.RouteConfig,
        result: ScanResult,
        access_rules: list[ra.AccessRule],
        seen: dict,
    ) -> None:
        for route in config.routes:
            index = self._append_unique_route(result, route.path, route.method, route.file, route.line, seen=seen)
            if index is not None and access_rules and ra.DYNAMIC_SEGMENT not in route.path:
                rule = ra.resolve_access_control(access_rules, route.path, route.method)
                if rule is not None:
                    self._set_route_auth(result, index, ra.combine([rule]))

    def _emit_laravel_routes(
        self,
        root: Path,
        scans: dict[str, tuple[str, lr.FileScan]],
        controllers: dict[str, list[ra.ControllerGuard]],
        result: ScanResult,
        seen: dict,
    ) -> None:
        sites: dict[str, list] = {}
        for relative, (_, scan) in scans.items():
            for mount in scan.mounts:
                sites.setdefault(mount.target, []).append((relative, mount.groups, mount.once))
        resolver = lr.MountResolver(sites, (lr.LITERAL, "api"))
        config_cache: dict[str, str | None] = {}
        for relative, (content, scan) in scans.items():
            if not scan.routes:
                continue
            chains = resolver.chains(relative)
            # The enclosing groups are fixed by the innermost one, so each
            # (mount chain, innermost group) pair is joined and merged once,
            # not once per route.
            merged: dict[tuple[int, int | None], tuple[str | None, lr.LaravelGroup] | None] = {}
            resolved: dict[tuple, ra.Resolution] = {}
            for route in scan.routes:
                line = line_of(content, route.offset)
                inner = id(route.groups[-1]) if route.groups else (None if route.groups is None else 0)
                for index_chain, chain in enumerate(chains):
                    key = (index_chain, inner)
                    if key not in merged:
                        merged[key] = self._merge_groups(root, chain, route.groups, config_cache)
                    joined = merged[key]
                    if joined is None:
                        # Nested past MAX_NESTING or mounted in a cycle: the
                        # prefix and the enclosing middleware are unknown.
                        path = lr.join_path([(lr.DYNAMIC, "")], route.uri)
                    else:
                        path = lr.join_base(joined[0], route.uri)
                    for method in route.methods:
                        index = self._append_unique_route(result, path, method, relative, line, seen=seen)
                        if index is None or joined is None:
                            continue
                        # Same groups, route-level middleware and controller
                        # guard -> same resolution.
                        guarded = route.action if route.action and route.action[0] in controllers else None
                        rkey = (key, tuple(route.scope.applied), tuple(route.scope.excluded), guarded)
                        if rkey not in resolved:
                            resolved[rkey] = ra.resolve_laravel(route.scope, [joined[1]], guarded, controllers)
                        self._set_route_auth(result, index, resolved[rkey])

    def _merge_groups(
        self,
        root: Path,
        chain: list | None,
        groups: list | None,
        config_cache: dict[str, str | None],
    ) -> tuple[str | None, lr.LaravelGroup] | None:
        """The joined prefix and the merged middleware of ``chain + groups``."""
        if chain is None or groups is None:
            return None
        outer = chain + groups
        prefixes = [self._resolve_prefix(root, group.prefix, config_cache) for group in outer]
        # One entry per middleware name (the outermost evidence), so the
        # merged scope is as long as the distinct names, not the groups.
        applied: dict[str, tuple[str, str]] = {}
        excluded: dict[str, tuple[str, str]] = {}
        for group in outer:
            for name, evidence in group.scope.applied:
                applied.setdefault(name, (name, evidence))
            for name, evidence in group.scope.excluded:
                excluded.setdefault(name, (name, evidence))
        scope = ra.LaravelScope(list(applied.values()), list(excluded.values()))
        return lr.prefix_base(prefixes), lr.LaravelGroup(-1, -1, scope)

    @staticmethod
    def _resolve_prefix(root: Path, prefix: lr.Prefix, cache: dict[str, str | None]) -> lr.Prefix:
        """A literal for ``config('file.key')`` when config/<file>.php sets
        the key to a literal (or an ``env()`` default); else dynamic."""
        kind, value = prefix
        if kind != lr.CONFIG:
            return prefix
        if value not in cache:
            cache[value] = None
            name, key = value.split(".", 1)
            if CONFIG_NAME_PATTERN.fullmatch(name) and CONFIG_NAME_PATTERN.fullmatch(key):
                text = read_source(root / "config" / f"{name}.php", root=root)
                if text is not None:
                    found = (m.group(2) for m in CONFIG_VALUE_PATTERN.finditer(text) if m.group(1) == key)
                    cache[value] = next(found, None)
        literal = cache[value]
        return (lr.LITERAL, literal) if literal is not None else (lr.DYNAMIC, "")

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
        route_config: sf.RouteConfig | None = None,
        seen: dict | None = None,
    ) -> None:
        """Slim, Symfony-attribute and config-array routes (Laravel routes
        are emitted after the walk, see ``_emit_laravel_routes``)."""
        self._extract_slim_routes(content, relative, result, seen)
        if "#[" in content:
            self._extract_attribute_routes(content, relative, result, access_rules or [], route_config, seen)

        if not CONFIG_ROUTES_KEY_PATTERN.search(content):
            return
        for match in CONFIG_ROUTE_PATH_PATTERN.finditer(content):
            self._append_unique_route(
                result, match.group(1), "ANY", relative, line_of(content, match.start()), seen=seen
            )

    def _extract_slim_routes(self, content: str, relative: str, result: ScanResult, seen: dict | None) -> None:
        routers = set(SLIM_ROUTER_NAMES)
        routers.update(SLIM_ROUTER_ASSIGN_PATTERN.findall(content))
        routers.update(SLIM_ROUTER_PARAM_PATTERN.findall(content))
        found: list[tuple[int, list[str], str]] = []
        for match in SLIM_ROUTE_PATTERN.finditer(content):
            if match.group(1) in routers:
                method = match.group(2).upper()
                found.append((match.start(), ["ANY" if method in ("MAP", "ANY") else method], match.group(3)))
        for match in SLIM_MAP_PATTERN.finditer(content):
            if match.group(1) in routers:
                methods = list(dict.fromkeys(m.upper() for m in SLIM_MAP_METHOD_PATTERN.findall(match.group(2))))
                if methods:
                    found.append((match.start(), methods, match.group(3)))
        if not found:
            return
        found.sort(key=lambda item: item[0])
        groups = ra.slim_groups(content, routers) if "->group" in content else []
        enclosing = ra.enclosing(groups, [offset for offset, _, _ in found])
        for (offset, methods, path), outer in zip(found, enclosing):
            if outer is None or any(group.prefix is None for group in outer):
                full = "/" + lr.DYNAMIC_SEGMENT + path
            else:
                full = "".join(group.prefix for group in outer) + path
            for method in methods:
                index = self._append_unique_route(result, full, method, relative, line_of(content, offset), seen=seen)
                if index is None or outer is None:
                    continue
                close = ra.matching_close(content, content.find("(", offset))
                links = ra.parse_chain(content, close + 1) if close > 0 else []
                self._set_route_auth(result, index, ra.resolve_slim(links, outer))

    def _extract_attribute_routes(
        self,
        content: str,
        relative: str,
        result: ScanResult,
        access_rules: list[ra.AccessRule],
        route_config: sf.RouteConfig | None,
        seen: dict | None,
    ) -> None:
        """Symfony ``#[Route]`` actions, joined onto their class's
        ``#[Route]`` prefix and any route-config import prefix."""
        blocks = ra.attribute_blocks(content)
        routed = [(block, attrs) for block in blocks if (attrs := self._route_attrs(block))]
        if not routed:
            return
        decl_ends = ra.class_decl_ends(content)
        class_blocks = {block.target_offset: block for block in blocks if block.target == "class"}
        import_prefixes = route_config.prefixes_for(relative) if route_config else [""]
        # (offset, path, methods, block, owner class block)
        found: list[tuple[int, str, list[str], ra.AttributeBlock, ra.AttributeBlock | None]] = []
        prefixed_classes: set[int] = set()
        for block, attrs in routed:
            if block.target == "class":
                continue
            owner = None
            class_attr = None
            if block.target == "function":
                owner = ra.owning_class(decl_ends, class_blocks, block.target_offset)
                owner_attrs = self._route_attrs(owner) if owner is not None else []
                if owner_attrs:
                    prefixed_classes.add(owner.target_offset)
                    class_attr = owner_attrs[0][1]
            for offset, attr in attrs:
                if attr.path is None:
                    continue
                if class_attr is None:
                    path, methods = attr.path, attr.methods
                else:
                    prefix = class_attr.path if class_attr.path is not None else "/" + lr.DYNAMIC_SEGMENT
                    path = sf.class_path(prefix, attr.path)
                    methods = list(dict.fromkeys(class_attr.methods + attr.methods))
                found.append((offset, path, methods, block, owner))
        for block, attrs in routed:
            # A class-level route is a route itself only for an invokable
            # controller (no routed actions); otherwise it's the prefix.
            if block.target == "class" and block.target_offset not in prefixed_classes:
                found += [(offset, attr.path, attr.methods, block, None) for offset, attr in attrs if attr.path is not None]
        found.sort(key=lambda item: item[0])
        for offset, path, methods, block, owner in found:
            line = line_of(content, offset)
            # One route per live import (imports with different name
            # prefixes all register it).
            for import_prefix in import_prefixes:
                full = sf.import_prefix(import_prefix, path)
                # access_control is only matched against a fully known path.
                rules = access_rules if lr.DYNAMIC_SEGMENT not in full else []
                for method in methods or ["ANY"]:
                    index = self._append_unique_route(result, full, method, relative, line, seen=seen)
                    if index is not None:
                        resolution = self._symfony_resolution(block, owner, full, method, rules)
                        self._set_route_auth(result, index, resolution)

    @staticmethod
    def _route_attrs(block: ra.AttributeBlock) -> list[tuple[int, sf.RouteAttr]]:
        return [(offset, attr) for offset, item in block.attributes if (attr := sf.route_attribute(item))]

    @staticmethod
    def _symfony_resolution(
        block: ra.AttributeBlock,
        owner: ra.AttributeBlock | None,
        path: str,
        method: str,
        access_rules: list[ra.AccessRule],
    ) -> ra.Resolution:
        states = [g for _, text in block.attributes if (g := ra.symfony_guard(text))]
        if owner is not None:
            states += [g for _, text in owner.attributes if (g := ra.symfony_guard(text))]
        # access_control matches the full path (class and import prefixes
        # joined); callers pass no rules when that path isn't certain.
        if access_rules:
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
        seen: dict | None = None,
    ) -> int | None:
        """Append a route once per (path, method, file); return its index, or
        None when it was already recorded. ``seen`` indexes the keys already
        in ``result.routes`` so a large repo isn't quadratic."""
        key = (path, method, file)
        if seen is not None:
            if key in seen:
                return None
            seen[key] = len(result.routes)
        elif any((item.path, item.method, item.file) == key for item in result.routes):
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
