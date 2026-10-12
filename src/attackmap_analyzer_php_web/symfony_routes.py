"""Symfony routes from ``#[Route]`` attributes and YAML/XML route config (#3).

- ``#[Route('/x', methods: [...])]`` (or ``path: '/x'``) on an action; a
  class-level ``#[Route('/prefix')]`` is joined onto every action's path
  (and its ``methods`` merged), as Symfony's attribute loader does. A class
  route is a route of its own only when no action of the class declares one
  (an invokable controller).
- ``config/routes.yaml``, ``config/routes/*.yaml`` and ``*.xml`` (and Symfony
  2/3's ``app/config/routing*.yml``): ``path`` / ``methods`` entries are
  routes, and ``resource`` imports carry a ``prefix`` onto the routes they
  load: attribute controllers under a directory (``../src/Controller/``,
  ``routing.controllers``) or another local route file.

The YAML and XML readers are line/tag scanners, not full parsers: they read
the shapes Symfony's docs and recipes use and skip anything else (localized
path maps, ``when@dev`` blocks, bundle ``@`` resources). A prefix that can't
be read (a localized prefix map) becomes a ``{prefix}`` segment rather than a
wrong path, and access_control isn't resolved for those routes. Symfony keys
routes by name, so a later import of the same controllers or route file
replaces the earlier one: each route is emitted once, under the last prefix.
"""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass, field

from attackmap.sdk import line_of

from . import route_auth as ra

HTTP_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"})

# Route config Symfony loads on its own, in the kernel's order
# (MicroKernelTrait::configureRoutes): `config/routes/*.yaml` first, sorted,
# then `config/routes.yaml` last, so the latter's imports win a route-name
# collision. The kernel's glob is `*.{php,yaml}`: `.yml` / `.xml` files
# there are only read when something imports them. Symfony 2/3's
# `app/config/routing.*` comes from the framework config.
ROUTE_CONFIG_DIR = "config/routes"
ROUTE_CONFIG_DIR_SUFFIXES = (".yaml",)
ROUTE_CONFIG_LAST = ("config/routes.yaml",)
LEGACY_ROUTE_CONFIG_FILES = ("app/config/routing.yml", "app/config/routing.yaml", "app/config/routing.xml")
ROUTE_CONFIG_SUFFIXES = (".yaml", ".yml", ".xml")
# Imports followed this deep; files loaded and entries read at most this many.
MAX_IMPORT_DEPTH = 4
MAX_CONFIG_FILES = 64
# Distinct prefixes (different route-name prefixes) per attribute route.
MAX_PREFIXES = 8
MAX_ENTRIES = 2000
MAX_LINES = 20000

_ROUTE_ATTR = re.compile(r"\\?(?:[\w\\]+\\)?Route\s*\(")
_POSITIONAL_PATH = re.compile(r"\s*(?:'([^'\\]*)'|\"([^\"\\]*)\")")
_NAMED_PATH = re.compile(r"\bpath\s*:\s*(?:'([^'\\]*)'|\"([^\"\\]*)\")")
_NAMED_METHODS = re.compile(r"\bmethods\s*:\s*(\[[^\]]*\]|'[^']*'|\"[^\"]*\")")
_METHOD_NAME = re.compile(r"[A-Za-z]+")


@dataclass
class RouteAttr:
    path: str | None  # None: no literal path (localized map, constant, ...)
    methods: list[str]


def route_attribute(item: str) -> RouteAttr | None:
    """A ``Route(...)`` attribute (one item of a ``#[...]`` group), or None."""
    match = _ROUTE_ATTR.match(item)
    if not match:
        return None
    args = item[match.end() :]
    path = None
    positional = _POSITIONAL_PATH.match(args)
    if positional:
        path = positional.group(1) if positional.group(1) is not None else positional.group(2)
    else:
        named = _NAMED_PATH.search(args)
        if named:
            path = named.group(1) if named.group(1) is not None else named.group(2)
        elif not args.lstrip().startswith("["):
            # `#[Route(name: 'x_')]`: no path; a class prefix of ''.
            path = "" if "path" not in args else None
    methods = []
    named_methods = _NAMED_METHODS.search(args)
    if named_methods:
        methods = _methods(named_methods.group(1))
    return RouteAttr(path, methods)


def _methods(text: str) -> list[str]:
    found = [m.upper() for m in _METHOD_NAME.findall(text)]
    return list(dict.fromkeys(m for m in found if m in HTTP_METHODS))


def class_path(prefix: str, path: str) -> str:
    """Symfony's attribute loader concatenates the class and action paths."""
    return prefix + path


def import_prefix(prefix: str, path: str) -> str:
    """``RouteCollection::addPrefix``: ``'/' . trim($prefix, '/') . $path``."""
    prefix = prefix.strip().strip("/")
    if not prefix:
        return path
    return "/" + prefix + path


# ---------- route config ----------


@dataclass
class ConfigRoute:
    method: str
    path: str
    file: str
    line: int


@dataclass
class RouteConfig:
    """Routes from config files, and the import prefixes of attribute
    controllers.

    Symfony keys routes by name: an import that re-adds a route name
    replaces the earlier route. So an import of the same controllers or the
    same route file with the same effective ``name_prefix`` replaces the
    earlier one (the last in load order wins), while imports with different
    name prefixes both stay live.
    """

    # (config file, entry line, name prefix) -> routes.
    route_sets: dict[tuple[str, int, str], list[ConfigRoute]] = field(default_factory=dict)
    # target (dir ending in "/", or file) -> name prefix -> (load order, path prefix).
    imports_by_target: dict[str, dict[str, tuple[int, str]]] = field(default_factory=dict)
    _order: int = 0

    @property
    def routes(self) -> list[ConfigRoute]:
        return [route for routes in self.route_sets.values() for route in routes]

    def add_import(self, target: str, prefix: str, name_prefix: str = "") -> None:
        """Record an import. Each target keeps the MAX_PREFIXES most recent
        name prefixes (dict order is recency), so a lookup stays bounded."""
        self._order += 1
        entries = self.imports_by_target.setdefault(target, {})
        entries.pop(name_prefix, None)
        entries[name_prefix] = (self._order, prefix)
        if len(entries) > MAX_PREFIXES:
            del entries[next(iter(entries))]

    def prefixes_for(self, file: str) -> list[str]:
        """Import prefixes for attribute routes in ``file``: for each name
        prefix, the last import (in load order) covering the file. A prefix
        that couldn't be read is a ``{prefix}`` segment. Looks up the file
        and each ancestor directory, so it's O(path depth)."""
        if not self.imports_by_target:
            return [""]
        parts = file.split("/")
        candidates = ["./", file] + ["/".join(parts[:i]) + "/" for i in range(1, len(parts))]
        latest: dict[str, tuple[int, str]] = {}
        for target in candidates:
            for name_prefix, (order, prefix) in self.imports_by_target.get(target, {}).items():
                if name_prefix not in latest or order > latest[name_prefix][0]:
                    latest[name_prefix] = (order, prefix)
        if not latest:
            return [""]
        ordered = sorted(latest.values())
        # The most recent imports, oldest first.
        return list(dict.fromkeys(prefix for _, prefix in ordered))[-MAX_PREFIXES:]


@dataclass
class _Entry:
    name: str
    line: int
    values: dict[str, str]
    nested: set[str]  # keys whose value is a nested mapping/list


_FLOW_PAIR = re.compile(r"([\w.@-]+)\s*:\s*('[^']*'|\"[^\"]*\"|\[[^\]]*\]|\{|[^,{}\[\]]+)")
_FLOW_PATH = re.compile(r"\bpath\s*:\s*([^,}]+)")
_YAML_KEY = re.compile(r"([\w.@-]+|'[^']*'|\"[^\"]*\")\s*:(?:\s+(.*))?$")


def _unquote(value: str) -> str:
    value = value.strip()
    if " #" in value:
        value = value.split(" #", 1)[0].rstrip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        return value[1:-1]
    return value


def _flow_entry(entry: _Entry, text: str) -> None:
    """Top-level keys of a one-line flow mapping. A key whose value is a
    nested mapping (``prefix: {en: '', nl: /nl}``) is recorded as nested,
    and that mapping's own keys are skipped."""
    body = text[1:]
    pos = 0
    depth = 0
    parent = None
    for pair in _FLOW_PAIR.finditer(body):
        between = body[pos : pair.start()]
        depth += between.count("{") - between.count("}")
        pos = pair.end()
        name, value = pair.group(1), pair.group(2)
        if depth == 1 and parent is not None and value != "{":
            # `resource: {path: ../src/Controller/, namespace: ...}`.
            entry.values.setdefault(f"{parent}.{name}", value.strip())
            continue
        if depth > 0:
            continue
        if value == "{":
            entry.nested.add(name)
            parent = name
            depth += 1
        elif name not in entry.values and name not in entry.nested:
            entry.values[name] = value.strip()


def parse_yaml_entries(text: str) -> list[_Entry]:
    """Top-level route entries (``name:`` + indented keys) of a routes YAML.

    ``when@prod:`` blocks are read as top-level; other ``when@<env>`` blocks
    are skipped (dev/test only). A key whose value is a nested mapping is
    recorded as ``key.subkey``."""
    entries: list[_Entry] = []
    entry: _Entry | None = None
    child_indent: int | None = None
    parent_key: str | None = None
    base: int | None = 0  # indent of route names; None: set by the next line
    skipping = False
    for number, raw in enumerate(text.splitlines()[:MAX_LINES], start=1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#") or stripped == "---":
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        key = _YAML_KEY.match(stripped)
        if indent == 0:
            entry = None
            skipping = False
            base = 0
            if key and key.group(1).startswith("when@"):
                if key.group(1) == "when@prod":
                    base = None
                else:
                    skipping = True
                continue
        elif skipping:
            continue
        if base is None:
            base = indent
        if indent == base:
            entry = None
            if key and len(entries) < MAX_ENTRIES:
                entry = _Entry(_unquote(key.group(1)), number, {}, set())
                entries.append(entry)
                child_indent = None
                parent_key = None
                inline = (key.group(2) or "").strip()
                if inline.startswith("{"):
                    # `name: { path: /x, methods: [GET] }` on one line.
                    _flow_entry(entry, inline)
                    entry = None
            continue
        if entry is None or not key or indent < base:
            continue
        name = _unquote(key.group(1))
        value = key.group(2)
        if child_indent is None:
            child_indent = indent
        if indent == child_indent:
            parent_key = name
            if value is None or not value.strip() or value.strip().startswith("#"):
                entry.nested.add(name)
            else:
                entry.values[name] = value.strip()
        elif indent > child_indent and parent_key is not None and value is not None:
            entry.values[f"{parent_key}.{name}"] = value.strip()
    return entries


_XML_COMMENT_OPEN = "<!--"
_XML_TAG = re.compile(r"<(route|import)\b([^<>]{0,4000})>")
_XML_ATTR = re.compile(r"([\w:-]+)\s*=\s*(?:\"([^\"]*)\"|'([^']*)')")


def _strip_xml_comments(text: str) -> str:
    """Blank out ``<!-- ... -->`` (keeping offsets), one forward scan."""
    out = []
    pos = 0
    while True:
        start = text.find(_XML_COMMENT_OPEN, pos)
        if start < 0:
            out.append(text[pos:])
            break
        end = text.find("-->", start + 4)
        stop = len(text) if end < 0 else end + 3
        out.append(text[pos:start])
        out.append("".join(ch if ch == "\n" else " " for ch in text[start:stop]))
        pos = stop
        if end < 0:
            break
    return "".join(out)


def parse_xml_entries(text: str) -> list[_Entry]:
    text = _strip_xml_comments(text)
    entries = []
    for match in _XML_TAG.finditer(text):
        attrs = {m.group(1): m.group(2) if m.group(2) is not None else m.group(3) for m in _XML_ATTR.finditer(match.group(2))}
        if match.group(1) == "route":
            values = {k: v for k, v in attrs.items() if k in ("path", "methods", "controller")}
            nested = set() if "path" in attrs else {"path"}  # <path locale="..."> children
        else:
            values = {k: v for k, v in attrs.items() if k in ("resource", "prefix", "type", "name-prefix")}
            nested = set()
        entries.append(_Entry(attrs.get("id", ""), line_of(text, match.start()), values, nested))
        if len(entries) >= MAX_ENTRIES:
            break
    return entries


def _resolve(base_dir: str, resource: str) -> str | None:
    """A repo-relative path for ``resource`` (relative to the config file's
    directory), or None for bundle (``@``), absolute or out-of-repo paths."""
    resource = resource.strip()
    if not resource or resource.startswith(("@", "/", "%")) or "://" in resource:
        return None
    trailing = resource.endswith("/")
    target = posixpath.normpath(posixpath.join(base_dir, resource))
    if target == ".." or target.startswith("../"):
        return None
    if target == ".":
        return "./"
    return target + "/" if trailing or not posixpath.splitext(target)[1] else target


def load_route_config(read, list_dir) -> RouteConfig:
    """Read the repo's Symfony route config.

    ``read(relative) -> str | None`` reads a repo file (contained, None when
    missing); ``list_dir(relative) -> list[str]`` lists a directory's files
    (repo-relative). Kept I/O-free so it can be fuzzed directly."""
    config = RouteConfig()
    roots = sorted(f for f in list_dir(ROUTE_CONFIG_DIR) if f.endswith(ROUTE_CONFIG_DIR_SUFFIXES))
    roots += [*ROUTE_CONFIG_LAST, *LEGACY_ROUTE_CONFIG_FILES]
    parsed: dict[str, list[_Entry] | None] = {}
    loads = 0

    def entries_of(relative: str) -> list[_Entry] | None:
        if relative not in parsed:
            text = read(relative)
            if text is None:
                parsed[relative] = None
            else:
                parsed[relative] = parse_xml_entries(text) if relative.endswith(".xml") else parse_yaml_entries(text)
        return parsed[relative]

    def load(relative: str, prefix: str, name_prefix: str, depth: int) -> None:
        # Loaded again on a re-import (a later import wins), up to the cap.
        nonlocal loads
        if loads >= MAX_CONFIG_FILES or depth > MAX_IMPORT_DEPTH:
            return
        loads += 1
        entries = entries_of(relative)
        if entries is None:
            return
        base_dir = posixpath.dirname(relative)
        for entry in entries:
            values = entry.values
            if "resource" in values or "resource" in entry.nested:
                _import(entry, base_dir, prefix, name_prefix, depth)
                continue
            if "path" in entry.nested or "path" not in values:
                continue  # localized path map, or not a route
            path = _unquote(values["path"])
            if not path.startswith("/"):
                path = "/" + path
            methods = _methods(_unquote(values.get("methods", ""))) or ["ANY"]
            full = import_prefix(prefix, path)
            key = (relative, entry.line, name_prefix)
            config.route_sets.pop(key, None)
            config.route_sets[key] = [ConfigRoute(method, full, relative, entry.line) for method in methods]

    def _import(entry: _Entry, base_dir: str, prefix: str, name_prefix: str, depth: int) -> None:
        values = entry.values
        resource = values.get("resource") or values.get("resource.path")
        if resource is None:
            return
        resource = _unquote(resource)
        if resource.startswith("{"):
            # Flow mapping: `resource: { path: ../src/Controller/, namespace: App\Controller }`.
            inner = _FLOW_PATH.search(resource)
            if inner is None:
                return
            resource = _unquote(inner.group(1))
        if "prefix" in entry.nested or _unquote(values.get("prefix", "")).startswith("{"):
            # A localized prefix map (`prefix: {en: '', nl: /nl}`): the
            # real path is one of several, so mark the segment unknown.
            own = "/" + ra.DYNAMIC_SEGMENT
        else:
            own = _unquote(values.get("prefix", ""))
        combined = _join_prefix(prefix, own)
        names = name_prefix + _unquote(values.get("name_prefix", values.get("name-prefix", "")))
        kind = _unquote(values.get("type", ""))
        if resource == "routing.controllers":
            # Symfony 7.1+: every attribute-routed controller (src/).
            config.add_import("src/", combined, names)
            return
        target = _resolve(base_dir, resource)
        if target is None:
            return
        if target.endswith(ROUTE_CONFIG_SUFFIXES) and kind not in ("attribute", "annotation"):
            load(target, combined, names, depth + 1)
        elif kind in ("attribute", "annotation") or target.endswith("/") or target.endswith(".php"):
            config.add_import(target, combined, names)

    for relative in roots:
        load(relative, "", "", 0)
    return config


def _join_prefix(outer: str, inner: str) -> str:
    inner = inner.strip().strip("/")
    outer = outer.strip().rstrip("/")
    return f"{outer}/{inner}" if inner else outer
