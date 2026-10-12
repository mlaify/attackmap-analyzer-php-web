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
path maps, ``when@dev`` blocks, bundle ``@`` resources), so an unread prefix
never turns into a wrong path silently: routes it may cover are marked
uncertain and access_control isn't resolved for them.
"""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass, field

from attackmap.sdk import line_of

from . import route_auth as ra

HTTP_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"})

# Route config files Symfony loads on its own.
ROUTE_CONFIG_FILES = (
    "config/routes.yaml",
    "config/routes.yml",
    "config/routes.xml",
    "app/config/routing.yml",
    "app/config/routing.yaml",
    "app/config/routing.xml",
)
ROUTE_CONFIG_DIRS = ("config/routes",)
ROUTE_CONFIG_SUFFIXES = (".yaml", ".yml", ".xml")
# Imports followed this deep; files and entries read at most this many.
MAX_IMPORT_DEPTH = 4
MAX_CONFIG_FILES = 64
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
class AttributeImport:
    target: str  # repo-relative directory (ending in "/") or file
    prefix: str | None  # None: a prefix we couldn't read


@dataclass
class RouteConfig:
    routes: list[ConfigRoute] = field(default_factory=list)
    attribute_imports: list[AttributeImport] = field(default_factory=list)

    def prefixes_for(self, file: str) -> tuple[list[str], bool]:
        """Import prefixes for attribute routes in ``file`` and whether they
        are certain. The most specific import wins (a later import of the
        same controllers overrides an earlier one by route name)."""
        matches = [imp for imp in self.attribute_imports if _covers(imp.target, file)]
        if not matches:
            return [""], True
        longest = max(len(imp.target) for imp in matches)
        best = [imp for imp in matches if len(imp.target) == longest]
        prefixes = list(dict.fromkeys(imp.prefix for imp in best if imp.prefix is not None))
        certain = all(imp.prefix is not None for imp in matches)
        return prefixes or [""], certain


def _covers(target: str, file: str) -> bool:
    if target.endswith("/"):
        return file.startswith(target) or target == "./"
    return file == target


@dataclass
class _Entry:
    name: str
    line: int
    values: dict[str, str]
    nested: set[str]  # keys whose value is a nested mapping/list


_FLOW_PATH = re.compile(r"\bpath\s*:\s*([^,}]+)")
_YAML_KEY = re.compile(r"([\w.@-]+|'[^']*'|\"[^\"]*\")\s*:(?:\s+(.*))?$")


def _unquote(value: str) -> str:
    value = value.strip()
    if " #" in value:
        value = value.split(" #", 1)[0].rstrip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        return value[1:-1]
    return value


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
            values = {k: v for k, v in attrs.items() if k in ("resource", "prefix", "type")}
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
    roots = list(ROUTE_CONFIG_FILES)
    for directory in ROUTE_CONFIG_DIRS:
        roots += sorted(f for f in list_dir(directory) if f.endswith(ROUTE_CONFIG_SUFFIXES))
    seen: set[str] = set()

    def load(relative: str, prefixes: list[str | None], depth: int) -> None:
        if len(seen) >= MAX_CONFIG_FILES or depth > MAX_IMPORT_DEPTH:
            return
        key = f"{relative}\0{prefixes}"
        if key in seen:
            return
        seen.add(key)
        text = read(relative)
        if text is None:
            return
        entries = parse_xml_entries(text) if relative.endswith(".xml") else parse_yaml_entries(text)
        base_dir = posixpath.dirname(relative)
        for entry in entries:
            values = entry.values
            if "resource" in values or "resource" in entry.nested:
                _import(entry, base_dir, prefixes, depth)
                continue
            if "path" in entry.nested or "path" not in values:
                continue  # localized path map, or not a route
            path = _unquote(values["path"])
            if not path.startswith("/"):
                path = "/" + path
            methods = _methods(_unquote(values.get("methods", ""))) or ["ANY"]
            for prefix in prefixes:
                if prefix is None:
                    continue  # an unreadable prefix: the full path is unknown
                for method in methods:
                    config.routes.append(ConfigRoute(method, _join_all(prefix, path), relative, entry.line))

    def _import(entry: _Entry, base_dir: str, prefixes: list[str | None], depth: int) -> None:
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
        if "prefix" in entry.nested:
            own: str | None = None  # localized prefix map
        else:
            own = _unquote(values.get("prefix", ""))
        combined = [None if p is None or own is None else _join_prefix(p, own) for p in prefixes]
        kind = _unquote(values.get("type", ""))
        if resource == "routing.controllers":
            # Symfony 7.1+: every attribute-routed controller (src/).
            config.attribute_imports += [AttributeImport("src/", p) for p in combined]
            return
        target = _resolve(base_dir, resource)
        if target is None:
            return
        if target.endswith(ROUTE_CONFIG_SUFFIXES) and kind not in ("attribute", "annotation"):
            load(target, combined, depth + 1)
        elif kind in ("attribute", "annotation") or target.endswith("/") or target.endswith(".php"):
            config.attribute_imports += [AttributeImport(target, p) for p in combined]

    for relative in roots:
        load(relative, [""], 0)
    return config


def _join_prefix(outer: str, inner: str) -> str:
    inner = inner.strip().strip("/")
    outer = outer.strip().rstrip("/")
    return f"{outer}/{inner}" if inner else outer


def _join_all(prefix: str, path: str) -> str:
    return import_prefix(prefix, path)
