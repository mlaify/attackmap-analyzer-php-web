"""Laravel route registrations, groups and route-file mounts (#3).

One pass per file over every ``Route::...`` statement. Each statement is a
chain of calls (``Route::prefix('admin')->middleware('auth')->group(...)``);
the links before the terminal call (a verb, ``match``, ``resource`` or
``group``) are the statement's scope, the links after it are route options.

- **Registrations**: ``Route::get|post|put|patch|delete|options|head|any``,
  array-first ``Route::match([...], ...)``, and ``Route::resource`` /
  ``apiResource`` / ``resources`` / ``apiResources`` expanded to their REST
  routes (honouring ``->only()`` / ``->except()`` / ``->shallow()`` and an
  ``['only' => ...]`` options array). A chained registration
  (``Route::middleware('auth')->get(...)``) carries the chain's scope.
- **Groups**: ``...->group(function () { ... })`` and
  ``Route::group(['prefix' => ..., 'middleware' => ...], fn)``. The group's
  argument list is its span; the registrations inside it inherit its prefix,
  middleware and controller.
- **Mounts**: a route file loaded from another file
  (``->group(base_path('routes/api.php'))``, ``require base_path(...)`` or
  ``$this->loadRoutesFrom(__DIR__.'/../routes/web.php')`` inside a group, and
  ``withRouting(api: ..., apiPrefix: ...)`` in ``bootstrap/app.php``) inherits
  the groups around the mount.

Brackets come from ``route_auth.bracket_pairs`` (one string-, comment- and
heredoc-aware pass per file), argument heads are read up to a fixed bound,
and group nesting past ``route_auth.MAX_NESTING`` is not resolved, so hostile
input stays linear.
"""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass, field

from . import route_auth as ra

# A prefix is a literal string, a `config('file.key')` reference resolved
# against the repo's config/ directory, or dynamic (anything else).
LITERAL = "lit"
CONFIG = "config"
DYNAMIC = "dyn"
Prefix = tuple[str, str]
NO_PREFIX: Prefix = (LITERAL, "")
# Shown in place of a prefix that can't be read statically.
DYNAMIC_SEGMENT = "{prefix}"

VERBS = frozenset({"get", "post", "put", "patch", "delete", "options", "head", "any"})
RESOURCE_CALLS = frozenset({"resource", "apiResource", "resources", "apiResources"})
# Calls that may precede a terminal in a `Route::` chain (RouteRegistrar).
SCOPE_CALLS = frozenset(
    {
        "prefix",
        "middleware",
        "withoutMiddleware",
        "controller",
        "name",
        "as",
        "domain",
        "namespace",
        "where",
        "whereNumber",
        "whereAlpha",
        "whereAlphaNumeric",
        "whereUuid",
        "whereUlid",
        "whereIn",
        "scopeBindings",
        "withoutScopedBindings",
        "missing",
    }
)

# Resource actions: (action, methods, member route?, suffix).
_RESOURCE_ACTIONS = (
    ("index", ("GET",), False, ""),
    ("create", ("GET",), False, "/create"),
    ("store", ("POST",), False, ""),
    ("show", ("GET",), True, ""),
    ("edit", ("GET",), True, "/edit"),
    ("update", ("PUT", "PATCH"), True, ""),
    ("destroy", ("DELETE",), True, ""),
)
_API_ACTIONS = frozenset({"index", "store", "show", "update", "destroy"})
# `Route::resources([...])` entries read per statement.
MAX_RESOURCES = 64
# Route-file mounts followed transitively this deep, and at most this many
# distinct mount chains per file.
MAX_MOUNT_DEPTH = 8
MAX_MOUNT_CHAINS = 8

_STATEMENT = re.compile(r"\bRoute::(\w+)\s*\(")
_STRING_ARG = re.compile(r"\s*(?:'([^'\\]*)'|\"([^\"\\]*)\")")
_ARRAY_ARG = re.compile(r"\s*\[")
_COMMA = re.compile(r"\s*,")
_QUOTED = re.compile(r"['\"]([^'\"]*)['\"]")
_CLASS_REF = re.compile(r"\s*\\?([\w\\]+)::class")
_CONFIG_CALL = re.compile(r"\s*config\s*\(\s*['\"]([\w-]+)\.([\w-]+)['\"]\s*(?:,[^)]*)?\)\s*$")
_GROUP_ATTR = re.compile(r"['\"](prefix|controller)['\"]\s*=>\s*")
_RESOURCES_PAIR = re.compile(r"['\"]([^'\"]+)['\"]\s*=>\s*\\?([\w\\]+)::class")
_OPTIONS_KEY = re.compile(r"['\"](only|except)['\"]\s*=>\s*(\[[^\]]*\]|['\"][^'\"]*['\"])")
_WITH_ROUTING = re.compile(r"->\s*withRouting\s*\(")
_API_PREFIX = re.compile(r"\bapiPrefix\s*:\s*['\"]([^'\"]*)['\"]")
_MOUNT_REF = re.compile(
    r"\bbase_path\s*\(\s*['\"]([^'\"]+\.php)['\"]\s*\)|\b__DIR__\s*\.\s*['\"]([^'\"]+\.php)['\"]"
)
# What precedes a mount reference: the file is loaded, not just named.
_MOUNT_LEAD = re.compile(
    r"(?:\b(?:require|include)(?:_once)?\s*\(?|\bloadRoutesFrom\s*\(|->\s*group\s*\(|\bapi\s*:\s*\[?)\s*$"
)
_API_NAMED_ARG = re.compile(r"\bapi\s*:\s*\[?\s*$")


@dataclass
class LaravelGroup:
    """A group's span (its argument list) and what it applies inside."""

    start: int
    end: int
    scope: ra.LaravelScope = field(default_factory=ra.LaravelScope)
    prefix: Prefix = NO_PREFIX
    controller: str | None = None


@dataclass
class LaravelRoute:
    methods: list[str]
    uri: str
    offset: int
    scope: ra.LaravelScope
    action: tuple[str, str] | None
    # Enclosing in-file groups, outermost first; None past MAX_NESTING.
    groups: list[LaravelGroup] | None


@dataclass
class Mount:
    """``target`` (repo-relative route file) is loaded inside ``groups``."""

    target: str
    groups: list[LaravelGroup] | None


@dataclass
class FileScan:
    routes: list[LaravelRoute] = field(default_factory=list)
    mounts: list[Mount] = field(default_factory=list)


def _string_at(content: str, pos: int, end: int) -> tuple[str | None, int]:
    """A string literal starting at ``pos`` (after whitespace), and the
    offset past it; ``(None, pos)`` when there isn't one."""
    match = _STRING_ARG.match(content, pos, end)
    if not match:
        return None, pos
    value = match.group(1) if match.group(1) is not None else match.group(2)
    return value, match.end()


def _prefix_value(content: str, start: int, end: int) -> Prefix:
    """Classify the expression ``content[start:end]`` as a prefix."""
    value, after = _string_at(content, start, end)
    if value is not None and not content[after:end].strip():
        return (LITERAL, value)
    text = content[start:end]
    config = _CONFIG_CALL.match(text)
    if config:
        return (CONFIG, f"{config.group(1)}.{config.group(2)}")
    return (DYNAMIC, "")


def _expr_end(content: str, start: int, end: int) -> int:
    """End of the expression starting at ``start``: the next top-level comma
    or ``end``. Brackets are skipped via the cached pair table."""
    pairs = ra.bracket_pairs(content)
    pos = start
    limit = min(end, start + ra._ARG_SCAN)
    while pos < limit:
        ch = content[pos]
        if ch == ",":
            return pos
        if ch in "([{":
            close = pairs.get(pos, -1)
            if close < 0:
                return end
            pos = close + 1
            continue
        if ch in "'\"":
            _, after = _string_at(content, pos, end)
            pos = after if after > pos else pos + 1
            continue
        pos += 1
    return limit


def _array_span(content: str, link: ra.Link) -> tuple[int, int] | None:
    """``(open, close)`` of an array literal that is the call's first argument."""
    match = _ARRAY_ARG.match(content, link.open + 1, link.close)
    if not match:
        return None
    close = ra.matching_close(content, match.end() - 1)
    return (match.end() - 1, close) if 0 <= close <= link.close else None


def _class_name(text: str) -> str | None:
    match = _CLASS_REF.match(text)
    if match:
        return match.group(1).rsplit("\\", 1)[-1]
    quoted = _STRING_ARG.match(text)
    if quoted:
        value = quoted.group(1) if quoted.group(1) is not None else quoted.group(2)
        return value.rsplit("\\", 1)[-1] or None
    return None


def _second_arg(content: str, link: ra.Link) -> int | None:
    """Offset where the call's second argument starts, or None."""
    first_end = _expr_end(content, link.open + 1, link.close)
    if first_end >= link.close or content[first_end] != ",":
        return None
    return first_end + 1


def _group_from(links: list[ra.Link], group: ra.Link, content: str) -> LaravelGroup:
    scope = ra.LaravelScope()
    scope.add_links([link for link in links if link is not group])
    prefix = NO_PREFIX
    prefixes: list[Prefix] = []
    controller = None
    for link in links:
        if link is group:
            break
        if link.name == "prefix":
            prefixes.append(_prefix_value(content, link.open + 1, link.close))
        elif link.name == "controller":
            controller = _class_name(content[link.open + 1 : link.close])
    span = _array_span(content, group)
    if span is not None:
        # Legacy `Route::group(['prefix' => 'x', 'middleware' => ...], fn)`.
        attrs_open, attrs_close = span
        attrs_end = min(attrs_close, attrs_open + ra._ARG_SCAN)
        ra.add_group_attr_middleware(scope, content[attrs_open + 1 : attrs_end])
        for attr in _GROUP_ATTR.finditer(content, attrs_open + 1, attrs_end):
            value_end = _expr_end(content, attr.end(), attrs_close)
            if attr.group(1) == "prefix":
                prefixes.append(_prefix_value(content, attr.end(), value_end))
            else:
                controller = _class_name(content[attr.end() : value_end]) or controller
    if prefixes:
        prefix = _join_prefixes(prefixes)
    return LaravelGroup(group.open, group.close, scope, prefix, controller)


def _join_prefixes(prefixes: list[Prefix]) -> Prefix:
    """Several prefixes on one chain collapse to one (Laravel joins them)."""
    if len(prefixes) == 1:
        return prefixes[0]
    if all(kind == LITERAL for kind, _ in prefixes):
        return (LITERAL, "/".join(p.strip("/") for _, p in prefixes if p.strip("/")))
    return (DYNAMIC, "")


def _list_values(text: str) -> set[str]:
    return {m.group(1) for m in _QUOTED.finditer(text)}


def singular(word: str) -> str:
    """Laravel's resource wildcard: the singular of the segment, ``-`` → ``_``.

    A small English heuristic; the parameter name doesn't change what the
    route exposes."""
    word = word.replace("-", "_")
    if word.endswith("ies") and len(word) > 3:
        return word[:-3] + "y"
    if word.endswith(("sses", "shes", "ches", "xes", "zes")):
        return word[:-2]
    if word.endswith("s") and not word.endswith(("ss", "us", "is")) and len(word) > 1:
        return word[:-1]
    return word


def resource_routes(
    name: str, api: bool, only: set[str] | None, except_: set[str], shallow: bool
) -> list[tuple[str, str, str]]:
    """``(method, uri, action)`` for a resource registration."""
    name = name.strip().strip("/")
    if not name:
        return []
    base_prefix = ""
    if "/" in name:
        base_prefix, name = name.rsplit("/", 1)
    segments = [s for s in name.split(".") if s]
    if not segments:
        return []
    parents = "/".join(f"{s}/{{{singular(s)}}}" for s in segments[:-1])
    last = segments[-1]
    collection = "/".join(p for p in (base_prefix, parents, last) if p)
    member_base = "/".join(p for p in (base_prefix, last) if p) if shallow else collection
    member = f"{member_base}/{{{singular(last)}}}"
    out = []
    for action, methods, is_member, suffix in _RESOURCE_ACTIONS:
        if api and action not in _API_ACTIONS:
            continue
        if only is not None and action not in only:
            continue
        if action in except_:
            continue
        uri = (member if is_member else collection) + suffix
        out.extend((method, uri, action) for method in methods)
    return out


def _resource_options(content: str, link: ra.Link, after: list[ra.Link]) -> tuple[set[str] | None, set[str], bool]:
    only: set[str] | None = None
    except_: set[str] = set()
    shallow = False
    # `Route::resource('x', C::class, ['only' => [...]])`.
    for option in _OPTIONS_KEY.finditer(link.head()):
        values = _list_values(option.group(2))
        if option.group(1) == "only":
            only = values
        else:
            except_ |= values
    for chained in after:
        if chained.name == "only":
            only = _list_values(chained.head())
        elif chained.name == "except":
            except_ |= _list_values(chained.head())
        elif chained.name == "shallow":
            shallow = True
    return only, except_, shallow


def _statement_routes(
    content: str, link: ra.Link, after: list[ra.Link], scope: ra.LaravelScope
) -> list[tuple[list[str], str, tuple[str, str] | None]]:
    """``(methods, uri, action)`` for a terminal registration call."""
    name = link.name
    end = link.close
    if name in VERBS or name == "match":
        pos = link.open + 1
        if name == "match":
            span = _array_span(content, link)
            if span is None:
                return []
            methods = [m.upper() for m in _list_values(content[span[0] + 1 : min(span[1], span[0] + 300)])]
            methods = sorted(m for m in methods if m.lower() in VERBS and m != "ANY")
            if not methods:
                return []
            comma = _COMMA.match(content, span[1] + 1, end)
            if not comma:
                return []
            pos = comma.end()
        else:
            methods = ["ANY" if name == "any" else name.upper()]
        uri, _ = _string_at(content, pos, end)
        if uri is None:
            return []
        return [(methods, uri, ra.laravel_action(content, link.open, link.close))]
    # Resources.
    api = name.startswith("api")
    only, except_, shallow = _resource_options(content, link, after)
    entries: list[tuple[str, str | None]] = []
    if name in ("resource", "apiResource"):
        resource, _ = _string_at(content, link.open + 1, end)
        if resource is None:
            return []
        second = _second_arg(content, link)
        controller = None
        if second is not None:
            controller = _class_name(content[second : _expr_end(content, second, end)])
        entries.append((resource, controller))
    else:
        span = _array_span(content, link)
        if span is None:
            return []
        body = content[span[0] + 1 : min(span[1], span[0] + 1 + ra._ARG_SCAN)]
        for pair in _RESOURCES_PAIR.finditer(body):
            entries.append((pair.group(1), pair.group(2).rsplit("\\", 1)[-1]))
            if len(entries) >= MAX_RESOURCES:
                break
    out = []
    for resource, controller in entries:
        for method, uri, action in resource_routes(resource, api, only, except_, shallow):
            out.append(([method], uri, (controller, action) if controller else None))
    return out


def scan_file(content: str, relative: str) -> FileScan:
    """Registrations and route-file mounts in one PHP file."""
    scan = FileScan()
    if "Route::" not in content:
        if "base_path" in content or "__DIR__" in content:
            # `$this->loadRoutesFrom(__DIR__.'/../routes/api.php')` outside
            # any group still claims the file (no default /api).
            scan.mounts = _mounts(content, relative, [])
        return scan
    pairs = ra.bracket_pairs(content)
    groups: list[LaravelGroup] = []
    pending: list[tuple[int, list[tuple[list[str], str, tuple[str, str] | None]], ra.LaravelScope, str | None]] = []
    for match in _STATEMENT.finditer(content):
        open_idx = match.end() - 1
        close = pairs.get(open_idx, -1)
        if close < 0:
            continue  # in a comment or string, or unbalanced
        first = ra.Link(match.group(1), content, match.start(), open_idx, close)
        links = [first, *ra.parse_chain(content, close + 1)]
        terminal = None
        for index, link in enumerate(links):
            if link.name == "group" or link.name in VERBS or link.name == "match" or link.name in RESOURCE_CALLS:
                terminal = index
                break
            if link.name not in SCOPE_CALLS:
                break
        if terminal is None:
            continue
        link = links[terminal]
        if link.name == "group":
            groups.append(_group_from(links[: terminal + 1], link, content))
            continue
        before, after = links[:terminal], links[terminal + 1 :]
        scope = ra.LaravelScope()
        scope.add_links(before + after)
        controller = None
        prefixes: list[Prefix] = []
        for chained in before:
            if chained.name == "controller":
                controller = _class_name(content[chained.open + 1 : chained.close])
            elif chained.name == "prefix":
                prefixes.append(_prefix_value(content, chained.open + 1, chained.close))
        found = _statement_routes(content, link, after, scope)
        if not found:
            continue
        if prefixes:
            # `Route::prefix('x')->get('/y')`: a one-route group.
            prefix = _join_prefixes(prefixes)
            found = [(methods, _join([prefix], uri), action) for methods, uri, action in found]
        pending.append((match.start(), found, scope, controller))

    ordered = sorted(pending, key=lambda item: item[0])
    enclosing = ra.enclosing(groups, [offset for offset, *_ in ordered])
    for (offset, found, scope, controller), outer in zip(ordered, enclosing):
        group_controller = controller
        if outer:
            for group in outer:
                group_controller = group.controller or group_controller
        for methods, uri, action in found:
            action = action or _controller_action(content, offset, group_controller)
            scan.routes.append(LaravelRoute(methods, uri, offset, scope, action, outer))

    scan.mounts = _mounts(content, relative, groups)
    return scan


_BARE_ACTION = re.compile(r"\s*\\?(?:[\w\\]+::)?\w+\s*\(\s*['\"][^'\"]*['\"]\s*,\s*['\"](\w+)['\"]")


def _controller_action(content: str, offset: int, controller: str | None) -> tuple[str, str] | None:
    """``Route::controller(C::class)->group(fn () => Route::get('/x', 'show'))``."""
    if controller is None:
        return None
    match = _BARE_ACTION.match(content, offset, offset + 500)
    return (controller, match.group(1)) if match else None


def _mounts(content: str, relative: str, groups: list[LaravelGroup]) -> list[Mount]:
    refs: list[tuple[int, str]] = []
    for match in _MOUNT_REF.finditer(content):
        lead = content[max(0, match.start() - 60) : match.start()]
        if not _MOUNT_LEAD.search(lead) and not _inside(groups, match.start()):
            continue
        if match.group(1) is not None:
            target = posixpath.normpath(match.group(1).lstrip("/"))
        else:
            target = posixpath.normpath(posixpath.join(posixpath.dirname(relative), match.group(2).lstrip("/")))
        if target.startswith("..") or target == relative:
            continue
        refs.append((match.start(), target))
    if not refs:
        return []
    routing_spans = []
    for match in _WITH_ROUTING.finditer(content):
        close = ra.matching_close(content, match.end() - 1)
        if close > 0:
            api_prefix = _API_PREFIX.search(content, match.end(), close)
            routing_spans.append((match.end(), close, api_prefix.group(1) if api_prefix else "api"))
    enclosing = ra.enclosing(groups, [offset for offset, _ in refs])
    mounts = []
    for (offset, target), outer in zip(refs, enclosing):
        outer = list(outer) if outer is not None else None
        for start, end, api_prefix in routing_spans:
            lead = content[max(start, offset - 40) : offset]
            if start <= offset <= end and _API_NAMED_ARG.search(lead) and outer is not None:
                # Laravel 11 `->withRouting(api: __DIR__.'/../routes/api.php', apiPrefix: 'api/v1')`.
                outer.append(LaravelGroup(start, end, prefix=(LITERAL, api_prefix)))
        mounts.append(Mount(target, outer))
    return mounts


def _inside(groups: list[LaravelGroup], offset: int) -> bool:
    return any(group.start < offset < group.end for group in groups)


def _join(prefixes: list[Prefix], uri: str) -> str:
    """Laravel's URI for ``uri`` under literal/dynamic ``prefixes``."""
    if all(kind == LITERAL and not value.strip("/") for kind, value in prefixes):
        return uri if uri.startswith("/") else "/" + uri
    parts = []
    for kind, value in prefixes:
        if kind == LITERAL:
            parts.append(value.strip("/"))
        else:
            parts.append(DYNAMIC_SEGMENT)
    parts.append(uri.strip("/"))
    return "/" + "/".join(part for part in parts if part)


def join_path(prefixes: list[Prefix], uri: str) -> str:
    return _join(prefixes, uri)


class MountResolver:
    """The outer group chains each route file is loaded under.

    ``sites[target]`` lists ``(source file, groups at the mount)``. A file no
    one mounts is loaded at the root, except ``routes/api.php``, which
    Laravel's default provider mounts under ``default_api`` (``/api``).
    Chains are followed MAX_MOUNT_DEPTH deep; a cycle or anything deeper is
    None (unresolved).
    """

    def __init__(self, sites: dict[str, list[tuple[str, list[LaravelGroup] | None]]], default_api: Prefix) -> None:
        self.sites = sites
        self.default_api = default_api
        self._memo: dict[str, list[list[LaravelGroup] | None]] = {}

    def chains(self, target: str) -> list[list[LaravelGroup] | None]:
        return self._chains(target, 0, frozenset())

    def _chains(self, target: str, depth: int, visiting: frozenset[str]) -> list[list[LaravelGroup] | None]:
        if target in self._memo:
            return self._memo[target]
        sites = self.sites.get(target)
        if not sites:
            if target == "routes/api.php":
                return [[LaravelGroup(-1, -1, prefix=self.default_api)]]
            return [[]]
        if depth >= MAX_MOUNT_DEPTH or target in visiting:
            return [None]
        out: list[list[LaravelGroup] | None] = []
        for source, groups in sites:
            for parent in self._chains(source, depth + 1, visiting | {target}):
                chain = None if parent is None or groups is None else parent + groups
                if not any(chain is other or chain == other for other in out):
                    out.append(chain)
                if len(out) >= MAX_MOUNT_CHAINS:
                    break
            if len(out) >= MAX_MOUNT_CHAINS:
                break
        if depth == 0:
            self._memo[target] = out
        return out
