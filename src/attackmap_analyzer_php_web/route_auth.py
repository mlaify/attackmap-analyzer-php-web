"""Route-level auth resolution for the AttackMap#256 contract.

Each emitted ``Route`` carries ``auth`` (``required`` / ``anonymous`` /
``unknown``), the ``guards`` that apply and the ``guard_evidence`` source text
that established the state. Core trusts a declared state over its own regex
resolution, so this module only declares what the source verifiably says:

- **Laravel** — ``->middleware('auth')`` on the route,
  ``Route::middleware([...])->group(...)`` / ``Route::group(['middleware' =>
  ...], ...)`` around it, and a controller constructor's
  ``$this->middleware('auth')`` (honouring ``->only()`` / ``->except()``).
  ``->withoutMiddleware('auth')`` on the route or a group, and a controller
  ``->except([...])`` naming the action, are explicit opt-outs (anonymous).
- **Slim** — ``->add($authMiddleware)`` on the route or an enclosing
  ``->group(...)``.
- **Symfony** — ``#[IsGranted]`` / ``#[Security]`` on the action or its class,
  and ``access_control`` rules in ``security.yaml`` with literal path prefixes.
  ``PUBLIC_ACCESS`` / ``IS_AUTHENTICATED_ANONYMOUSLY`` are explicitly public.

Anything else stays ``unknown``. Every pattern here is linear: brackets are
matched by a single forward scan and no regex nests quantifiers over
overlapping classes.
"""

from __future__ import annotations

import bisect
import functools
import re
from dataclasses import dataclass, field

REQUIRED = "required"
ANONYMOUS = "anonymous"
UNKNOWN = "unknown"

# Stands in for a path prefix that can't be read statically.
DYNAMIC_SEGMENT = "{prefix}"

_OPEN = "([{"
_CLOSE = ")]}"
_EVIDENCE_MAX = 200


@dataclass
class Resolution:
    auth: str = UNKNOWN
    guards: list[str] = field(default_factory=list)
    evidence: str | None = None


def clip(text: str) -> str:
    text = " ".join(text.split())
    return text if len(text) <= _EVIDENCE_MAX else text[: _EVIDENCE_MAX - 1] + "…"


# One token per step: a string opener, a heredoc/nowdoc opener, a comment
# opener or a bracket.
_SCAN_TOKEN = re.compile(r"['\"]|<<<|//|/\*|#(?!\[)|[()\[\]{}]")
_HEREDOC_OPEN = re.compile(r"[ \t]*(['\"]?)([A-Za-z_]\w*)\1\r?\n")
_STRING_BODY = {
    "'": re.compile(r"[^'\\]*(?:\\.[^'\\]*)*'", re.DOTALL),
    '"': re.compile(r'[^"\\]*(?:\\.[^"\\]*)*"', re.DOTALL),
}


@functools.lru_cache(maxsize=4)
def bracket_pairs(content: str) -> dict[int, int]:
    """Map each opening bracket's offset to its closing bracket's offset.

    One forward pass over the file (strings, heredocs/nowdocs and ``//`` /
    ``#`` / ``/* */`` comments skipped; ``#[`` is an attribute), so every
    later lookup is O(1)
    and a file full of unclosed brackets stays linear.
    """
    pairs: dict[int, int] = {}
    stack: list[int] = []
    pos = 0
    n = len(content)
    while pos < n:
        match = _SCAN_TOKEN.search(content, pos)
        if not match:
            break
        token = match.group()
        pos = match.end()
        if token in _STRING_BODY:
            body = _STRING_BODY[token].match(content, pos)
            pos = body.end() if body else n
        elif token == "<<<":
            # Heredoc / nowdoc: skip to the closing identifier, which starts
            # its own line (PHP 7.3+ allows indenting it).
            opener = _HEREDOC_OPEN.match(content, pos)
            if opener:
                pos = _heredoc_end(content, opener.end(), opener.group(2))
        elif token == "//" or token == "#":
            nl = content.find("\n", pos)
            pos = n if nl < 0 else nl
        elif token == "/*":
            end = content.find("*/", pos)
            pos = n if end < 0 else end + 2
        elif token in _OPEN:
            stack.append(match.start())
        elif stack:
            pairs[stack.pop()] = match.start()
    return pairs


def _heredoc_end(content: str, pos: int, label: str) -> int:
    """Offset just past the line-leading ``label`` that closes a heredoc
    opened before ``pos``, or the end of the file. One forward scan."""
    n = len(content)
    while pos < n:
        nl = content.find("\n", pos)
        line_end = n if nl < 0 else nl
        stripped = content[pos:line_end].lstrip(" \t")
        after = stripped[len(label) : len(label) + 1]
        if stripped.startswith(label) and not (after.isalnum() or after == "_"):
            return line_end - len(stripped) + len(label)
        pos = line_end + 1
    return n


def matching_close(content: str, open_idx: int) -> int:
    """Index of the bracket closing ``content[open_idx]``, or -1."""
    if open_idx < 0:
        return -1
    return bracket_pairs(content).get(open_idx, -1)


_CHAIN_LINK = re.compile(r"\s*->\s*(\w+)\s*\(")


# Argument lists are only read this far. Middleware lists are short; a
# bound keeps nested registrations (a group's closure holding thousands of
# routes) from being rescanned once per enclosing call.
_ARG_SCAN = 2000
# Deeper group nesting than this is not resolved (the route stays unknown).
MAX_NESTING = 32


@dataclass
class Link:
    """One ``name(args)`` call; offsets into ``content``, sliced on demand."""

    name: str
    content: str = field(repr=False)
    start: int
    open: int  # offset of the `(`
    close: int  # offset of the matching `)`

    def head(self, limit: int = _ARG_SCAN) -> str:
        return self.content[self.open + 1 : min(self.close, self.open + 1 + limit)]

    @property
    def text(self) -> str:
        return clip(self.content[self.start : min(self.close + 1, self.start + 2 * _EVIDENCE_MAX)])


_TRIVIA = re.compile(r"\s+|//[^\n]*|#(?!\[)[^\n]*|/\*")


def skip_trivia(content: str, idx: int) -> int:
    """Offset of the first character at or after ``idx`` that isn't
    whitespace or a comment."""
    while True:
        match = _TRIVIA.match(content, idx)
        if not match:
            return idx
        if match.group() == "/*":
            end = content.find("*/", match.end())
            if end < 0:
                return len(content)
            idx = end + 2
        else:
            idx = match.end()


def parse_chain(content: str, idx: int) -> list[Link]:
    """Method calls chained after ``idx`` (``->name(args)->name(args)...``),
    with comments allowed between the links."""
    links: list[Link] = []
    while True:
        idx = skip_trivia(content, idx)
        match = _CHAIN_LINK.match(content, idx)
        if not match:
            return links
        open_idx = match.end() - 1
        close = matching_close(content, open_idx)
        if close < 0:
            return links
        links.append(Link(match.group(1), content, match.start(), open_idx, close))
        idx = close + 1


def enclosing(spans: list, offsets: list[int]) -> list[list | None]:
    """For each offset (ascending), the spans (``.start``/``.end``, properly
    nested as bracket pairs are) that contain it, outermost first. None when
    nesting exceeds MAX_NESTING. Each span is pushed and popped once."""
    ordered = sorted(spans, key=lambda span: span.start)
    out: list[list | None] = []
    stack: list = []
    i = 0
    for offset in offsets:
        while i < len(ordered) and ordered[i].start < offset:
            span = ordered[i]
            i += 1
            while stack and stack[-1].end < span.start:
                stack.pop()
            stack.append(span)
        while stack and stack[-1].end < offset:
            stack.pop()
        out.append(None if len(stack) > MAX_NESTING else list(stack))
    return out


# ---------- Laravel ----------

_STRING_OR_CLASS = re.compile(r"['\"]([^'\"]*)['\"]|\\?([\w\\]+)::class")
# Middleware aliases / classes that authenticate the caller. Authorization-only
# middleware (`can:`) is left out: a policy can admit guests.
_LARAVEL_AUTH_ALIASES = frozenset({"auth", "auth.basic", "auth.basic.once"})
_LARAVEL_AUTH_CLASSES = frozenset({"Authenticate", "AuthenticateWithBasicAuth"})
_LARAVEL_GROUP_ATTR_MIDDLEWARE = re.compile(
    r"['\"](excluded_middleware|middleware)['\"]\s*=>\s*(\[[^\]]*\]|['\"][^'\"]*['\"])"
)
_CONTROLLER_MIDDLEWARE = re.compile(r"\$this\s*->\s*middleware\s*\(")
_CLASS_DECL = re.compile(r"\bclass\s+(\w+)")
_ACTION_ARRAY = re.compile(r"\[\s*\\?([\w\\]+)::class\s*,\s*['\"](\w+)['\"]\s*\]")
_ACTION_STRING = re.compile(r"['\"]\\?([\w\\]+)@(\w+)['\"]")
_ACTION_INVOKABLE = re.compile(r",\s*\\?([\w\\]+)::class\s*$")


def laravel_auth_names(args: str) -> list[str]:
    """Auth middleware named in a ``middleware(...)`` argument list."""
    names = []
    for match in _STRING_OR_CLASS.finditer(args):
        if match.group(1) is not None:
            value = match.group(1).strip()
            if value.split(":", 1)[0] in _LARAVEL_AUTH_ALIASES:
                names.append(value)
        elif match.group(2).rsplit("\\", 1)[-1] in _LARAVEL_AUTH_CLASSES:
            names.append(match.group(2).rsplit("\\", 1)[-1] + "::class")
    return names


def _base(name: str) -> str:
    return name.split(":", 1)[0]


@dataclass
class LaravelScope:
    """Middleware a route registration (or an enclosing group) applies/excludes."""

    applied: list[tuple[str, str]] = field(default_factory=list)  # (name, evidence)
    excluded: list[tuple[str, str]] = field(default_factory=list)

    def add_links(self, links: list[Link]) -> None:
        for link in links:
            if link.name == "middleware":
                self.applied += [(name, link.text) for name in laravel_auth_names(link.head())]
            elif link.name == "withoutMiddleware":
                self.excluded += [(name, link.text) for name in laravel_auth_names(link.head())]


def add_group_attr_middleware(scope: LaravelScope, attrs: str) -> None:
    """``'middleware' => ...`` / ``'excluded_middleware' => ...`` in a legacy
    ``Route::group([...], fn)`` attribute array."""
    for attr in _LARAVEL_GROUP_ATTR_MIDDLEWARE.finditer(attrs):
        names = laravel_auth_names(attr.group(2))
        evidence = clip(attr.group(0))
        target = scope.excluded if attr.group(1) == "excluded_middleware" else scope.applied
        target += [(name, evidence) for name in names]


@dataclass
class ControllerGuard:
    names: list[str]
    evidence: str
    only: set[str] | None
    except_: set[str]


def laravel_controller_guards(content: str) -> dict[str, list[ControllerGuard]]:
    """``class X { __construct() { $this->middleware('auth')->except([...]); } }``."""
    found: dict[str, list[ControllerGuard]] = {}
    class_decls: list[tuple[int, str]] | None = None
    for match in _CONTROLLER_MIDDLEWARE.finditer(content):
        open_idx = match.end() - 1
        close = matching_close(content, open_idx)
        if close < 0:
            continue
        names = laravel_auth_names(content[open_idx + 1 : min(close, open_idx + 1 + _ARG_SCAN)])
        if not names:
            continue
        if class_decls is None:
            class_decls = [(m.start(), m.group(1)) for m in _CLASS_DECL.finditer(content)]
        owner = bisect.bisect_left(class_decls, (match.start(),)) - 1
        if owner < 0:
            continue
        only: set[str] | None = None
        except_: set[str] = set()
        links = parse_chain(content, close + 1)
        for link in links:
            methods = {m.group(1) for m in _STRING_OR_CLASS.finditer(link.head()) if m.group(1)}
            if link.name == "only":
                only = methods
            elif link.name == "except":
                except_ |= methods
        head = content[match.start() : min(close + 1, match.start() + _EVIDENCE_MAX)]
        evidence = clip(head + "".join(link.text for link in links[:3]))
        found.setdefault(class_decls[owner][1], []).append(ControllerGuard(names, evidence, only, except_))
    return found


def laravel_action(content: str, open_idx: int, close: int) -> tuple[str, str] | None:
    """``(ControllerShortName, method)`` a Laravel route call dispatches to.

    The action is the second argument (array / ``'C@m'``), or a trailing
    ``C::class`` for an invokable controller; only the ends are read.
    """
    head = content[open_idx + 1 : min(close, open_idx + 1 + 500)]
    match = _ACTION_ARRAY.search(head) or _ACTION_STRING.search(head)
    if match:
        return match.group(1).rsplit("\\", 1)[-1], match.group(2)
    match = _ACTION_INVOKABLE.search(content[max(open_idx + 1, close - 200) : close])
    if match:
        return match.group(1).rsplit("\\", 1)[-1], "__invoke"
    return None


def resolve_laravel(
    route_scope: LaravelScope,
    groups: list,
    action: tuple[str, str] | None,
    controllers: dict[str, list[ControllerGuard]],
) -> Resolution:
    applied = list(route_scope.applied)
    excluded = list(route_scope.excluded)
    for group in groups:
        applied += group.scope.applied
        excluded += group.scope.excluded
    controller_excepted: list[str] = []
    if action is not None:
        cls, method = action
        for guard in controllers.get(cls, []):
            if method in guard.except_:
                controller_excepted.append(guard.evidence)
            elif guard.only is None or method in guard.only:
                applied += [(name, guard.evidence) for name in guard.names]
    # Laravel removes excluded middleware wherever it was added (route, group
    # or controller), matched by alias.
    excluded_bases = {_base(name) for name, _ in excluded}
    remaining = [(name, ev) for name, ev in applied if _base(name) not in excluded_bases]
    if remaining:
        guards = list(dict.fromkeys(name for name, _ in remaining))
        return Resolution(REQUIRED, guards, clip("; ".join(dict.fromkeys(ev for _, ev in remaining))))
    if excluded or controller_excepted:
        evidence = [ev for _, ev in excluded] + controller_excepted
        return Resolution(ANONYMOUS, [], clip("; ".join(dict.fromkeys(evidence))))
    return Resolution()


# ---------- Slim ----------

# A middleware whose name says it authenticates: `$authMiddleware`,
# `new JwtAuthentication(...)`, `HttpBasicAuthentication`. Not "author".
_SLIM_AUTH_MIDDLEWARE = re.compile(r"auth(?!or)|jwt|bearer", re.IGNORECASE)


_SLIM_NEW = re.compile(r"\s*new\s+\\?(?:[\w\\]+\\)?(\w+)")


def slim_auth_adds(links: list[Link]) -> list[tuple[str, str]]:
    """``(guard name, evidence)`` for each auth ``->add(...)`` in a chain."""
    found = []
    for link in links:
        if link.name != "add" or not _SLIM_AUTH_MIDDLEWARE.search(link.head()):
            continue
        new = _SLIM_NEW.match(link.head())
        found.append((new.group(1) if new else clip(link.head(_EVIDENCE_MAX)), link.text))
    return found


@dataclass
class SlimGroup:
    start: int
    end: int
    guards: list[tuple[str, str]]
    # Joined onto the routes inside: Slim's `$app->group('/v1', ...)`
    # pattern, or Lumen's `$router->group(['prefix' => 'api'], ...)` as
    # `/api`. None when it isn't a literal.
    prefix: str | None = ""


_SLIM_GROUP = re.compile(r"\$(\w+)\s*->\s*group\s*\(")
_SLIM_GROUP_PATTERN = re.compile(r"\s*(?:'([^'\\]*)'|\"([^\"\\]*)\")\s*,")
_SLIM_GROUP_CLOSURE = re.compile(r"\s*(?:static\s+)?(?:function|fn)\b")
_LUMEN_GROUP_ATTRS = re.compile(r"\s*\[")
_LUMEN_PREFIX = re.compile(r"['\"]prefix['\"]\s*=>\s*(?:'([^'\\]*)'|\"([^\"\\]*)\")?")


def _slim_group_prefix(content: str, open_idx: int, close: int) -> str | None:
    pattern = _SLIM_GROUP_PATTERN.match(content, open_idx + 1, close)
    if pattern:
        return pattern.group(1) if pattern.group(1) is not None else pattern.group(2)
    attrs = _LUMEN_GROUP_ATTRS.match(content, open_idx + 1, close)
    if attrs:
        attrs_close = matching_close(content, attrs.end() - 1)
        if attrs_close < 0:
            return None
        prefix = _LUMEN_PREFIX.search(content, attrs.end(), min(attrs_close, attrs.end() + _ARG_SCAN))
        if prefix is None:
            return ""
        value = prefix.group(1) if prefix.group(1) is not None else prefix.group(2)
        if value is None:
            return None
        return "/" + value.strip("/") if value.strip("/") else ""
    if _SLIM_GROUP_CLOSURE.match(content, open_idx + 1, close):
        return ""
    return None


def slim_groups(content: str, routers: set[str]) -> list[SlimGroup]:
    groups = []
    for match in _SLIM_GROUP.finditer(content):
        if match.group(1) not in routers:
            continue
        open_idx = match.end() - 1
        close = matching_close(content, open_idx)
        if close < 0:
            continue
        guards = slim_auth_adds(parse_chain(content, close + 1))
        prefix = _slim_group_prefix(content, open_idx, close)
        if guards or prefix != "":
            groups.append(SlimGroup(open_idx, close, guards, prefix))
    return groups


def resolve_slim(route_links: list[Link], groups: list[SlimGroup]) -> Resolution:
    guards = slim_auth_adds(route_links)
    for group in groups:
        guards += group.guards
    if guards:
        names = list(dict.fromkeys(name for name, _ in guards))
        return Resolution(REQUIRED, names, clip("; ".join(dict.fromkeys(ev for _, ev in guards))))
    return Resolution()


# ---------- Symfony ----------

_ATTR_START = re.compile(r"#\[")
_WS = re.compile(r"\s*")
_ATTR_TARGET = re.compile(
    r"\s*(?:(?:public|protected|private|static|final|abstract|readonly)\s+)*(function|class|enum|interface|trait)\b"
)
_PUBLIC_ROLES = frozenset({"PUBLIC_ACCESS", "IS_AUTHENTICATED_ANONYMOUSLY"})
_GUARD_ATTR = re.compile(r"\s*\\?(?:[\w\\]+\\)?(IsGranted|Security)\s*\(")
_FIRST_STRING = re.compile(r"['\"]([^'\"]*)['\"]")


# Attribute groups longer than this are read only this far.
_ATTR_GROUP_SCAN = 8000


def split_attribute_group(content: str, start: int, end: int) -> list[str]:
    """The comma-separated attributes in ``content[start:end]`` (the inside
    of one ``#[...]``), split at top-level commas via the bracket table."""
    pairs = bracket_pairs(content)
    items: list[str] = []
    end = min(end, start + _ATTR_GROUP_SCAN)
    item_start = pos = start
    while pos < end:
        ch = content[pos]
        if ch in _OPEN:
            close = pairs.get(pos, -1)
            pos = close + 1 if close > pos else pos + 1
            continue
        if ch in _STRING_BODY:
            body = _STRING_BODY[ch].match(content, pos + 1, end)
            pos = body.end() if body else end
            continue
        if ch == ",":
            items.append(content[item_start:pos].strip())
            item_start = pos + 1
        pos += 1
    items.append(content[item_start:end].strip())
    return [item for item in items if item]


@dataclass
class AttributeBlock:
    attributes: list[tuple[int, str]]  # (offset of `#[`, text inside the brackets)
    target: str | None  # function / class / ...
    target_offset: int


def attribute_blocks(content: str) -> list[AttributeBlock]:
    """Consecutive ``#[...]`` attributes and the declaration they decorate."""
    blocks: list[AttributeBlock] = []
    pos = 0
    current: list[tuple[int, str]] = []
    while True:
        match = _ATTR_START.search(content, pos)
        if not match:
            break
        close = matching_close(content, match.start() + 1)
        if close < 0:
            # A `#[` in a comment or string (the bracket scan skipped it).
            pos = match.end()
            continue
        # `#[Route('/x'), IsGranted('ROLE_USER')]` holds several attributes.
        current += [(match.start(), item) for item in split_attribute_group(content, match.start() + 2, close)]
        pos = close + 1
        if content.startswith("#[", _WS.match(content, pos).end()):
            continue
        target = _ATTR_TARGET.match(content, pos)
        blocks.append(AttributeBlock(current, target.group(1) if target else None, target.end() if target else pos))
        current = []
    return blocks


# A declaration starts its line (after any modifiers), so prose like
# "checks class and method attributes" in a comment doesn't count.
_CLASS_KEYWORD = re.compile(
    r"^[ \t]*(?:(?:final|abstract|readonly)[ \t]+)*(class)[ \t]+\w", re.MULTILINE
)


def class_decl_ends(content: str) -> list[int]:
    """Offsets just past every ``class`` keyword that declares a class."""
    return [match.end(1) for match in _CLASS_KEYWORD.finditer(content)]


def owning_class(
    decl_ends: list[int], class_blocks: dict[int, AttributeBlock], offset: int
) -> AttributeBlock | None:
    """The attribute block of the class declared last before ``offset``, or
    None when that class has no attributes. ``class_blocks`` is keyed by
    the offset just past the ``class`` keyword."""
    index = bisect.bisect_left(decl_ends, offset) - 1
    if index < 0:
        return None
    return class_blocks.get(decl_ends[index])


def symfony_guard(attribute: str) -> tuple[str, str, str] | None:
    """``(state, guard, evidence)`` for ``#[IsGranted(...)]`` / ``#[Security(...)]``."""
    match = _GUARD_ATTR.match(attribute)
    if not match:
        return None
    evidence = clip(f"#[{attribute}]")
    if match.group(1) == "IsGranted":
        role = _FIRST_STRING.search(attribute, match.end())
        if role and role.group(1).strip() in _PUBLIC_ROLES:
            return ANONYMOUS, "", evidence
    return REQUIRED, clip(attribute), evidence


@dataclass
class AccessRule:
    prefix: str | None  # None: unparseable (stop resolving)
    exact: bool
    methods: set[str] | None
    roles: set[str]
    evidence: str


_YAML_PAIR = re.compile(r"(\w+)\s*:\s*(\[[^\]]*\]|'[^']*'|\"[^\"]*\"|[^,}\[\]]+)")
_LITERAL_PREFIX = re.compile(r"\^(/[\w/-]*)(\$?)")
_MAX_ACCESS_RULES = 256
_ALLOWED_KEYS = frozenset({"path", "roles", "methods", "requires_channel"})


def _yaml_list(value: str) -> set[str]:
    value = value.strip().strip("[]")
    return {item.strip().strip("'\"") for item in value.split(",") if item.strip()}


def _access_rule(pairs: dict[str, str], evidence: str) -> AccessRule:
    unparseable = AccessRule(None, False, None, set(), evidence)
    if set(pairs) - _ALLOWED_KEYS or "roles" not in pairs:
        return unparseable
    path = pairs.get("path", "^/").strip().strip("'\"")
    literal = _LITERAL_PREFIX.fullmatch(path)
    if not literal:
        return unparseable
    methods = {m.upper() for m in _yaml_list(pairs["methods"])} if "methods" in pairs else None
    return AccessRule(literal.group(1), bool(literal.group(2)), methods, _yaml_list(pairs["roles"]), evidence)


def parse_access_control(text: str) -> list[AccessRule]:
    """``security.access_control`` rules, in order (flow or block mappings)."""
    lines = text.splitlines()
    rules: list[AccessRule] = []
    section_indent: int | None = None
    entry: dict[str, str] | None = None
    entry_text: list[str] = []

    def flush() -> None:
        if entry is not None:
            rules.append(_access_rule(entry, clip(" ".join(entry_text))))

    for raw in lines:
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip())
        if section_indent is None:
            if stripped.startswith("access_control:"):
                section_indent = indent
            continue
        if indent <= section_indent and not stripped.startswith("-"):
            break
        if stripped.startswith("-"):
            flush()
            body = stripped[1:].strip()
            entry = {}
            entry_text = [stripped]
        elif entry is not None:
            body = stripped
            entry_text.append(stripped)
        else:
            continue
        for key, value in _YAML_PAIR.findall(body.strip("{}")):
            entry[key] = value.strip()
    flush()
    if len(rules) > _MAX_ACCESS_RULES:
        # Past the cap, stop resolving rather than trust a partial list.
        rules = rules[:_MAX_ACCESS_RULES] + [AccessRule(None, False, None, set(), "")]
    return rules


def resolve_access_control(rules: list[AccessRule], path: str, method: str) -> tuple[str, str, str] | None:
    """First matching rule's ``(state, guard, evidence)``; None when none
    matches or a rule can't be evaluated statically."""
    for rule in rules:
        if rule.prefix is None:
            return None
        if rule.methods is not None:
            if method == "ANY":
                return None
            if method not in rule.methods:
                continue
        brace = path.find("{")
        if 0 <= brace < len(rule.prefix):
            return None  # a placeholder where the literal prefix is compared
        matched = path == rule.prefix if rule.exact else path.startswith(rule.prefix)
        if not matched:
            continue
        if rule.roles <= _PUBLIC_ROLES:
            return ANONYMOUS, "", rule.evidence
        roles = ", ".join(sorted(rule.roles))
        return REQUIRED, f"access_control ^{rule.prefix}: {roles}", rule.evidence
    return None


def combine(states: list[tuple[str, str, str]]) -> Resolution:
    """Every Symfony check must pass: one requiring auth makes the route
    required; explicitly public only when nothing requires auth."""
    required = [(guard, ev) for state, guard, ev in states if state == REQUIRED]
    if required:
        guards = list(dict.fromkeys(guard for guard, _ in required))
        return Resolution(REQUIRED, guards, clip("; ".join(dict.fromkeys(ev for _, ev in required))))
    anonymous = list(dict.fromkeys(ev for state, _, ev in states if state == ANONYMOUS))
    if anonymous:
        return Resolution(ANONYMOUS, [], clip("; ".join(anonymous)))
    return Resolution()
