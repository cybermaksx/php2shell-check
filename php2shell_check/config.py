"""Work out the effective value of PHP settings, per context.

PHP settings are not global: one install can have a mitigation on in one
FPM pool and off in another, or overridden in a single .htaccess. This
module parses every layer that can set a value and resolves each setting
per context (pool, vhost, directory, .htaccess), lowest layer first:

    0  PHP built-in default
    1  php.ini, then conf.d/*.ini in load order        (last one wins)
    2  php.ini [PATH=] / [HOST=] sections               CGI/FPM only
    3  FPM pool php_value/php_flag, then php_admin_*    admin sets a LOCK
    4  web server PHP_VALUE / PHP_ADMIN_VALUE           overrides the LOCK,
                                                        sticks to the worker
    5  Apache config php_value/php_flag/php_admin_*     admin sets a LOCK
    6  .htaccess php_value/php_flag                     blocked by a LOCK
    --- request startup ---
    7  .user.ini                                        blocked by a LOCK,
                                                        too late to mitigate

Layer 4 behaviour was measured on PHP-FPM 8.3: PHP_VALUE overrides a pool
php_admin_value, and the new value stays on that worker for later
requests, so it is treated as pool-wide.

Nothing here touches the system directly. Reading files goes through the
FileSystem protocol; discovery.HostFileSystem is the real implementation.
"""

from __future__ import annotations

import os
import re
import shlex
from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Protocol

from .models import ExpectOp, HardeningCheck, Mitigation, PhpInstall, SettingType

# --- value parsing ----------------------------------------------------------

_TRUE_WORDS = {"on", "yes", "true"}


def parse_ini_bool(value: str) -> bool:
    """Interpret a value the way zend_ini_parse_bool() does.

    "on", "yes" and "true" (any case) are true; anything else is true only
    if it starts with a non-zero integer, so "off", "", "none" and "abc"
    are all false.
    """
    text = value.strip().strip('"').strip()
    if text.lower() in _TRUE_WORDS:
        return True
    match = re.match(r"[+-]?\d+", text)
    return bool(match and int(match.group()) != 0)


_SIZE_RE = re.compile(r"^([+-]?\d+)\s*([kKmMgG]?)$")
_SIZE_FACTORS = {"": 1, "k": 1024, "m": 1024**2, "g": 1024**3}


def parse_ini_size(value: str) -> int:
    """Parse a quantity like "128M", "8m", "1G" or "-1" into bytes.

    -1 (unlimited) stays -1. Raises ValueError for anything PHP would
    reject or warn about.
    """
    text = value.strip().strip('"').strip()
    match = _SIZE_RE.match(text)
    if not match:
        raise ValueError(f"not a size: {value!r}")
    number, suffix = match.groups()
    return int(number) * _SIZE_FACTORS[suffix.lower()]


def parse_ini_int(value: str) -> int:
    text = value.strip().strip('"').strip()
    if not re.fullmatch(r"[+-]?\d+", text):
        raise ValueError(f"not an integer: {value!r}")
    return int(text)


def normalise(value: str, type_: SettingType) -> int | bool:
    if type_ == "bool":
        return parse_ini_bool(value)
    if type_ == "size":
        return parse_ini_size(value)
    if type_ == "int":
        return parse_ini_int(value)
    raise ValueError(f"unknown setting type: {type_!r}")


def satisfies(actual: str, op: ExpectOp, expected: str, type_: SettingType) -> bool:
    """True if the setting's actual value meets the expectation.

    For sizes, -1 means unlimited, so it never satisfies an upper bound.
    """
    a, e = normalise(actual, type_), normalise(expected, type_)
    if op == "eq":
        return a == e
    if type_ == "bool":
        raise ValueError(f"operator {op!r} makes no sense for a bool")
    if type_ == "size" and a == -1:
        return op == "gte"
    if op == "lte":
        return a <= e
    if op == "gte":
        return a >= e
    raise ValueError(f"unknown operator: {op!r}")


# Where each setting we check may be changed, from the "Changeable" column
# of https://www.php.net/manual/en/ini.list.php. INI_SYSTEM settings are
# ignored by .htaccess, .user.ini and Apache php_value, as PHP ignores them.
# Unknown settings are treated as INI_ALL, which only makes results stricter.
INI_SYSTEM_ONLY = {"max_file_uploads", "expose_php"}

# Defaults for settings that have no php_default in advisories.json
# (hardening checks), from the same manual page.
PHP_DEFAULTS = {
    "expose_php": "1",
    "max_input_nesting_level": "64",
    "max_input_vars": "1000",
    "max_file_uploads": "20",
    "upload_max_filesize": "2M",
    "post_max_size": "8M",
    "user_ini.filename": ".user.ini",
}

_BOOL_WORDS = {"on": "1", "yes": "1", "true": "1", "off": "", "no": "", "false": "", "none": "", "null": ""}


def ini_value(raw: str) -> str:
    """Value of one php.ini right-hand side, as PHP's ini scanner yields it.

    Quotes are removed, a ';' outside quotes starts a comment, and the bare
    words On/Off/Yes/No/True/False/None/Null become "1" or "".
    """
    raw = raw.strip()
    if raw and raw[0] in "\"'":
        quote = raw[0]
        end = raw.find(quote, 1)
        return raw[1:end] if end != -1 else raw[1:]
    value = raw.split(";", 1)[0].strip()
    return _BOOL_WORDS.get(value.lower(), value)


# --- assignments and layers -------------------------------------------------


class Layer(IntEnum):
    DEFAULT = 0
    INI = 1
    INI_SECTION = 2
    POOL = 3
    FRONTEND = 4
    APACHE = 5
    HTACCESS = 6
    USER_INI = 7


@dataclass(frozen=True)
class Assignment:
    setting: str
    value: str
    layer: Layer
    origin: str  # "path:line"
    admin: bool = False  # php_admin_* / PHP_ADMIN_VALUE: sets a lock


@dataclass
class ParseResult:
    warnings: list[str] = field(default_factory=list)


# --- reading files ----------------------------------------------------------


class FileSystem(Protocol):
    def read(self, path: str) -> str | None:
        """File contents, or None if it is missing or unreadable (the
        implementation records a warning for unreadable files)."""

    def glob(self, pattern: str) -> list[str]:
        """Sorted matches; a pattern without wildcards matches itself if it exists."""

    def find(self, roots: Sequence[str], names: set[str]) -> list[str]:
        """Every file under `roots` whose basename is in `names`."""


# --- php.ini / .user.ini ----------------------------------------------------

_SECTION_RE = re.compile(r"^\[(.+)\]\s*$")
_INI_LINE_RE = re.compile(r"^([A-Za-z0-9_.\-]+)(\[[^\]]*\])?\s*=\s*(.*)$")


def parse_ini(text: str, path: str, layer: Layer = Layer.INI) -> tuple[list[Assignment], dict[str, list[Assignment]]]:
    """Returns (global assignments, {"PATH=/x" or "HOST=y": assignments})."""
    global_values: list[Assignment] = []
    sections: dict[str, list[Assignment]] = {}
    current: list[Assignment] = global_values
    for number, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line or line.startswith((";", "#")):
            continue
        section = _SECTION_RE.match(line)
        if section:
            name = section.group(1).strip()
            if name.upper().startswith(("PATH=", "HOST=")):
                current = sections.setdefault(name, [])
            else:
                current = global_values  # [PHP], [Session] ... are cosmetic
            continue
        match = _INI_LINE_RE.match(line)
        if not match or match.group(2):  # skip extension[] style arrays
            continue
        key, _, raw = match.groups()
        current.append(Assignment(key, ini_value(raw), layer, f"{path}:{number}"))
    return global_values, sections


# --- php-fpm.conf and pools -------------------------------------------------


@dataclass
class Pool:
    name: str
    origin: str
    listen: str = ""
    values: list[Assignment] = field(default_factory=list)  # php_value / php_flag
    admin_values: list[Assignment] = field(default_factory=list)  # php_admin_*


_FPM_PHP_RE = re.compile(r"^(php_value|php_flag|php_admin_value|php_admin_flag)\[([^\]]+)\]\s*=\s*(.*)$")
_FPM_KEY_RE = re.compile(r"^([A-Za-z0-9_.]+)\s*=\s*(.*)$")


def parse_fpm(fs: FileSystem, main_conf: str, result: ParseResult, max_depth: int = 10) -> list[Pool]:
    """Pools defined by php-fpm.conf and everything it includes.

    `include` works at global and pool level; in pool context the included
    file's settings belong to that pool, and $pool expands to its name.
    """
    pools: dict[str, Pool] = {}
    seen: set[str] = set()

    def process(path: str, pool: Pool | None, depth: int) -> Pool | None:
        if path in seen or depth > max_depth:
            result.warnings.append(f"{path}: include loop or too deep, skipped")
            return pool
        seen.add(path)
        text = fs.read(path)
        if text is None:
            result.warnings.append(f"{path}: cannot read FPM config")
            return pool
        base_dir = os.path.dirname(path)
        for number, line in enumerate(text.splitlines(), start=1):
            line = line.strip()
            if not line or line.startswith((";", "#")):
                continue
            origin = f"{path}:{number}"
            section = _SECTION_RE.match(line)
            if section:
                name = section.group(1).strip()
                pool = None if name == "global" else pools.setdefault(name, Pool(name, origin))
                continue
            php = _FPM_PHP_RE.match(line)
            if php:
                if pool is None:
                    result.warnings.append(f"{origin}: {php.group(1)} outside a pool, ignored")
                    continue
                kind, key, raw = php.groups()
                value = ini_value(raw).replace("$pool", pool.name)
                admin = kind.startswith("php_admin")
                target = pool.admin_values if admin else pool.values
                target.append(Assignment(key.strip(), value, Layer.POOL, origin, admin=admin))
                continue
            kv = _FPM_KEY_RE.match(line)
            if not kv:
                continue
            key, raw = kv.groups()
            value = ini_value(raw)
            if pool is not None:
                value = value.replace("$pool", pool.name)
            if key == "include":
                pattern = value if os.path.isabs(value) else os.path.join(base_dir, value)
                matches = fs.glob(pattern)
                if not matches:
                    result.warnings.append(f"{origin}: include {value} matches no files")
                # Like FPM's own parser, the section an included file ends
                # in stays current afterwards.
                for included in matches:
                    pool = process(included, pool, depth + 1)
            elif key == "listen" and pool is not None:
                pool.listen = value
        return pool

    process(main_conf, None, 0)
    return list(pools.values())


# --- FastCGI endpoints ------------------------------------------------------


def normalise_endpoint(text: str) -> str | None:
    """Turn a pool listen value or a web server target into a comparable key.

    "/run/php/x.sock", "unix:/run/php/x.sock" -> "unix:/run/php/x.sock"
    "127.0.0.1:9000", "9000", "[::]:9000", "fcgi://localhost:9000/x" -> "tcp:9000"

    TCP endpoints compare by port only: on one host, a pool on
    127.0.0.1:9000 and a web server pointing at localhost:9000 are the same.
    """
    text = text.strip().strip("\"'")
    if not text:
        return None
    if text.startswith("proxy:"):
        text = text[len("proxy:") :]
    if text.startswith("unix:"):
        path = text[len("unix:") :].split("|", 1)[0]
        return f"unix:{path}"
    if text.startswith("/"):
        return f"unix:{text}"
    text = re.sub(r"^fcgi://", "", text)
    host_port = text.split("/", 1)[0]
    port = host_port.rsplit(":", 1)[-1] if ":" in host_port else host_port
    return f"tcp:{port}" if port.isdigit() else None


# --- frontend PHP_VALUE / PHP_ADMIN_VALUE -----------------------------------


@dataclass
class FrontendOverride:
    origin: str
    assignments: list[Assignment]
    targets: list[str]  # normalised endpoints in the same server/vhost; [] = unknown


def parse_frontend_value(text: str, admin: bool, origin: str) -> list[Assignment]:
    """PHP_VALUE / PHP_ADMIN_VALUE hold ini lines separated by newlines
    (real ones or a literal backslash-n, depending on the web server)."""
    assignments = []
    for line in re.split(r"\n|\\n", text):
        if "=" not in line:
            continue
        key, _, raw = line.partition("=")
        if key.strip():
            assignments.append(Assignment(key.strip(), ini_value(raw), Layer.FRONTEND, origin, admin=admin))
    return assignments


# --- nginx ------------------------------------------------------------------


@dataclass
class NginxDirective:
    name: str
    args: list[str]
    origin: str
    children: list[NginxDirective] | None = None  # None = not a block


_NGINX_ESCAPES = {"n": "\n", "t": "\t", "r": "\r"}


def _nginx_tokens(text: str) -> list[tuple[str, int, bool]]:
    """(token, line, quoted) tuples; '{', '}' and ';' are their own tokens."""
    tokens: list[tuple[str, int, bool]] = []
    i, line = 0, 1
    while i < len(text):
        c = text[i]
        if c == "\n":
            line += 1
            i += 1
        elif c.isspace():
            i += 1
        elif c == "#":
            while i < len(text) and text[i] != "\n":
                i += 1
        elif c in "{};":
            tokens.append((c, line, False))
            i += 1
        elif c in "\"'":
            quote, start_line, out = c, line, []
            i += 1
            while i < len(text) and text[i] != quote:
                if text[i] == "\\" and i + 1 < len(text):
                    nxt = text[i + 1]
                    out.append(_NGINX_ESCAPES.get(nxt, nxt if nxt in "\"'\\" else "\\" + nxt))
                    i += 2
                    continue
                if text[i] == "\n":
                    line += 1
                out.append(text[i])
                i += 1
            i += 1
            tokens.append(("".join(out), start_line, True))
        else:
            start = i
            while i < len(text) and not text[i].isspace() and text[i] not in "{};":
                i += 1
            tokens.append((text[start:i], line, False))
    return tokens


def parse_nginx(fs: FileSystem, main_conf: str, result: ParseResult, max_depth: int = 10) -> list[NginxDirective]:
    """Directive tree with every `include` expanded in place."""
    conf_dir = os.path.dirname(main_conf)

    def parse_file(path: str, depth: int) -> list[NginxDirective]:
        if depth > max_depth:
            result.warnings.append(f"{path}: nginx include too deep, skipped")
            return []
        text = fs.read(path)
        if text is None:
            result.warnings.append(f"{path}: cannot read nginx config")
            return []
        tokens = _nginx_tokens(text)
        pos = 0

        def block() -> list[NginxDirective]:
            nonlocal pos
            items: list[NginxDirective] = []
            words: list[str] = []
            first_line = 0
            while pos < len(tokens):
                token, line, quoted = tokens[pos]
                pos += 1
                if not quoted and token == "}":
                    return items
                if not quoted and token in (";", "{"):
                    if not words:
                        continue
                    name, args = words[0], words[1:]
                    origin = f"{path}:{first_line}"
                    if token == "{":
                        items.append(NginxDirective(name, args, origin, block()))
                    elif name == "include" and args:
                        pattern = args[0] if os.path.isabs(args[0]) else os.path.join(conf_dir, args[0])
                        matches = fs.glob(pattern)
                        if not matches and not re.search(r"[*?\[]", pattern):
                            result.warnings.append(f"{origin}: include {args[0]} not found")
                        for included in matches:
                            items.extend(parse_file(included, depth + 1))
                    else:
                        items.append(NginxDirective(name, args, origin))
                    words = []
                    continue
                if not words:
                    first_line = line
                words.append(token)
            return items

        return block()

    return parse_file(main_conf, 0)


def _walk_nginx(directives: list[NginxDirective], name: str):
    for d in directives:
        if d.name == name:
            yield d
        if d.children:
            yield from _walk_nginx(d.children, name)


def _expand_nginx_vars(value: str, variables: dict[str, str]) -> str:
    return re.sub(r"\$(\w+)", lambda m: variables.get(m.group(1), m.group(0)), value)


@dataclass
class WebConfig:
    frontends: list[FrontendOverride] = field(default_factory=list)
    docroots: list[str] = field(default_factory=list)
    apache: list[ApacheAssignment] = field(default_factory=list)
    vhost_docroots: dict[str, str] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


def nginx_to_web(tree: list[NginxDirective], web: WebConfig) -> None:
    upstreams: dict[str, list[str]] = {}
    for up in _walk_nginx(tree, "upstream"):
        if up.args and up.children:
            upstreams[up.args[0]] = [s.args[0] for s in up.children if s.name == "server" and s.args]

    def targets_of(text: str) -> list[str]:
        if text in upstreams:
            return [e for e in (normalise_endpoint(s) for s in upstreams[text]) if e]
        endpoint = normalise_endpoint(text)
        return [endpoint] if endpoint else []

    for root in _walk_nginx(tree, "root"):
        if root.args and root.args[0] not in web.docroots:
            web.docroots.append(root.args[0])

    servers = list(_walk_nginx(tree, "server")) or [NginxDirective("main", [], "", tree)]
    for server in servers:
        if server.children is None:
            continue  # "server" inside an upstream block
        targets = list(
            dict.fromkeys(t for p in _walk_nginx(server.children, "fastcgi_pass") if p.args for t in targets_of(p.args[0]))
        )
        variables: dict[str, str] = {}
        for d in _walk_nginx(server.children, "set"):
            if len(d.args) == 2:
                variables[d.args[0].lstrip("$")] = _expand_nginx_vars(d.args[1], variables)
        for param in _walk_nginx(server.children, "fastcgi_param"):
            if len(param.args) < 2 or param.args[0] not in ("PHP_VALUE", "PHP_ADMIN_VALUE"):
                continue
            value = _expand_nginx_vars(param.args[1], variables)
            if re.search(r"\$\w+", value):
                web.warnings.append(f"{param.origin}: {param.args[0]} uses an unresolved nginx variable")
            admin = param.args[0] == "PHP_ADMIN_VALUE"
            web.frontends.append(
                FrontendOverride(param.origin, parse_frontend_value(value, admin, param.origin), targets)
            )


# --- Apache -----------------------------------------------------------------


@dataclass(frozen=True)
class ApacheAssignment:
    assignment: Assignment
    vhost: str | None  # "<VirtualHost *:80> at path:line"
    directory: str | None  # <Directory> path


_APACHE_PHP = {"php_value", "php_flag", "php_admin_value", "php_admin_flag"}
_APACHE_SECTION_OPEN = re.compile(r"^<\s*(\w+)\s*([^>]*)>$")
_APACHE_SECTION_CLOSE = re.compile(r"^</\s*(\w+)\s*>$")
_APACHE_FCGI_TARGET = re.compile(r'(proxy:unix:[^|"\s]+|(?:proxy:)?fcgi://[^/"\s]+)')


def _apache_lines(text: str) -> list[tuple[int, str]]:
    """Logical lines: comments dropped, backslash continuations joined."""
    lines: list[tuple[int, str]] = []
    pending, start = "", 0
    for number, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if not pending:
            start = number
        if stripped.endswith("\\"):
            pending += stripped[:-1] + " "
            continue
        full = (pending + stripped).strip()
        pending = ""
        if full and not full.startswith("#"):
            lines.append((start, full))
    return lines


def _apache_words(line: str) -> list[str] | None:
    try:
        return shlex.split(line, posix=True)
    except ValueError:
        return None


def _apache_php_directive(words: list[str], layer: Layer, origin: str) -> Assignment | None:
    if len(words) < 2:
        return None
    kind, key = words[0].lower(), words[1]
    value = " ".join(words[2:])
    if kind.endswith("_flag"):
        value = "1" if parse_ini_bool(value) else ""
    elif value.lower() == "none":
        value = ""
    return Assignment(key, value, layer, origin, admin=kind.startswith("php_admin"))


def parse_apache(fs: FileSystem, main_conf: str, web: WebConfig, max_depth: int = 10) -> None:
    server_root = os.path.dirname(main_conf)
    first = fs.read(main_conf)
    if first:
        match = re.search(r'^\s*ServerRoot\s+"?([^"\s]+)"?', first, flags=re.M | re.I)
        if match:
            server_root = match.group(1)

    seen: set[str] = set()

    def process(path: str, stack: list[tuple[str, str, str]], depth: int) -> None:
        if path in seen or depth > max_depth:
            web.warnings.append(f"{path}: Apache include loop or too deep, skipped")
            return
        seen.add(path)
        text = fs.read(path)
        if text is None:
            web.warnings.append(f"{path}: cannot read Apache config")
            return
        for number, line in _apache_lines(text):
            origin = f"{path}:{number}"
            closing = _APACHE_SECTION_CLOSE.match(line)
            if closing:
                if stack and stack[-1][0].lower() == closing.group(1).lower():
                    stack.pop()
                continue
            opening = _APACHE_SECTION_OPEN.match(line)
            if opening:
                stack.append((opening.group(1), opening.group(2).strip().strip('"'), origin))
                continue
            words = _apache_words(line)
            if not words:
                web.warnings.append(f"{origin}: cannot parse line")
                continue
            name = words[0].lower()
            vhost = next((f"<VirtualHost {a}> at {o}" for t, a, o in stack if t.lower() == "virtualhost"), None)
            directory = next(
                (a for t, a, _ in reversed(stack) if t.lower() in ("directory", "directorymatch")), None
            )
            if name in ("include", "includeoptional") and len(words) > 1:
                pattern = words[1] if os.path.isabs(words[1]) else os.path.join(server_root, words[1])
                matches = fs.glob(pattern)
                if not matches and name == "include":
                    web.warnings.append(f"{origin}: Include {words[1]} matches no files")
                for included in matches:
                    process(included, stack, depth + 1)
            elif name in _APACHE_PHP:
                assignment = _apache_php_directive(words, Layer.APACHE, origin)
                if assignment:
                    web.apache.append(ApacheAssignment(assignment, vhost, directory))
            elif name == "documentroot" and len(words) > 1:
                if words[1] not in web.docroots:
                    web.docroots.append(words[1])
                if vhost:
                    web.vhost_docroots[vhost] = words[1]
            elif name in ("setenv", "proxyfcgisetenvif") and ("PHP_VALUE" in words or "PHP_ADMIN_VALUE" in words):
                key = "PHP_ADMIN_VALUE" if "PHP_ADMIN_VALUE" in words else "PHP_VALUE"
                idx = words.index(key)
                if idx + 1 < len(words):
                    admin = key == "PHP_ADMIN_VALUE"
                    frontends.append(FrontendOverride(origin, parse_frontend_value(words[idx + 1], admin, origin), []))
            for match in _APACHE_FCGI_TARGET.finditer(line):
                endpoint = normalise_endpoint(match.group(1))
                if endpoint and endpoint not in targets:
                    targets.append(endpoint)

    # Apache frontends are tied to whatever FPM endpoints this config proxies
    # to. Scoping that per vhost is not worth the parsing; all are used.
    frontends: list[FrontendOverride] = []
    targets: list[str] = []
    process(main_conf, [], 0)
    for frontend in frontends:
        frontend.targets = list(targets)
    web.frontends.extend(frontends)


def parse_htaccess(text: str, path: str, warnings: list[str]) -> list[Assignment]:
    assignments = []
    for number, line in _apache_lines(text):
        words = _apache_words(line)
        if not words or words[0].lower() not in _APACHE_PHP:
            continue
        origin = f"{path}:{number}"
        if words[0].lower().startswith("php_admin"):
            warnings.append(f"{origin}: {words[0]} is not allowed in .htaccess; PHP ignores it")
            continue
        assignment = _apache_php_directive(words, Layer.HTACCESS, origin)
        if assignment:
            assignments.append(assignment)
    return assignments


# --- per-directory files ----------------------------------------------------


@dataclass
class DirFile:
    directory: str
    assignments: list[Assignment]


def load_dir_files(fs: FileSystem, roots: Sequence[str], name: str, layer: Layer, warnings: list[str]) -> list[DirFile]:
    files = []
    for path in fs.find(roots, {name}):
        text = fs.read(path)
        if text is None:
            continue
        if layer == Layer.HTACCESS:
            assignments = parse_htaccess(text, path, warnings)
        else:
            assignments, _ = parse_ini(text, path, layer)
        if assignments:
            files.append(DirFile(os.path.dirname(path), assignments))
    return files


def _is_under(path: str, directory: str) -> bool:
    directory = directory.rstrip("/") or "/"
    return path == directory or path.startswith(directory + "/") or directory == "/"


def _chain(files: list[DirFile], target: DirFile) -> list[Assignment]:
    """Assignments from every per-directory file in target's ancestry,
    outermost first, ending with target itself."""
    ancestors = [f for f in files if _is_under(target.directory, f.directory)]
    ancestors.sort(key=lambda f: len(f.directory))
    return [a for f in ancestors for a in f.assignments]


# --- contexts and resolution ------------------------------------------------


@dataclass
class Context:
    name: str
    stack: list[Assignment]
    late: list[list[Assignment]] = field(default_factory=list)  # alternatives, e.g. one per .user.ini


@dataclass(frozen=True)
class ContextValue:
    context: str
    value: str
    origin: str
    locked: bool
    satisfied: bool | None  # None: value could not be interpreted


@dataclass
class SettingResult:
    check_id: str
    setting: str
    contexts: list[ContextValue] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)  # ignored or late overrides
    warnings: list[str] = field(default_factory=list)

    @property
    def satisfied(self) -> bool | None:
        states = [c.satisfied for c in self.contexts]
        if not states or any(s is False for s in states):
            return False if states else None
        return None if any(s is None for s in states) else True


@dataclass
class Resolved:
    value: str
    origin: str
    locked: bool
    notes: list[str]


def resolve(setting: str, default: str, stack: Sequence[Assignment]) -> Resolved:
    """Apply the stack in order and return where the value ended up."""
    value, origin, locked = default, "PHP default", False
    notes: list[str] = []
    system_only = setting in INI_SYSTEM_ONLY
    for a in stack:
        if a.setting != setting:
            continue
        per_dir = a.layer in (Layer.HTACCESS, Layer.USER_INI)
        if system_only and (per_dir or (a.layer == Layer.APACHE and not a.admin)):
            notes.append(f"{a.origin}: {setting} is INI_SYSTEM; this line has no effect")
            continue
        if per_dir and locked:
            notes.append(f"{a.origin}: blocked by php_admin value at {origin}")
            continue
        value, origin = a.value, a.origin
        locked = locked or a.admin
    return Resolved(value, origin, locked, notes)


def contexts_for(
    install: PhpInstall,
    ini: list[Assignment],
    sections: dict[str, list[Assignment]],
    pools: list[Pool],
    web: WebConfig,
    htaccess: list[DirFile],
    user_ini: list[DirFile],
) -> tuple[list[Context], list[str]]:
    """The contexts in which this install serves requests, each with the
    stack of assignments that apply there."""
    notes: list[str] = []
    late = [_chain(user_ini, f) for f in user_ini]
    section_contexts = [Context(f"php.ini [{name}]", ini + values, late) for name, values in sections.items()]

    if install.sapi == "fpm-fcgi":
        contexts = []
        if not pools:
            notes.append("no FPM pools found; only php.ini values are checked")
            contexts.append(Context("php.ini (no pools found)", list(ini), late))
        for pool in pools:
            stack = ini + pool.values + pool.admin_values
            contexts.append(Context(f"pool {pool.name}", stack, late))
            endpoint = normalise_endpoint(pool.listen)
            for frontend in web.frontends:
                if frontend.targets and endpoint not in frontend.targets:
                    continue
                how = "" if frontend.targets else " (target unknown, assumed)"
                contexts.append(
                    Context(f"pool {pool.name} after a request from {frontend.origin}{how}", stack + frontend.assignments, late)
                )
        return contexts + section_contexts, notes

    if install.sapi == "apache2handler":
        server = [a.assignment for a in web.apache if a.vhost is None and a.directory is None]
        contexts = [Context("Apache server config", ini + server)]
        scopes = sorted({(a.vhost, a.directory) for a in web.apache if a.vhost or a.directory}, key=str)
        for vhost, directory in scopes:
            stack = ini + server + [
                a.assignment
                for a in web.apache
                if (a.vhost in (None, vhost))
                and (a.directory is None or (directory is not None and _is_under(directory, a.directory)))
                and (a.vhost or a.directory)
            ]
            label = " ".join(part for part in (vhost, f"<Directory {directory}>" if directory else None) if part)
            contexts.append(Context(label, stack))
        for f in htaccess:
            apache = [
                a.assignment
                for a in web.apache
                if (a.directory is None or _is_under(f.directory, a.directory))
                and (a.vhost is None or _is_under(f.directory, web.vhost_docroots.get(a.vhost, "/nonexistent")))
            ]
            contexts.append(Context(f".htaccess in {f.directory}", ini + apache + _chain(htaccess, f)))
        return contexts, notes

    if install.sapi == "cgi-fcgi":
        return [Context("php.ini", list(ini), late)] + section_contexts, notes

    if install.sapi == "litespeed":
        notes.append("LiteSpeed .htaccess handling assumed like mod_php; not verified")
        contexts = [Context("php.ini", list(ini))]
        contexts += [Context(f".htaccess in {f.directory}", ini + _chain(htaccess, f)) for f in htaccess]
        return contexts, notes

    return [Context("php.ini", list(ini))], notes


def evaluate(
    check: Mitigation | HardeningCheck,
    contexts: list[Context],
    php_default: str,
) -> SettingResult:
    """Resolve one setting in every context and judge it against `expect`."""
    early_only = getattr(check, "early_only", False)
    prefer_admin = getattr(check, "prefer_admin", False)
    result = SettingResult(check.id, check.setting)

    def judge(value: str) -> bool | None:
        if check.expect is None:
            return True  # report-only check
        if "${" in value:
            result.warnings.append(f"{check.setting} = {value!r} uses an environment variable; cannot evaluate")
            return None
        try:
            return satisfies(value, check.expect.op, check.expect.value, check.type)
        except ValueError as exc:
            result.warnings.append(f"{check.setting}: {exc}")
            return None

    for ctx in contexts:
        early = resolve(check.setting, php_default, ctx.stack)
        result.notes.extend(n for n in early.notes if n not in result.notes)
        final = early
        for alternative in ctx.late:
            full = resolve(check.setting, php_default, ctx.stack + alternative)
            result.notes.extend(n for n in full.notes if n not in result.notes)
            if full.origin == early.origin:
                continue
            ok_early, ok_full = judge(early.value), judge(full.value)
            if early_only:
                if ok_early and ok_full is False:
                    note = f"{full.origin}: sets {check.setting} = {full.value!r} after request startup ({ctx.name})"
                    if note not in result.notes:
                        result.notes.append(note)
                elif not ok_early and ok_full:
                    note = f"{full.origin}: .user.ini value comes too late to count as a mitigation"
                    if note not in result.notes:
                        result.notes.append(note)
            elif ok_full is False:
                final = full
        satisfied = judge(final.value)
        if satisfied and prefer_admin and not final.locked and check.expect is not None:
            warning = (
                f"{ctx.name}: {check.setting} = {final.value!r} is not set with php_admin_value; "
                "an application can change it with ini_set()"
            )
            if warning not in result.warnings:
                result.warnings.append(warning)
        result.contexts.append(ContextValue(ctx.name, final.value, final.origin, final.locked, satisfied))
    return result


def cross_check(setting: str, type_: SettingType, ini: list[Assignment], default: str, install: PhpInstall) -> str | None:
    """Compare our php.ini result with what `php -i` reported as the master
    value. A mismatch means our parsing is wrong somewhere."""
    reported = install.ini_values.get(setting)
    if reported is None:
        return None
    ours = resolve(setting, default, ini)
    if reported in ("no value",):
        reported = ""
    try:
        if normalise(ours.value, type_) == normalise(reported, type_):
            return None
    except ValueError:
        if ours.value == reported:
            return None
    return (
        f"{setting}: php.ini parsing gives {ours.value!r} (from {ours.origin}) "
        f"but PHP reports {reported!r}; the result for this setting may be wrong"
    )


# --- entry points -----------------------------------------------------------

APACHE_MAIN_CONFS = ("/etc/apache2/apache2.conf", "/etc/httpd/conf/httpd.conf", "/usr/local/apache2/conf/httpd.conf")
NGINX_MAIN_CONFS = ("/etc/nginx/nginx.conf", "/usr/local/nginx/conf/nginx.conf")


def load_web_config(fs: FileSystem) -> WebConfig:
    """Parse nginx and Apache once per run; every install shares the result."""
    web = WebConfig()
    for conf in NGINX_MAIN_CONFS:
        if fs.read(conf) is not None:
            result = ParseResult()
            nginx_to_web(parse_nginx(fs, conf, result), web)
            web.warnings.extend(result.warnings)
    for conf in APACHE_MAIN_CONFS:
        if fs.read(conf) is not None:
            parse_apache(fs, conf, web)
    return web


@dataclass
class ConfigReport:
    results: dict[str, SettingResult] = field(default_factory=dict)  # check id -> result
    contexts: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def check_install(
    install: PhpInstall,
    checks: Sequence[Mitigation | HardeningCheck],
    fs: FileSystem,
    web: WebConfig,
    extra_roots: Sequence[str] = (),
) -> ConfigReport:
    """Resolve every check for one install."""
    report = ConfigReport()

    ini: list[Assignment] = []
    sections: dict[str, list[Assignment]] = {}
    for path in install.ini_files:
        text = fs.read(path)
        if text is None:
            report.warnings.append(f"{path}: cannot read ini file")
            continue
        values, file_sections = parse_ini(text, path)
        ini.extend(values)
        for name, assignments in file_sections.items():
            sections.setdefault(name, []).extend(assignments)
    if install.sapi not in ("fpm-fcgi", "cgi-fcgi"):
        sections = {}  # [PATH=]/[HOST=] only work in CGI/FastCGI

    pools: list[Pool] = []
    if install.sapi == "fpm-fcgi" and install.fpm_config:
        parse = ParseResult()
        pools = parse_fpm(fs, install.fpm_config, parse)
        report.warnings.extend(parse.warnings)

    roots = list(dict.fromkeys([*web.docroots, *extra_roots]))
    htaccess: list[DirFile] = []
    user_ini: list[DirFile] = []
    if install.sapi in ("apache2handler", "litespeed"):
        htaccess = load_dir_files(fs, roots, ".htaccess", Layer.HTACCESS, report.warnings)
    if install.sapi in ("fpm-fcgi", "cgi-fcgi"):
        name = resolve("user_ini.filename", PHP_DEFAULTS["user_ini.filename"], ini).value
        if name:
            user_ini = load_dir_files(fs, roots, name, Layer.USER_INI, report.warnings)

    contexts, notes = contexts_for(install, ini, sections, pools, web, htaccess, user_ini)
    report.contexts = [c.name for c in contexts]
    report.notes.extend(notes)

    for check in checks:
        default = getattr(check, "php_default", None) or PHP_DEFAULTS.get(check.setting, "")
        report.results[check.id] = evaluate(check, contexts, default)
        mismatch = cross_check(check.setting, check.type, ini, default, install)
        if mismatch:
            report.warnings.append(mismatch)
    return report

