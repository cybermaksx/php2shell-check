"""Precedence tests. The FPM rules marked "measured" reproduce what PHP-FPM
8.3 actually did in a container (pool admin vs .user.ini, PHP_VALUE vs pool
admin, values sticking to the worker)."""

from pathlib import Path

import pytest

from php2shell_check.advisories import load
from php2shell_check.config import (
    Assignment,
    Context,
    Layer,
    ParseResult,
    check_install,
    cross_check,
    evaluate,
    ini_value,
    load_web_config,
    normalise_endpoint,
    parse_fpm,
    parse_frontend_value,
    parse_htaccess,
    parse_ini,
    parse_nginx,
    resolve,
)
from php2shell_check.discovery import HostFileSystem
from php2shell_check.models import Expectation, HardeningCheck, PhpInstall

CONFIG = Path(__file__).parent / "fixtures" / "config"


@pytest.fixture(scope="module")
def db():
    return load()


def a(setting, value, layer, origin="x:1", admin=False):
    return Assignment(setting, value, layer, origin, admin)


# --- ini values -------------------------------------------------------------


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("On", "1"),
        ("off", ""),
        ("None", ""),
        ("128M", "128M"),
        ("128M ; comment", "128M"),
        ('"quoted ; not a comment"', "quoted ; not a comment"),
        ("'single'", "single"),
        ('"On"', "On"),  # quoted words stay as they are
        ("", ""),
        ("${HOME}/tmp", "${HOME}/tmp"),
    ],
)
def test_ini_value(raw, expected):
    assert ini_value(raw) == expected


def test_parse_ini_sections_and_comments():
    text = (
        "[PHP]\n"
        ";memory_limit = 1G\n"
        "memory_limit = 128M\n"
        "extension[] = foo\n"
        "[PATH=/var/www/b]\n"
        "memory_limit = 64M\n"
        "[Session]\n"
        "session.upload_progress.enabled = Off\n"
    )
    values, sections = parse_ini(text, "/etc/php.ini")
    assert [(v.setting, v.value, v.origin) for v in values] == [
        ("memory_limit", "128M", "/etc/php.ini:3"),
        ("session.upload_progress.enabled", "", "/etc/php.ini:8"),
    ]
    assert [(v.setting, v.value) for v in sections["PATH=/var/www/b"]] == [("memory_limit", "64M")]


# --- endpoints and frontend values ------------------------------------------


@pytest.mark.parametrize(
    "text, expected",
    [
        ("/run/php/php8.3-fpm.sock", "unix:/run/php/php8.3-fpm.sock"),
        ("unix:/run/php/php8.3-fpm.sock", "unix:/run/php/php8.3-fpm.sock"),
        ("proxy:unix:/run/php/x.sock|fcgi://localhost", "unix:/run/php/x.sock"),
        ("127.0.0.1:9000", "tcp:9000"),
        ("9000", "tcp:9000"),
        ("[::]:9000", "tcp:9000"),
        ("localhost:9000", "tcp:9000"),
        ("fcgi://127.0.0.1:9000/var/www/$1", "tcp:9000"),
        ("proxy:fcgi://127.0.0.1:9000", "tcp:9000"),
        ("legacy_php", None),
        ("", None),
    ],
)
def test_normalise_endpoint(text, expected):
    assert normalise_endpoint(text) == expected


def test_parse_frontend_value_real_and_literal_newlines():
    real = parse_frontend_value("memory_limit=256M\nmax_execution_time=300", False, "n:1")
    literal = parse_frontend_value("memory_limit=256M \\n session.upload_progress.enabled=Off", True, "a:1")
    assert [(x.setting, x.value) for x in real] == [("memory_limit", "256M"), ("max_execution_time", "300")]
    assert [(x.setting, x.value, x.admin) for x in literal] == [
        ("memory_limit", "256M", True),
        ("session.upload_progress.enabled", "", True),
    ]


# --- resolution rules -------------------------------------------------------


def test_last_assignment_wins_within_ini():
    stack = [a("memory_limit", "128M", Layer.INI, "php.ini:1"), a("memory_limit", "-1", Layer.INI, "conf.d/99.ini:1")]
    assert resolve("memory_limit", "128M", stack).origin == "conf.d/99.ini:1"


def test_default_when_nothing_sets_it():
    r = resolve("session.upload_progress.enabled", "1", [])
    assert (r.value, r.origin, r.locked) == ("1", "PHP default", False)


def test_measured_pool_admin_blocks_user_ini():
    stack = [
        a("memory_limit", "64M", Layer.POOL, "www.conf:5", admin=True),
        a("memory_limit", "16M", Layer.USER_INI, "/app/.user.ini:3"),
    ]
    r = resolve("memory_limit", "128M", stack)
    assert r.value == "64M"
    assert "blocked by php_admin value at www.conf:5" in r.notes[0]


def test_measured_pool_php_value_loses_to_user_ini():
    stack = [a("x", "2", Layer.POOL, "www.conf:6"), a("x", "3", Layer.USER_INI, "/app/.user.ini:2")]
    assert resolve("x", "1", stack).value == "3"


def test_measured_php_value_overrides_pool_admin():
    stack = [
        a("memory_limit", "64M", Layer.POOL, "www.conf:5", admin=True),
        a("memory_limit", "32M", Layer.FRONTEND, "nginx:9"),
        a("memory_limit", "16M", Layer.USER_INI, "/app/.user.ini:3"),
    ]
    r = resolve("memory_limit", "128M", stack)
    assert r.value == "32M"  # frontend wins over the lock ...
    assert r.locked  # ... but the lock still blocks .user.ini


def test_htaccess_blocked_by_apache_admin():
    stack = [
        a("session.upload_progress.enabled", "", Layer.APACHE, "vhost:4", admin=True),
        a("session.upload_progress.enabled", "1", Layer.HTACCESS, ".htaccess:2"),
    ]
    assert resolve("session.upload_progress.enabled", "1", stack).value == ""


def test_system_only_setting_ignored_per_directory():
    stack = [a("max_file_uploads", "500", Layer.HTACCESS, ".htaccess:3"), a("max_file_uploads", "5", Layer.USER_INI, ".user.ini:1")]
    r = resolve("max_file_uploads", "20", stack)
    assert r.value == "20"
    assert len(r.notes) == 2


def test_htaccess_rejects_admin_directives():
    warnings = []
    values = parse_htaccess("php_admin_value memory_limit 64M\nphp_flag display_errors on\n", "/w/.htaccess", warnings)
    assert [(v.setting, v.value) for v in values] == [("display_errors", "1")]
    assert "not allowed in .htaccess" in warnings[0]


def test_htaccess_none_clears_value():
    [value] = parse_htaccess("php_value auto_prepend_file none\n", "/w/.htaccess", [])
    assert value.value == ""


# --- evaluate ---------------------------------------------------------------


def test_early_only_ignores_user_ini_but_reports_it(db):
    check = db.mitigations["session-upload-progress-off"]
    ctx = Context(
        "pool www",
        [a(check.setting, "", Layer.INI, "php.ini:9")],
        late=[[a(check.setting, "1", Layer.USER_INI, "/app/.user.ini:1")]],
    )
    result = evaluate(check, [ctx], check.php_default)
    assert result.satisfied is True
    assert any("after request startup" in n for n in result.notes)


def test_user_ini_disabling_does_not_count(db):
    check = db.mitigations["session-upload-progress-off"]
    ctx = Context("pool www", [], late=[[a(check.setting, "0", Layer.USER_INI, "/app/.user.ini:1")]])
    result = evaluate(check, [ctx], check.php_default)
    assert result.satisfied is False
    assert any("too late" in n for n in result.notes)


def test_prefer_admin_warns_when_overridable(db):
    check = db.mitigations["memory-limit-unlimited"]
    ctx = Context("php.ini", [a("memory_limit", "-1", Layer.INI, "php.ini:3")])
    result = evaluate(check, [ctx], check.php_default)
    assert result.satisfied is True
    assert any("ini_set()" in w for w in result.warnings)


def test_env_variable_value_is_undecidable(db):
    check = db.mitigations["memory-limit-unlimited"]
    ctx = Context("php.ini", [a("memory_limit", "${PHP_MEMORY}", Layer.INI)])
    result = evaluate(check, [ctx], check.php_default)
    assert result.satisfied is None
    assert "environment variable" in result.warnings[0]


def test_one_bad_context_fails_the_setting(db):
    check = db.mitigations["session-upload-progress-off"]
    good = Context("pool a", [a(check.setting, "", Layer.INI)])
    bad = Context("pool b", [a(check.setting, "", Layer.INI), a(check.setting, "1", Layer.POOL, "b.conf:3")])
    result = evaluate(check, [good, bad], check.php_default)
    assert result.satisfied is False
    assert [c.satisfied for c in result.contexts] == [True, False]
    assert result.contexts[1].origin == "b.conf:3"


def test_report_only_hardening_check():
    check = HardeningCheck("max-input-vars", "max_input_vars", "int", ())
    result = evaluate(check, [Context("php.ini", [])], "1000")
    assert result.contexts[0].value == "1000"
    assert result.satisfied is True


def test_cross_check_flags_disagreement():
    install = PhpInstall("/usr/bin/php", "cli", "8.3.6", ini_values={"memory_limit": "256M"})
    ini = [a("memory_limit", "128M", Layer.INI, "php.ini:3")]
    assert "PHP reports '256M'" in cross_check("memory_limit", "size", ini, "128M", install)
    install.ini_values["memory_limit"] = "128M"
    assert cross_check("memory_limit", "size", ini, "128M", install) is None


def test_cross_check_bool_spelling():
    install = PhpInstall("/usr/bin/php", "cli", "8.3.6", ini_values={"session.upload_progress.enabled": "Off"})
    ini = [a("session.upload_progress.enabled", "", Layer.INI)]
    assert cross_check("session.upload_progress.enabled", "bool", ini, "1", install) is None


# --- parsers on fixture trees -----------------------------------------------


def test_parse_fpm_pools_and_includes():
    fs = HostFileSystem(str(CONFIG / "debian-fpm"))
    result = ParseResult()
    pools = {p.name: p for p in parse_fpm(fs, "/etc/php/8.3/fpm/php-fpm.conf", result)}
    assert set(pools) == {"www", "legacy"}
    assert pools["www"].listen == "/run/php/php8.3-fpm.sock"
    admin = {v.setting: v.value for v in pools["www"].admin_values}
    assert admin == {"memory_limit": "-1", "post_max_size": "16M", "error_log": "/var/log/www.log"}  # $pool expanded
    assert pools["legacy"].values[1].value == ""  # php_flag off
    assert result.warnings == []


def test_parse_nginx_expands_includes_and_variables():
    fs = HostFileSystem(str(CONFIG / "debian-fpm"))
    web = load_web_config(fs)
    assert web.docroots == ["/var/www/a", "/var/www/b"]
    [import_override, legacy_override] = web.frontends
    assert [(x.setting, x.value) for x in import_override.assignments] == [
        ("memory_limit", "256M"),
        ("max_execution_time", "300"),
    ]
    assert import_override.targets == ["unix:/run/php/php8.3-fpm.sock"]
    assert legacy_override.targets == ["tcp:9001"]  # resolved through the upstream block
    assert legacy_override.assignments[0].admin
    assert any("fastcgi_params not found" in w for w in web.warnings)


def test_nginx_tokens_comments_and_escapes():
    fs = _MemoryFS({"/etc/nginx/nginx.conf": 'server { # comment ; {\n fastcgi_param PHP_VALUE "a=1\\nb=2"; }\n'})
    tree = parse_nginx(fs, "/etc/nginx/nginx.conf", ParseResult())
    [server] = tree
    [param] = server.children
    assert param.args == ["PHP_VALUE", "a=1\nb=2"]
    assert param.origin == "/etc/nginx/nginx.conf:2"


def test_parse_apache_contexts_and_continuations():
    fs = HostFileSystem(str(CONFIG / "apache-modphp"))
    web = load_web_config(fs)
    assert web.docroots == ["/var/www/site"]
    by_setting = {x.assignment.setting: x for x in web.apache}
    assert by_setting["memory_limit"].assignment.admin
    assert by_setting["memory_limit"].vhost is None
    assert by_setting["session.upload_progress.enabled"].vhost.startswith("<VirtualHost *:80>")
    assert by_setting["post_max_size"].assignment.value == "32M"  # joined continuation line
    assert by_setting["post_max_size"].directory == "/var/www/site"


class _MemoryFS:
    def __init__(self, files):
        self.files = files

    def read(self, path):
        return self.files.get(path)

    def glob(self, pattern):
        return [pattern] if pattern in self.files else []

    def find(self, roots, names):
        return []


# --- whole installs ---------------------------------------------------------


def fpm_install():
    return PhpInstall(
        binary="/usr/sbin/php-fpm8.3",
        sapi="fpm-fcgi",
        version="8.3.6",
        ini_files=["/etc/php/8.3/fpm/php.ini", "/etc/php/8.3/fpm/conf.d/10-opcache.ini", "/etc/php/8.3/fpm/conf.d/99-php2shell.ini"],
        ini_values={"session.upload_progress.enabled": "Off", "memory_limit": "128M"},
        fpm_config="/etc/php/8.3/fpm/php-fpm.conf",
    )


@pytest.fixture
def fpm_report(db):
    fs = HostFileSystem(str(CONFIG / "debian-fpm"))
    checks = [*db.mitigations.values(), *db.hardening]
    return check_install(fpm_install(), checks, fs, load_web_config(fs))


def contexts(result):
    return {c.context: (c.value, c.satisfied) for c in result.contexts}


def test_fpm_upload_progress_per_pool(fpm_report):
    result = fpm_report.results["session-upload-progress-off"]
    ctx = contexts(result)
    assert ctx["pool www"] == ("", True)  # conf.d/99 turned it off
    assert ctx["pool legacy"] == ("1", False)  # pool php_value turned it back on
    # PHP_ADMIN_VALUE from nginx b.conf targets the legacy pool and fixes it
    assert ctx["pool legacy after a request from /etc/nginx/sites-enabled/b.conf:6"] == ("0", True)
    assert ctx["php.ini [PATH=/var/www/b]"] == ("1", False)
    assert result.satisfied is False
    # the .user.ini re-enable is reported even though it cannot change the verdict
    assert any("/var/www/a/.user.ini:1" in n and "after request startup" in n for n in result.notes)


def test_fpm_memory_limit_frontend_breaks_the_lock(fpm_report):
    result = fpm_report.results["memory-limit-unlimited"]
    ctx = contexts(result)
    assert ctx["pool www"] == ("-1", True)
    assert ctx["pool www after a request from /etc/nginx/sites-enabled/a.conf:8"] == ("256M", False)
    assert ctx["pool legacy"] == ("128M", False)
    # the .user.ini 16M is blocked by the pool's php_admin_value
    assert any("/var/www/a/.user.ini:2: blocked by php_admin value" in n for n in result.notes)


def test_fpm_frontend_only_hits_matching_pool(fpm_report):
    names = fpm_report.contexts
    assert "pool legacy after a request from /etc/nginx/sites-enabled/a.conf:8" not in names
    assert "pool www after a request from /etc/nginx/sites-enabled/b.conf:6" not in names


def test_fpm_cross_check_is_clean(fpm_report):
    assert not any("PHP reports" in w for w in fpm_report.warnings)


def test_fpm_cross_check_catches_wrong_parse(db):
    fs = HostFileSystem(str(CONFIG / "debian-fpm"))
    install = fpm_install()
    install.ini_values["session.upload_progress.enabled"] = "On"
    report = check_install(install, [db.mitigations["session-upload-progress-off"]], fs, load_web_config(fs))
    assert any("PHP reports 'On'" in w for w in report.warnings)


def test_fpm_hardening_values(fpm_report):
    assert contexts(fpm_report.results["expose-php-off"])["pool legacy"] == ("", True)
    assert contexts(fpm_report.results["expose-php-off"])["pool www"] == ("1", False)


def modphp_install():
    return PhpInstall(
        binary="/usr/lib/apache2/modules/libphp8.3.so",
        sapi="apache2handler",
        version="8.3.6",
        ini_files=["/etc/php/8.3/apache2/php.ini"],
        enabled=True,
    )


@pytest.fixture
def modphp_report(db):
    fs = HostFileSystem(str(CONFIG / "apache-modphp"))
    checks = [*db.mitigations.values(), *db.hardening]
    return check_install(modphp_install(), checks, fs, load_web_config(fs))


def test_modphp_upload_progress(modphp_report):
    result = modphp_report.results["session-upload-progress-off"]
    ctx = contexts(result)
    assert ctx["Apache server config"] == ("1", False)  # outside the vhost: PHP default
    vhost = next(k for k in ctx if k.startswith("<VirtualHost *:80>") and "Directory" not in k)
    assert ctx[vhost] == ("", True)
    assert ctx[".htaccess in /var/www/site/blocked"] == ("", True)  # php_flag on is blocked
    assert any("blocked by php_admin value" in n for n in result.notes)


def test_modphp_memory_limit_server_admin_holds(modphp_report):
    result = modphp_report.results["memory-limit-unlimited"]
    assert all(c.value == "-1" and c.locked for c in result.contexts)
    assert result.satisfied is True
    assert not result.warnings  # set with php_admin_value: no ini_set() warning


def test_modphp_htaccess_raises_post_max_size(modphp_report):
    ctx = contexts(modphp_report.results["post-max-size-low"])
    assert ctx[".htaccess in /var/www/site/sub"] == ("512M", False)
    dir_ctx = next(k for k in ctx if "<Directory /var/www/site>" in k)
    assert ctx[dir_ctx] == ("32M", True)


def test_modphp_htaccess_admin_and_system_lines_reported(modphp_report):
    assert any("not allowed in .htaccess" in w for w in modphp_report.warnings)
    notes = modphp_report.results["max-file-uploads"].notes
    assert any("INI_SYSTEM" in n for n in notes)


def test_cli_has_one_context(db):
    fs = HostFileSystem(str(CONFIG / "debian-fpm"))
    install = PhpInstall("/usr/bin/php8.3", "cli", "8.3.6", ini_files=["/etc/php/8.3/fpm/php.ini"])
    report = check_install(install, [db.mitigations["session-upload-progress-off"]], fs, load_web_config(fs))
    assert report.contexts == ["php.ini"]


def test_unreadable_ini_is_a_warning(db, tmp_path):
    fs = HostFileSystem(str(tmp_path))
    install = PhpInstall("/usr/bin/php", "cli", "8.3.6", ini_files=["/etc/php.ini"])
    report = check_install(install, [db.mitigations["session-upload-progress-off"]], fs, load_web_config(fs))
    assert "/etc/php.ini: cannot read ini file" in report.warnings


def test_fpm_without_pools(db, tmp_path):
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/php-fpm.conf").write_text("[global]\ninclude=/etc/php-fpm.d/*.conf\n")
    fs = HostFileSystem(str(tmp_path))
    install = PhpInstall("/usr/sbin/php-fpm", "fpm-fcgi", "8.0.30", fpm_config="/etc/php-fpm.conf")
    report = check_install(install, [db.mitigations["session-upload-progress-off"]], fs, load_web_config(fs))
    assert report.contexts == ["php.ini (no pools found)"]
    assert any("matches no files" in w for w in report.warnings)


def test_find_respects_file_limit(tmp_path):
    for i in range(30):
        d = tmp_path / "www" / f"d{i}"
        d.mkdir(parents=True)
        (d / ".htaccess").write_text("")
    fs = HostFileSystem(str(tmp_path), max_files=10)
    fs.find(["/www"], {".htaccess"})
    assert any("stopped scanning" in w for w in fs.warnings)


def test_expectation_type_is_used():
    # A size check must compare bytes, not strings.
    check = HardeningCheck("x", "post_max_size", "size", (), Expectation("lte", "32M"))
    assert evaluate(check, [Context("c", [a("post_max_size", "33554432", Layer.INI)])], "8M").satisfied is True
