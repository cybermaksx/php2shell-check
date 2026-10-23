import pytest

from php2shell_check.distro import (
    CommandError,
    CommandResult,
    candidate_paths,
    distro_from_fields,
    lookup_package,
    manager_order,
    parse_dpkg_search,
    parse_dpkg_show,
    parse_os_release,
    parse_rpm_query,
    read_distro,
    source_name_from_srpm,
)
from php2shell_check.models import Distro, Package

# --- os-release -------------------------------------------------------------


@pytest.mark.parametrize(
    "name, os_id, version_id, id_like",
    [
        ("ubuntu-24.04", "ubuntu", "24.04", ("debian",)),
        ("debian-12", "debian", "12", ()),
        ("debian-sid", "debian", "", ()),
        ("rhel-7.9", "rhel", "7.9", ("fedora",)),
        ("rocky-9.4", "rocky", "9.4", ("rhel", "centos", "fedora")),
        ("arch", "arch", "", ()),
    ],
)
def test_os_release_fixtures(fixture_text, name, os_id, version_id, id_like):
    distro = distro_from_fields(parse_os_release(fixture_text("os-release", name)))
    assert (distro.os_id, distro.version_id, distro.id_like) == (os_id, version_id, id_like)


def test_os_release_quoting(fixture_text):
    fields = parse_os_release(fixture_text("os-release", "quoted"))
    assert fields["ID"] == "weird"
    assert fields["PRETTY_NAME"] == 'Has "escaped" quotes and a $dollar'
    assert "BROKEN" not in fields  # unbalanced quote: line skipped
    assert "# comment line" not in fields


def test_distro_without_id():
    assert distro_from_fields({"NAME": "x"}) is None


def test_read_distro_falls_back_and_warns(tmp_path, fixture_text):
    missing = tmp_path / "missing"
    sid = tmp_path / "os-release"
    sid.write_text(fixture_text("os-release", "debian-sid"))
    distro, warnings = read_distro([missing, sid])
    assert distro.os_id == "debian"
    assert any("no VERSION_ID" in w for w in warnings)


def test_read_distro_none_found(tmp_path):
    distro, warnings = read_distro([tmp_path / "a", tmp_path / "b"])
    assert distro is None
    assert warnings == ["no os-release file found; distribution unknown"]


def test_read_distro_unreadable(tmp_path):
    unreadable = tmp_path / "os-release"
    unreadable.mkdir()  # reading a directory raises IsADirectoryError
    distro, warnings = read_distro([unreadable])
    assert distro is None
    assert any("cannot read" in w for w in warnings)


# --- dpkg / rpm output parsing ----------------------------------------------


def test_parse_dpkg_search(fixture_text):
    assert parse_dpkg_search(fixture_text("packages", "dpkg-S-php8.3-cli.txt")) == ["php8.3-cli"]


def test_parse_dpkg_search_skips_diversions(fixture_text):
    assert parse_dpkg_search(fixture_text("packages", "dpkg-S-diverted.txt")) == ["php8.3-cli:amd64"]


def test_parse_dpkg_search_several_owners():
    assert parse_dpkg_search("pkg-a, pkg-b: /usr/bin/x\n") == ["pkg-a", "pkg-b"]


def test_parse_dpkg_show(fixture_text):
    assert parse_dpkg_show(fixture_text("packages", "dpkg-W-php8.3-cli.txt")) == Package(
        "php8.3-cli", "8.3.6-0ubuntu0.24.04.13", "php8.3", "dpkg"
    )


def test_parse_dpkg_show_binnmu_source_with_version(fixture_text):
    package = parse_dpkg_show(fixture_text("packages", "dpkg-W-binnmu.txt"))
    assert package.source_name == "php8.2"
    assert package.version == "8.2.35-1~deb12u1+b1"  # binary version kept


def test_parse_dpkg_show_empty_source_means_same_name(fixture_text):
    package = parse_dpkg_show(fixture_text("packages", "dpkg-W-no-source.txt"))
    assert package.source_name == "php-common"
    assert package.version == "2:93"


@pytest.mark.parametrize("output", ["", "garbage", "a\tb\n"])
def test_parse_dpkg_show_rejects(output):
    assert parse_dpkg_show(output) is None


@pytest.mark.parametrize(
    "name, expected",
    [
        ("rpm-qf-el9.txt", Package("php-cli", "8.0.30-1.el9_4", "php", "rpm")),
        ("rpm-qf-remi.txt", Package("php-cli", "8.4.27-1.el9.remi", "php", "rpm")),
        ("rpm-qf-epoch.txt", Package("php-cli", "1:5.4.16-48.el7", "php", "rpm")),
        ("rpm-qf-scl.txt", Package("php82-php-cli", "8.2.13-1.el9.remi", "php82-php", "rpm")),
    ],
)
def test_parse_rpm_query(fixture_text, name, expected):
    assert parse_rpm_query(fixture_text("packages", name)) == [expected]


@pytest.mark.parametrize(
    "srpm, expected",
    [
        ("php-8.3.19-1.el10_0.src.rpm", "php"),
        ("php82-php-8.2.13-1.el9.remi.src.rpm", "php82-php"),
        ("ea-php83-8.3.36-1.1.1.cpanel.src.rpm", "ea-php83"),
        ("(none)", None),
        ("weird.src.rpm", None),
    ],
)
def test_source_name_from_srpm(srpm, expected):
    assert source_name_from_srpm(srpm) == expected


# --- lookup with a fake runner ----------------------------------------------


class FakeRunner:
    """Answers commands from a dict keyed by argv; records every call."""

    def __init__(self, answers):
        self.answers = answers
        self.calls = []

    def __call__(self, argv):
        argv = tuple(argv)
        self.calls.append(argv)
        answer = self.answers.get(argv)
        if isinstance(answer, Exception):
            raise answer
        if answer is None:
            raise AssertionError(f"unexpected command: {argv}")
        rc, out, err = answer
        return CommandResult(argv, rc, out, err)


DPKG_SHOW = ("dpkg-query", "-W", "-f=${Package}\\t${Version}\\t${Source}\\n")
RPM_QF = ("rpm", "-qf", "--qf", "%{NAME}\\t%{EPOCH}\\t%{VERSION}\\t%{RELEASE}\\t%{SOURCERPM}\\n")
UBUNTU = Distro("ubuntu", "24.04", ("debian",))
RHEL = Distro("rhel", "9.4", ("fedora",))


def only(*available):
    return lambda name: f"/usr/bin/{name}" if name in available else None


def test_lookup_dpkg(fixture_text):
    run = FakeRunner(
        {
            ("dpkg-query", "-S", "/usr/bin/php8.3"): (0, fixture_text("packages", "dpkg-S-php8.3-cli.txt"), ""),
            (*DPKG_SHOW, "php8.3-cli"): (0, fixture_text("packages", "dpkg-W-php8.3-cli.txt"), ""),
        }
    )
    package, warnings = lookup_package("/usr/bin/php8.3", UBUNTU, run=run, which=only("dpkg-query"))
    assert package.source_name == "php8.3"
    assert warnings == []


def test_lookup_rpm(fixture_text):
    run = FakeRunner({(*RPM_QF, "/usr/bin/php"): (0, fixture_text("packages", "rpm-qf-el9.txt"), "")})
    package, warnings = lookup_package("/usr/bin/php", RHEL, run=run, which=only("rpm"))
    assert package.version == "8.0.30-1.el9_4"
    assert warnings == []


def test_lookup_unowned_is_not_a_warning():
    run = FakeRunner(
        {
            ("dpkg-query", "-S", "/usr/local/bin/php"): (
                1,
                "",
                "dpkg-query: no path found matching pattern /usr/local/bin/php\n",
            )
        }
    )
    package, warnings = lookup_package("/usr/local/bin/php", UBUNTU, run=run, which=only("dpkg-query"))
    assert package is None
    assert warnings == []


def test_lookup_rpm_unowned():
    run = FakeRunner({(*RPM_QF, "/opt/php/bin/php"): (1, "file /opt/php/bin/php is not owned by any package\n", "")})
    package, warnings = lookup_package("/opt/php/bin/php", RHEL, run=run, which=only("rpm"))
    assert (package, warnings) == (None, [])


def test_lookup_failure_is_a_warning():
    run = FakeRunner({("dpkg-query", "-S", "/usr/bin/php"): (2, "", "dpkg-query: error: database is locked\n")})
    package, warnings = lookup_package("/usr/bin/php", UBUNTU, run=run, which=only("dpkg-query"))
    assert package is None
    assert warnings == ["dpkg-query -S /usr/bin/php exited 2: dpkg-query: error: database is locked"]


def test_lookup_command_error_is_a_warning():
    run = FakeRunner({(*RPM_QF, "/usr/bin/php"): CommandError("rpm -qf ...: timed out after 15s")})
    package, warnings = lookup_package("/usr/bin/php", RHEL, run=run, which=only("rpm"))
    assert package is None
    assert warnings == ["rpm -qf ...: timed out after 15s"]


def test_lookup_no_package_manager():
    package, warnings = lookup_package("/usr/bin/php", None, run=FakeRunner({}), which=only())
    assert package is None
    assert "neither dpkg-query nor rpm" in warnings[0]


def test_lookup_falls_through_to_second_manager(fixture_text):
    # rpm exists on this Debian box but owns nothing; dpkg answers.
    run = FakeRunner(
        {
            ("dpkg-query", "-S", "/usr/bin/php8.3"): (0, fixture_text("packages", "dpkg-S-php8.3-cli.txt"), ""),
            (*DPKG_SHOW, "php8.3-cli"): (0, fixture_text("packages", "dpkg-W-php8.3-cli.txt"), ""),
        }
    )
    package, _ = lookup_package("/usr/bin/php8.3", UBUNTU, run=run, which=only("dpkg-query", "rpm"))
    assert package.manager == "dpkg"
    assert run.calls[0][0] == "dpkg-query"  # debian family asks dpkg first


def test_lookup_warns_on_several_owners(fixture_text):
    run = FakeRunner(
        {
            ("dpkg-query", "-S", "/usr/bin/x"): (0, "pkg-a, pkg-b: /usr/bin/x\n", ""),
            (*DPKG_SHOW, "pkg-a"): (0, "pkg-a\t1.0\t\n", ""),
        }
    )
    package, warnings = lookup_package("/usr/bin/x", UBUNTU, run=run, which=only("dpkg-query"))
    assert package.name == "pkg-a"
    assert "several packages" in warnings[0]


def test_lookup_tries_resolved_path_then_original(tmp_path, fixture_text):
    real = tmp_path / "php8.3"
    real.write_text("")
    link = tmp_path / "php"
    link.symlink_to(real)
    run = FakeRunner(
        {
            ("dpkg-query", "-S", str(real)): (1, "", "dpkg-query: no path found matching pattern\n"),
            ("dpkg-query", "-S", str(link)): (0, f"php8.3-cli: {link}\n", ""),
            (*DPKG_SHOW, "php8.3-cli"): (0, fixture_text("packages", "dpkg-W-php8.3-cli.txt"), ""),
        }
    )
    package, _ = lookup_package(str(link), UBUNTU, run=run, which=only("dpkg-query"))
    assert package.name == "php8.3-cli"
    assert [c[2] for c in run.calls[:2]] == [str(real), str(link)]


def test_candidate_paths_plain_file(tmp_path):
    f = tmp_path / "php"
    f.write_text("")
    assert candidate_paths(str(f)) == [str(f)]


@pytest.mark.parametrize(
    "distro, expected",
    [
        (UBUNTU, ["dpkg", "rpm"]),
        (RHEL, ["rpm", "dpkg"]),
        (Distro("rocky", "9.4", ("rhel", "centos", "fedora")), ["rpm", "dpkg"]),
        (Distro("arch", ""), ["dpkg", "rpm"]),
        (None, ["dpkg", "rpm"]),
    ],
)
def test_manager_order(distro, expected):
    assert manager_order(distro) == expected
