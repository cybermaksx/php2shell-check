from php2shell_check.models import Advisory, DistroFix, InstallStatus, UpstreamFix


def test_placeholder_advisory_has_no_version_data():
    placeholder = Advisory(
        id="CVE-2026-115560",
        title="placeholder",
        published="2026-10-23",
        status="unconfirmed",
        sources=("php-net",),
    )
    assert not placeholder.has_version_data


def test_advisory_with_upstream_fix_has_version_data():
    adv = Advisory(
        id="CVE-2026-109618",
        title="RCE via OOM corruption",
        published="2026-10-21",
        status="confirmed",
        sources=("ghsa-w8hw",),
        upstream_fixed=(UpstreamFix("8.5", "8.5.12", ("ghsa-w8hw",)),),
    )
    assert adv.has_version_data


def test_advisory_with_only_distro_rows_has_version_data():
    adv = Advisory(
        id="CVE-X",
        title="t",
        published="2026-10-21",
        status="confirmed",
        sources=("s",),
        distros=(DistroFix("rhel", "7", "rpm", "php", ("s",), not_affected=True),),
    )
    assert adv.has_version_data


def test_status_enums_serialise_as_plain_strings():
    assert InstallStatus.UNKNOWN == "UNKNOWN"
    assert InstallStatus("PATCHED") is InstallStatus.PATCHED
