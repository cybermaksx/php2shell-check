# php2shell-check

Audit a Linux server for exposure to the PHP2Shell vulnerabilities,
CVE-2026-109618 and CVE-2026-109619, and optionally apply the official
interim mitigations.

It finds every PHP install on the host, decides from the package version
whether the distribution has already shipped the fix, and works out the
effective value of each mitigation setting in every FPM pool, vhost and
directory. Each value in the report points to the `file:line` that set it.

Author: Magsud Huseynli ([cybermaksx](https://github.com/cybermaksx)), <cybermaksx@proton.me>

## Safety

- **Defensive only.** It does not send requests, probe for the bug or
  attempt exploitation in any form. It contains no exploit code.
- **Read-only by default.** It runs PHP binaries with `-i` / `-v`, asks
  `dpkg-query` or `rpm` who owns a file, and reads configuration files.
- **It changes nothing unless you pass `--fix`.** Then it shows a diff,
  asks before writing (unless `--yes`), backs up every file, validates the
  result with `php-fpm -t` / `apachectl -t`, and rolls everything back if
  any step fails.

## What it does not do

- It does not install, upgrade or downgrade packages. The only real fix is
  an updated PHP; `--fix` only applies interim mitigations.
- It does not edit nginx or Apache configuration, `.htaccess`, `.user.ini`
  or `[PATH=]` / `[HOST=]` sections. Problems there are listed as manual
  steps with their `file:line`.
- It does not start services that were not running.
- It does not see `ini_set()` calls inside application code.
- It does not query PHP-FPM over FastCGI to read live values. The effective
  value is worked out from configuration files, and cross-checked against
  `php -i` for the php.ini layer.

## Requirements

Python 3.10 or newer, standard library only. Linux with dpkg or rpm.
Run as root for a complete picture: as a normal user, some configuration and
package data may be unreadable, and the report says so.

## Usage

```sh
# from a checkout
sudo python3 -m php2shell_check

# or installed
pip install .
sudo php2shell-check
```

| Option | |
|---|---|
| `--json` | JSON report for automation |
| `-v`, `--verbose` | also show hardening values, aliases and skipped files |
| `--scan-dir DIR` | also look for `.htaccess` / `.user.ini` under `DIR` (repeatable) |
| `--max-files N` | stop walking web roots after `N` entries (default 200000) |
| `--advisories FILE` | use another advisory data file |
| `--fix` | apply the interim mitigations to PHP configuration |
| `--fix --dry-run` | show the plan and the diff, change nothing |
| `--fix --yes` | do not ask for confirmation |
| `--fix --only ID` | apply only one mitigation, e.g. `session-upload-progress-off` |
| `--fix --no-restart` | do not restart services; restart them yourself |
| `--fix --backup-dir DIR` | where backups go (default `/var/backups/php2shell-check`) |

### Status per install

| Status | Meaning |
|---|---|
| `PATCHED` | The distribution package is at or above its fixed version, or the upstream PHP version is a fixed release. |
| `VULNERABLE` | The distribution has published a fix and the installed package is older. |
| `EOL` | The PHP branch is end-of-life upstream and nothing shows a fix. |
| `UNKNOWN` | Below the fixed release, but there is no advisory data for this distribution or package, so a backport cannot be ruled out. |

For anything not `PATCHED`, the mitigations are checked:

| Mitigation | Meaning |
|---|---|
| `MITIGATED` | Every mitigation that applies is in place in every context. |
| `PARTIAL` | Some are. |
| `EXPOSED` | None are. |

`MITIGATED` is not `PATCHED`. The mitigations block specific attack paths;
only an updated PHP fixes the bugs.

### Exit codes

| Code | |
|---|---|
| 0 | every web-facing install is patched or mitigated |
| 1 | an install is `VULNERABLE`, or its mitigations are `EXPOSED` |
| 2 | an `EOL` install without full mitigation |
| 3 | an `UNKNOWN` install without full mitigation |
| 4 | runtime error, or `--fix` failed and was rolled back |

CLI binaries are reported with their status but do not affect the exit
code: the advisories cover installs that serve web requests, and a CLI
binary cannot be mitigated.

### Example

PHP 8.3.20 from the official Docker image:

```
SAPI      BINARY                   VERSION  PACKAGE  STATUS   MITIGATION
--------  -----------------------  -------  -------  -------  ----------
cli       /usr/local/bin/php       8.3.20   -        UNKNOWN  -
fpm-fcgi  /usr/local/sbin/php-fpm  8.3.20   -        UNKNOWN  PARTIAL

fpm-fcgi /usr/local/sbin/php-fpm: UNKNOWN
  CVE-2026-109618: UNKNOWN - PHP 8.3.20 < 8.3.36, but not owned by a package (source build?); a manual patch cannot be detected
  CVE-2026-109619: UNKNOWN - PHP 8.3.20 < 8.3.36, but not owned by a package (source build?); a manual patch cannot be detected
  mitigations: PARTIAL
    [NOT SET] memory_limit  (memory-limit-unlimited)
        pool www: '128M' from PHP default
    [ok] post_max_size  (post-max-size-low)
    [NOT SET] session.upload_progress.enabled  (session-upload-progress-off)
        pool www: '1' from PHP default
```

## How it decides

**Version.** Distributions backport fixes without changing the upstream
version: Ubuntu 24.04's `php -v` reports 8.3.6, yet package
`8.3.6-0ubuntu0.24.04.13` is patched. A version-only check would get this
wrong, so the package version decides whenever there is advisory data for
the distribution:

1. A row for the host's os-release `ID`, `VERSION_ID` and the source
   package decides alone. dpkg and rpm versions are compared by pure-Python
   ports of dpkg's `verrevcmp()` and rpm's `rpmvercmp()`, tested against
   the real tools.
2. Without a row, a PHP version at or above the fixed release is `PATCHED`.
3. Without a row and below the fixed release: `EOL` if the branch is
   end-of-life, otherwise `UNKNOWN`.

`ID_LIKE` is never used: a Rocky or AlmaLinux host does not inherit RHEL's
rows, because their package versions are not guaranteed to match.

**Configuration.** PHP settings are resolved per context, lowest layer
first:

```
php.ini, conf.d/*.ini           last one wins
php.ini [PATH=] / [HOST=]        CGI/FPM only
FPM pool php_value, php_admin_*  admin locks the value
web server PHP_VALUE / PHP_ADMIN_VALUE
                                 overrides even a pool php_admin_value
Apache php_value, php_admin_*    admin locks the value
.htaccess php_value / php_flag   blocked by a lock
--- request startup ---
.user.ini                        blocked by a lock; too late to count as a mitigation
```

Two of these rules were measured on PHP-FPM 8.3 rather than taken from
the documentation: `PHP_VALUE` sent by nginx overrides a pool's
`php_admin_value`, and the new value stays on that worker for later
requests. A `PHP_VALUE` in any nginx location therefore affects the whole
pool it points to.

A setting counts as in place only if it holds in every context. Overrides
that switch a setting back on are reported with their location, including
`.user.ini` lines that cannot change the result.

## The mitigations

From the PHP advisories, php.net and Red Hat's RHSB-2026-013. None of them
makes an install safe.

| Setting | For | Notes |
|---|---|---|
| `session.upload_progress.enabled = 0` | CVE-2026-109619, CVE-2026-115560 | Blocks the confirmed session paths. Breaks native upload-progress reporting. |
| `fatal_error_backtraces = 0` | CVE-2026-109619 | PHP 8.5 only. Blocks the confirmed fatal backtrace path. |
| `memory_limit = -1` | CVE-2026-109618 | Removes the PHP memory limit failure that the attack relies on. Set it with `php_admin_value`, and limit memory with a container or cgroup instead; never `RLIMIT_AS` or `RLIMIT_DATA`. |
| `post_max_size <= 32M` | CVE-2026-109618 | 8M without file uploads, 32M with. Also limit request size at the web server, including requests without a usable `Content-Length`. |

All four must be set before request parsing: php.ini, an FPM pool or server
configuration. `ini_set()` and `.user.ini` do not count. Restart every
worker afterwards; a reload is not enough.

`--fix` writes values that come from php.ini into one drop-in,
`conf.d/99-php2shell-check.ini`, and adds `php_admin_value` /
`php_admin_flag` lines to failing FPM pools. Every line it adds is marked
with a dated comment. Remove them after updating PHP.

## Limitations

- **Backports without advisory data.** Distributions not in
  `advisories.json` come out `UNKNOWN` until a row is added. That includes
  RHEL 8/9/10, AlmaLinux, Rocky (Red Hat had not published fixed package
  versions at the time of writing) and third-party repositories such as Remi
  and deb.sury.org.
- **Source builds** below the fixed release are `UNKNOWN`, not
  `VULNERABLE`: a hand-applied patch, such as the PHP team's minimal
  backports for 7.4, 8.0 and 8.1, cannot be detected.
- **Unconfirmed facts.** The oldest affected version (5.4) comes only from
  secondary sources and is marked `unconfirmed` in the data. It is not used
  in any verdict. CVE-2026-115560 has no published versions yet: it never
  changes a status or exit code, but the report mentions its mitigation on
  hosts where it is missing.
- **Partial configuration coverage.** `AllowOverride` is not evaluated (a
  `.htaccess` is assumed to apply). Apache `<Directory>` blocks with
  wildcards are not matched against `.htaccess` paths. Values that use
  `${VAR}` cannot be decided. LiteSpeed's `.htaccess` handling is assumed to
  match mod_php's, unverified.
- **mod_php** cannot be run, so its version comes from the owning package
  and its ini files from the distribution's layout.
- **FrankenPHP** gets a version check only; its ini files are not
  discovered.
- **systemd units** passing `-c` or `PHP_INI_SCAN_DIR` to PHP-FPM are not
  read; the configuration found on disk is assumed.

## Updating advisories.json

All vulnerability facts live in `data/advisories.json`. The code contains
none, so filling in new data needs no code change.

- Every fact lists `sources`, which are ids from the `sources` table at the
  top of the file.
- Anything not confirmed by an official source gets
  `"status": "unconfirmed"` and a note containing `TODO`.
- A distribution fix is a row with `os_id` and `version_id` from
  `/etc/os-release`, the **source** package name, the version scheme and the
  fixed version, as published by the distribution:

  ```json
  { "os_id": "debian", "version_id": "12", "scheme": "dpkg",
    "source_package": "php8.2", "fixed": "8.2.35-1~deb12u1",
    "advisory": "DLA-4848-1", "sources": ["debian-109618"] }
  ```

  A row for `"9"` matches hosts reporting `9.4`; a row for `"9.4"` matches
  only `9.4`. Use `"not_affected": true` instead of `fixed` when the vendor
  states it is not affected.
- When PHP publishes details for CVE-2026-115560, fill in `upstream.fixed`
  and `distros` on its entry and set `status` to `confirmed`.

The loader is strict. Unknown keys, unknown source ids, versions that do
not parse, or a fixed version on the wrong branch all stop the tool with
every error listed, so a typo cannot silently change a verdict.

## Development

```sh
python3 -m venv .venv && .venv/bin/pip install pytest
.venv/bin/python -m pytest -q
```

The version comparison tests also run against the real `dpkg` and `rpm`
when they are installed, and are skipped otherwise.

### Docker lab

`docker/lab.sh` builds each scenario in `docker/scenarios/`, runs the tool,
and checks the result against that scenario's `expect` file:

| Scenario | Image | Expected |
|---|---|---|
| `upstream-old` | `php:8.3.20-fpm` | `UNKNOWN`, exit 3 |
| `upstream-patched` | `php:8.4.27-fpm` | `PATCHED`, exit 0 |
| `ubuntu-backport` | Ubuntu 24.04, php8.3 | `PATCHED` (php -v says 8.3.6), exit 0 |
| `eol-8.1` | `php:8.1.33-fpm` | `EOL`, exit 2 |
| `eol-8.1-fixed` | same, after `--fix --yes` | `EOL` and `MITIGATED`, exit 0 |
| `oracle-dpkg`, `oracle-rpm` | Debian, Fedora | version comparison matches the real tools |

```sh
docker/lab.sh                  # everything
docker/lab.sh ubuntu-backport  # one scenario
```

## Sources

Primary:

- [GHSA-w8hw-w9fx-j79w / CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [GHSA-6wmf-4rv5-p3rp / CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- [php.net security announcements, October 2026](https://www.php.net/archive/2026.php#2026-10-20-1)
- [PHP Foundation: today's PHP security release](https://thephp.foundation/blog/2026/10/21/todays-php-security-release-and-how-were-strengthening-php-security/)
- [Ubuntu USN-8948-1](https://ubuntu.com/security/notices/USN-8948-1)
- [Debian tracker: CVE-2026-109618](https://security-tracker.debian.org/tracker/CVE-2026-109618), [CVE-2026-109619](https://security-tracker.debian.org/tracker/CVE-2026-109619)
- [Red Hat RHSB-2026-013](https://access.redhat.com/security/vulnerabilities/RHSB-2026-013)

Secondary (cross-checks only):

- [CERT-EU 2026-018](https://cert.europa.eu/publications/security-advisories/2026-018)
- [CISA alert](https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching)
- [SANS ISC diary](https://isc.sans.edu/diary.html?storyid=44534)
- [Wiz research](https://www.wiz.io/blog/php2shell-php-rce)
- [watchTowr FAQ](https://watchtowr.com/intelligence/php-cve-2026-109618-faq/)

## License

MIT. See [LICENSE](LICENSE).
