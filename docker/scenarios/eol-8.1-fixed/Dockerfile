# The same EOL 8.1 after `--fix --yes`: still EOL, but every mitigation is in
# place, so the exit code is 0. There is no systemd in the container, hence
# --no-restart.
FROM php:8.1.33-fpm
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends python3 >/dev/null && rm -rf /var/lib/apt/lists/*
COPY . /opt/php2shell-check
WORKDIR /opt/php2shell-check
CMD ["sh", "-c", "python3 -m php2shell_check --fix --yes --no-restart >/tmp/fix.log 2>&1 || { cat /tmp/fix.log >&2; exit 4; }; python3 -m php2shell_check --json"]
