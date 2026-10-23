# Ubuntu 24.04: php -v says 8.3.6, far below 8.3.36, but the package
# 8.3.6-0ubuntu0.24.04.13 carries the fix (USN-8948-1). A version-only check
# would call this vulnerable; the tool must say PATCHED.
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends php8.3-cli php8.3-fpm libapache2-mod-php8.3 python3 >/dev/null && rm -rf /var/lib/apt/lists/*
COPY . /opt/php2shell-check
WORKDIR /opt/php2shell-check
CMD ["python3", "-m", "php2shell_check", "--json"]
