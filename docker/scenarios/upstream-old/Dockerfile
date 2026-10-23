# Upstream PHP 8.3.20 built from source (the official image): below the fixed
# 8.3.36 and not owned by any package. The tool must say UNKNOWN, not
# VULNERABLE, because a hand-applied patch cannot be ruled out.
FROM php:8.3.20-fpm
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends python3 >/dev/null && rm -rf /var/lib/apt/lists/*
COPY . /opt/php2shell-check
WORKDIR /opt/php2shell-check
CMD ["python3", "-m", "php2shell_check", "--json"]
