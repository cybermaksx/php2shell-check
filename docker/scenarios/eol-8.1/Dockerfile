# Upstream PHP 8.1 (end-of-life, no official fix), stock configuration.
FROM php:8.1.33-fpm
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends python3 >/dev/null && rm -rf /var/lib/apt/lists/*
COPY . /opt/php2shell-check
WORKDIR /opt/php2shell-check
CMD ["python3", "-m", "php2shell_check", "--json"]
