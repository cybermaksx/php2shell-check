# Compare version.py with the real dpkg --compare-versions.
FROM debian:trixie-slim
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends python3-pytest >/dev/null && rm -rf /var/lib/apt/lists/*
COPY . /opt/php2shell-check
WORKDIR /opt/php2shell-check
CMD ["python3", "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests/test_version.py", "-k", "matches_real"]
