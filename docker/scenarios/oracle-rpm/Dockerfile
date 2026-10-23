# Compare version.py with the real rpm vercmp.
FROM fedora:43
RUN dnf -q -y install python3-pytest && dnf clean all
COPY . /opt/php2shell-check
WORKDIR /opt/php2shell-check
CMD ["python3", "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests/test_version.py", "-k", "matches_real"]
