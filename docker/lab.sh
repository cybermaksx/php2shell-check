#!/bin/sh
# Build every scenario in docker/scenarios, run it, and compare the result
# with its `expect` file. Usage: docker/lab.sh [scenario ...]
#
# expect lines:
#   exit=N                      exit code of the container
#   <sapi>=<STATUS>             status of the first install with that SAPI
#   <sapi>.mitigation=<STATUS>  its mitigation status
#   <sapi>!~<text>              <text> must not appear in that install's report
set -u

cd "$(dirname "$0")/.." || exit 1
scenarios=${*:-$(ls docker/scenarios)}
failed=0

for name in $scenarios; do
    dir=docker/scenarios/$name
    tag=php2shell-check-lab:$name
    printf '%-18s ' "$name"
    if ! docker build -q -f "$dir/Dockerfile" -t "$tag" . >/dev/null 2>"/tmp/lab-$name.build"; then
        echo "BUILD FAILED (see /tmp/lab-$name.build)"
        failed=1
        continue
    fi
    docker run --rm "$tag" >"/tmp/lab-$name.out" 2>"/tmp/lab-$name.err"
    code=$?

    problems=$(python3 - "$dir/expect" "/tmp/lab-$name.out" "$code" <<'PY'
import json, sys
expect_file, out_file, code = sys.argv[1], sys.argv[2], int(sys.argv[3])
lines = [line.strip() for line in open(expect_file) if line.strip()]
absent = [line.split("!~", 1) for line in lines if "!~" in line]
expected = dict(line.split("=", 1) for line in lines if "!~" not in line and "=" in line)
problems = []
if int(expected.pop("exit")) != code:
    problems.append(f"exit {code}")
if expected:
    try:
        installs = json.load(open(out_file))["installs"]
    except ValueError:
        installs = []
        problems.append("no JSON output")
    for key, want in expected.items():
        sapi, _, field = key.partition(".")
        found = next((i for i in installs if i["sapi"] == sapi), None)
        got = (found or {}).get(field or "status")
        if got != want:
            problems.append(f"{key}={got}")
    for sapi, text in absent:
        found = next((i for i in installs if i["sapi"] == sapi), None)
        if found is not None and text in json.dumps(found):
            problems.append(f"{sapi} report contains {text!r}")
print(", ".join(problems))
PY
)
    if [ -z "$problems" ]; then
        echo "ok   (exit $code)"
    else
        echo "FAIL ($problems; output in /tmp/lab-$name.out)"
        failed=1
    fi
done
exit $failed
