#!/usr/bin/env bash
set -euo pipefail

image="${1:-r1db:local}"

version="$(docker run --rm --entrypoint /cockroach/cockroach "${image}" version)"
grep -q "Build Tag:        v23.1.28" <<< "${version}"
grep -q "Distribution:     OSS" <<< "${version}"
docker run --rm --entrypoint /usr/local/bin/cloudflared "${image}" version >/dev/null

echo "smoke ok"
