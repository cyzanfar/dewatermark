#!/usr/bin/env sh
set -eu

# Reproducible, opt-in client generation. The OpenAPI document intentionally
# declares no default server, so generated clients cannot select a remote host
# without an application supplying one explicitly.
ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OUTPUT_DIR=${1:-"$ROOT_DIR/generated-clients"}
GENERATOR_IMAGE="openapitools/openapi-generator-cli@sha256:509f01c3c7eee9d1ad286506a7b6aa4624a95b410be9a238a306d209e900621f"

python "$ROOT_DIR/scripts/export_openapi.py" --check
if [ -L "$OUTPUT_DIR" ]; then
  printf '%s\n' "Refusing a symbolic-link output directory." >&2
  exit 2
fi
mkdir -p "$OUTPUT_DIR"
if find "$OUTPUT_DIR" -mindepth 1 -print -quit | grep -q .; then
  printf '%s\n' "Output directory must be empty: $OUTPUT_DIR" >&2
  exit 2
fi
OUTPUT_DIR=$(CDPATH= cd -- "$OUTPUT_DIR" && pwd)
mkdir -p "$OUTPUT_DIR/python" "$OUTPUT_DIR/typescript"

docker run --rm \
  -v "$ROOT_DIR:/workspace:ro" \
  -v "$OUTPUT_DIR:/output" \
  "$GENERATOR_IMAGE" generate \
  -i /workspace/schemas/openapi-v1.json \
  -g python \
  -o /output/python \
  --additional-properties=packageName=dewatermark_client,projectName=dewatermark-client

docker run --rm \
  -v "$ROOT_DIR:/workspace:ro" \
  -v "$OUTPUT_DIR:/output" \
  "$GENERATOR_IMAGE" generate \
  -i /workspace/schemas/openapi-v1.json \
  -g typescript-fetch \
  -o /output/typescript \
  --additional-properties=npmName=@cyzanfar/dewatermark-client,supportsES6=true,typescriptThreePlus=true

printf '%s\n' "Generated clients in $OUTPUT_DIR; review before publishing."
