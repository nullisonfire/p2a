#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   export R2_BUCKET=p2a-cache
#   export R2_ACCOUNT_ID=...
#   export AWS_ACCESS_KEY_ID=...
#   export AWS_SECRET_ACCESS_KEY=...
#   ./scripts/upload-r2.sh /path/to/cpanel/project/cache /path/to/cpanel/project/purchased_course.json

: "${R2_BUCKET:?Set R2_BUCKET}"
: "${R2_ACCOUNT_ID:?Set R2_ACCOUNT_ID}"
: "${AWS_ACCESS_KEY_ID:?Set AWS_ACCESS_KEY_ID}"
: "${AWS_SECRET_ACCESS_KEY:?Set AWS_SECRET_ACCESS_KEY}"

CACHE_DIR="${1:?First argument must be the old cache directory}"
PURCHASED_FILE="${2:-}"
ENDPOINT="https://${R2_ACCOUNT_ID}.r2.cloudflarestorage.com"

aws s3 sync "$CACHE_DIR" "s3://${R2_BUCKET}" --endpoint-url "$ENDPOINT" --no-progress

if [[ -n "$PURCHASED_FILE" && -f "$PURCHASED_FILE" ]]; then
  aws s3 cp "$PURCHASED_FILE" "s3://${R2_BUCKET}/state/purchased_course.json" --endpoint-url "$ENDPOINT"
fi

echo "R2 cache migration complete."
