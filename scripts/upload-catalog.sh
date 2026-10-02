#!/usr/bin/env bash
set -euo pipefail
: "${R2_BUCKET:?Set R2_BUCKET}"
: "${R2_ACCOUNT_ID:?Set R2_ACCOUNT_ID}"
: "${AWS_ACCESS_KEY_ID:?Set AWS_ACCESS_KEY_ID}"
: "${AWS_SECRET_ACCESS_KEY:?Set AWS_SECRET_ACCESS_KEY}"
ENDPOINT="https://${R2_ACCOUNT_ID}.r2.cloudflarestorage.com"
aws s3 cp public/data/courses.json "s3://${R2_BUCKET}/catalog/courses.json" --endpoint-url "$ENDPOINT" --content-type "application/json; charset=utf-8"
echo "Course catalog uploaded."
