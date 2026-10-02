#!/usr/bin/env bash
set -euo pipefail
if grep -RInE 'Bearer eyJ|x-secret-token|p2a-secret-token-[A-Za-z0-9]+|p2a-app-key-[A-Za-z0-9]+|mZVsCwbqb0uPydd7tRYF9eb3WjPIHTx2cqT\+DRNGRPk=' . --exclude-dir=.git --exclude='secret-check.sh'; then
  echo "Potential archive secret material found. Review before git add." >&2
  exit 1
fi
echo "No known archive secret patterns found in tracked migration files."
