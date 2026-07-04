#!/usr/bin/env bash
# Builds the Lambda deployment package: third-party deps (resolved for the
# Lambda runtime's platform/Python version, not the local machine's) plus the
# src/ package copied in as a subfolder so `from src.X import Y` resolves at
# /var/task/src/... on the Lambda filesystem.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$HERE/.." && pwd)"
BUILD_DIR="$HERE/.build"
ZIP_PATH="$HERE/lambda.zip"

PYTHON_VERSION="3.13"
PLATFORM="manylinux2014_aarch64"

rm -rf "$BUILD_DIR" "$ZIP_PATH"
mkdir -p "$BUILD_DIR"

pip3 install \
  --platform "$PLATFORM" \
  --python-version "$PYTHON_VERSION" \
  --implementation cp \
  --abi "cp313" \
  --only-binary=:all: \
  --no-compile \
  --target "$BUILD_DIR" \
  -r "$PROJECT_ROOT/src/requirements.txt"

cp -R "$PROJECT_ROOT/src" "$BUILD_DIR/src"
find "$BUILD_DIR/src" -name "__pycache__" -type d -prune -exec rm -rf {} +
rm -f "$BUILD_DIR/src/requirements.txt"

cd "$BUILD_DIR"
zip -r -q -X "$ZIP_PATH" . -x '*.pyc'
cd "$HERE"

echo "Built $ZIP_PATH ($(du -h "$ZIP_PATH" | cut -f1))"
