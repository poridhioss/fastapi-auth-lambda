#!/usr/bin/env bash
# Build the AuthBackend Lambda deployment package.
#
# Use this on the lab VM (Ubuntu). It produces backend.zip at the repo root
# with a flat layout (no app/ folder) so absolute imports work on Lambda.
#
# Usage:
#   ./build_backend.sh
#   aws lambda update-function-code --function-name AuthBackend \
#       --zip-file fileb://backend.zip

set -euo pipefail

cd "$(dirname "$0")"

rm -rf build backend.zip
mkdir -p build/backend

# Force Linux x86_64 / Python 3.14 wheels for Lambda compatibility.
pip3 install \
    --platform manylinux2014_x86_64 \
    --target build/backend \
    --implementation cp \
    --python-version 3.14 \
    --only-binary=:all: \
    --upgrade \
    -r requirements.txt

cp *.py build/backend/

(cd build/backend && zip -r ../../backend.zip . > /dev/null)

echo "Built backend.zip ($(du -h backend.zip | cut -f1))"