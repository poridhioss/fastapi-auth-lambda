#!/usr/bin/env bash
# Build the AuthAuthorizer Lambda deployment package.
#
# Use this on the lab VM (Ubuntu). It produces authorizer.zip at the repo
# root with a flat layout (no app/ folder) so absolute imports work on
# Lambda.
#
# Usage:
#   ./build_authorizer.sh
#   aws lambda update-function-code --function-name AuthAuthorizer \
#       --zip-file fileb://authorizer.zip

set -euo pipefail

cd "$(dirname "$0")"

rm -rf build authorizer.zip
mkdir -p build/authorizer

# Force Linux x86_64 / Python 3.14 wheels for Lambda compatibility.
pip3 install \
    --platform manylinux2014_x86_64 \
    --target build/authorizer \
    --implementation cp \
    --python-version 3.14 \
    --only-binary=:all: \
    --upgrade \
    pyjwt

cp authorizer.py jwt_utils.py build/authorizer/

(cd build/authorizer && zip -r ../../authorizer.zip . > /dev/null)

echo "Built authorizer.zip ($(du -h authorizer.zip | cut -f1))"