#! /bin/bash

set -ueo pipefail

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

# Based on 
# - https://gist.github.com/discrimy/6c21c10995f1914cf72cd8474d4501b2
# - https://github.com/b01/dl-vscode-server/blob/7e7fe1f3d05ce2cfaebb430e6ed1de3f4ee3e760/download-vs-code.sh

# Installs VSCode CLI
# Usage: ./cli.sh [VSCODE commit SHA (in lowercase)] [ARCH]
# [ ARCH ] -- amd64, arm64

VSCODE_COMMIT_SHA="$1"
ARCH="$2"

ARCHIVE="vscode-cli-linux-${ARCH}.tar.gz"
VSCODE_DIR="${HOME}/.vscode-server"

mkdir -vp "$VSCODE_DIR"

# WARN: for alpine use `cli-alpine-x64`

echo "Downloading VS Code CLI version = '${VSCODE_COMMIT_SHA}'"
curl -L "https://update.code.visualstudio.com/commit:${VSCODE_COMMIT_SHA}/cli-linux-${ARCH}/stable" -o "/tmp/${ARCHIVE}"

# WARN: Do not need "strip-components here"
tar --no-same-owner \
    --no-same-permissions \
    --no-xattrs \
    --no-selinux \
    --no-acl \
    -xzv \
    -C "$VSCODE_DIR" \
    -f "/tmp/${ARCHIVE}"

mv -v "${VSCODE_DIR}/code" "${VSCODE_DIR}/code-${VSCODE_COMMIT_SHA}"

echo "CLI installed"
