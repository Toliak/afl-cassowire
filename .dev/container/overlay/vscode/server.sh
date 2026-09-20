#! /bin/bash

set -ueo pipefail

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

# Based on 
# [1] https://gist.github.com/discrimy/6c21c10995f1914cf72cd8474d4501b2
# [2] https://github.com/b01/dl-vscode-server/blob/7e7fe1f3d05ce2cfaebb430e6ed1de3f4ee3e760/download-vs-code.sh

# Installs VSCode Server
# Usage: ./server.sh [VSCODE commit SHA (in lowercase)] [ARCH]
# [ ARCH ] -- amd64, arm64

VSCODE_COMMIT_SHA="$1"
ARCH="$2"

ARCHIVE="vscode-server-linux-${ARCH}.tar.gz"
VSCODE_DIR="${HOME}/.vscode-server/cli/servers/Stable-${VSCODE_COMMIT_SHA}/server"

mkdir -vp "$VSCODE_DIR"

# Some dirs from [2]
mkdir -vp "${HOME}/.vscode-server/extensions"
mkdir -vp "${HOME}/.vscode-server/extensionsCache"

# WARN: for alpine use `server-linux-alpine` (idk what is the name for arm64)

echo "Downloading VS Code Server version = '${VSCODE_COMMIT_SHA}'"
curl -L "https://update.code.visualstudio.com/commit:${VSCODE_COMMIT_SHA}/server-linux-${ARCH}/stable" -o "/tmp/${ARCHIVE}"

tar --no-same-owner \
    --no-same-permissions \
    --no-xattrs \
    --no-selinux \
    --no-acl \
    -xzv \
    --strip-components=1 \
    -C "$VSCODE_DIR" \
    -f "/tmp/${ARCHIVE}"

echo "Server installed"
