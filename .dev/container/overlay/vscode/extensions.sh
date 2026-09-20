#! /bin/bash

set -ueo pipefail

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

# Based on 
# - https://gist.github.com/discrimy/6c21c10995f1914cf72cd8474d4501b2
# - https://github.com/b01/dl-vscode-server/blob/7e7fe1f3d05ce2cfaebb430e6ed1de3f4ee3e760/download-vs-code.sh

# Installs VSCode extensions
# Usage: ./extensions.sh [VSCODE commit SHA (in lowercase)] [extension_list_path]

VSCODE_COMMIT_SHA="$1"
EXTENSION_LIST_PATH="$2"
VSCODE_DIR="$HOME/.vscode-server/cli/servers/Stable-${VSCODE_COMMIT_SHA}/server"

echo "Downloading VS Code Server extensions"

for EXT_NAME in $(cat "$EXTENSION_LIST_PATH"); do 
    "$VSCODE_DIR/bin/code-server" \
        --accept-server-license-terms \
        --force \
        --install-extension "$EXT_NAME"
done
