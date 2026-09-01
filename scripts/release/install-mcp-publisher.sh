#!/usr/bin/env bash
set -euo pipefail

version="1.8.1"
archive_sha256="a06c9096dcb9727c13555b6be26c7effa707b01f06a4c561ba7a3635443cf2cc"
install_dir="${1:-/tmp/phantom-mcp-publisher-bin}"

if [ "$#" -gt 1 ] || [ -z "$install_dir" ]; then
  echo "usage: install-mcp-publisher.sh [INSTALL_DIR]" >&2
  exit 2
fi

archive="${install_dir}/mcp-publisher_linux_amd64.tar.gz"
mkdir -p "$install_dir"
curl --proto '=https' --proto-redir '=https' --tlsv1.2 --fail --location --silent --show-error \
  --max-redirs 3 --connect-timeout 10 --max-time 120 --max-filesize 134217728 \
  --output "$archive" \
  "https://github.com/modelcontextprotocol/registry/releases/download/v${version}/mcp-publisher_linux_amd64.tar.gz"
echo "${archive_sha256}  ${archive}" | sha256sum --check --strict -
tar -xzf "$archive" -C "$install_dir" mcp-publisher
"${install_dir}/mcp-publisher" --version
