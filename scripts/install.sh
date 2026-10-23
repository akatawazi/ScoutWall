#!/bin/sh
# Installs ScoutWall on Linux (x86-64, systemd):
#   curl -fsSL https://github.com/__REPOSITORY__/releases/download/v__VERSION__/install.sh | sudo sh
# This script is attached to one release and installs exactly that release. It downloads the scoutwall
# executable, checks its SHA-256 checksum against the release's SHA256SUMS file, then runs "scoutwall install".
set -eu

repository="__REPOSITORY__"
version="__VERSION__"
asset="scoutwall-linux-x64"
base="https://github.com/$repository/releases/download/v$version"

if [ "$(id -u)" -ne 0 ]; then
    echo "Please run as root, for example: curl -fsSL $base/install.sh | sudo sh" >&2
    exit 1
fi

if [ "$(uname -m)" != "x86_64" ]; then
    echo "This release is for x86-64 Linux; $(uname -m) isn't supported yet." >&2
    exit 1
fi

folder=$(mktemp -d)
trap 'rm -rf "$folder"' EXIT

echo "Downloading ScoutWall $version..."
curl -fsSL "$base/$asset" -o "$folder/scoutwall"
curl -fsSL "$base/SHA256SUMS" -o "$folder/SHA256SUMS"

expected=$(grep " $asset\$" "$folder/SHA256SUMS" | cut -d ' ' -f 1)
actual=$(sha256sum "$folder/scoutwall" | cut -d ' ' -f 1)
if [ -z "$expected" ] || [ "$expected" != "$actual" ]; then
    echo "The download didn't match its checksum; nothing was installed." >&2
    exit 1
fi

if ! ldconfig -p 2>/dev/null | grep -q "libpcap.so"; then
    echo "Installing libpcap for packet capture..."
    if command -v apt-get >/dev/null 2>&1; then
        apt-get install -y libpcap0.8 >/dev/null
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y libpcap >/dev/null
    elif command -v pacman >/dev/null 2>&1; then
        pacman -S --noconfirm libpcap >/dev/null
    else
        echo "Couldn't install libpcap automatically; install it with your package manager for live capture." >&2
    fi
fi

chmod +x "$folder/scoutwall"
"$folder/scoutwall" install
