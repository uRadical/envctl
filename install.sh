#!/bin/sh
set -e

REPO="uradical/envctl"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

# Detect OS
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$OS" in
    darwin) OS="darwin" ;;
    linux) OS="linux" ;;
    mingw*|msys*|cygwin*) OS="windows" ;;
    *)
        echo "Unsupported OS: $OS"
        exit 1
        ;;
esac

# Detect architecture
ARCH=$(uname -m)
case "$ARCH" in
    x86_64|amd64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *)
        echo "Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

# Windows ARM64 not supported
if [ "$OS" = "windows" ] && [ "$ARCH" = "arm64" ]; then
    echo "Windows ARM64 is not supported"
    exit 1
fi

# Get latest version
echo "Fetching latest version..."
VERSION=$(curl -s "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | cut -d '"' -f 4)
if [ -z "$VERSION" ]; then
    echo "Failed to fetch latest version"
    exit 1
fi
VERSION_NUM="${VERSION#v}"

echo "Installing envctl ${VERSION} for ${OS}/${ARCH}..."

# Set extension based on OS
if [ "$OS" = "windows" ]; then
    EXT="zip"
else
    EXT="tar.gz"
fi

# Download
FILENAME="envctl_${VERSION_NUM}_${OS}_${ARCH}.${EXT}"
URL="https://github.com/${REPO}/releases/download/${VERSION}/${FILENAME}"

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

echo "Downloading ${URL}..."
curl -fsSL "$URL" -o "$TMPDIR/$FILENAME"

# Extract
cd "$TMPDIR"
if [ "$EXT" = "zip" ]; then
    unzip -q "$FILENAME"
else
    tar xzf "$FILENAME"
fi

# Install
if [ -w "$INSTALL_DIR" ]; then
    mv envctl "$INSTALL_DIR/"
else
    echo "Installing to $INSTALL_DIR (requires sudo)..."
    sudo mv envctl "$INSTALL_DIR/"
fi

echo "Successfully installed envctl ${VERSION} to ${INSTALL_DIR}/envctl"
echo ""
echo "Run 'envctl version' to verify the installation."
