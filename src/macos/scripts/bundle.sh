#!/usr/bin/env bash
# Bundles the already-built `SealPDF` executable into a standalone macOS .app: no installer,
# nothing written outside the bundle. Double-click it in place, or drag it anywhere (e.g.
# /Applications): a .app is a directory, and the binary does not expect a fixed path.
#
# Prerequisite: `just build-macos` has built the Rust library and the Swift executable. Must run
# on macOS: .app bundles are a macOS-only concept and this repo does not cross-compile them.
#
# Usage: src/macos/scripts/bundle.sh [path-to-binary]
#
# APP_VERSION overrides the version (default: the workspace Cargo.toml version) and APP_COMMIT
# the commit shown in the About window (default: HEAD). CI sets APP_COMMIT to the release commit.
# The icon is src/macos/Resources/icon.icns when that file exists; without it the app gets the
# generic icon.
set -euo pipefail

APP_NAME="SealPDF"
BUNDLE_ID="com.leoborai.sealpdf"
BIN_NAME="SealPDF"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
PKG_DIR="$ROOT_DIR/src/macos"
ICON_PATH="$PKG_DIR/Resources/icon.icns"
TEMPLATE_PATH="$PKG_DIR/Info.plist.template"
OUT_DIR="$ROOT_DIR/target/macos"
APP_DIR="$OUT_DIR/$APP_NAME.app"

if [[ "$(uname)" != "Darwin" ]]; then
    echo "error: macOS .app bundles can only be assembled on macOS" >&2
    exit 1
fi

BIN_PATH="${1:-$(swift build -c release --package-path "$PKG_DIR" --show-bin-path)/$BIN_NAME}"
VERSION="${APP_VERSION:-$(awk '/^\[workspace.package\]/{p=1;next} /^\[/{p=0} p && /^version/{gsub(/.*= *"|".*/,""); print; exit}' "$ROOT_DIR/Cargo.toml")}"
COMMIT="${APP_COMMIT:-$(git -C "$ROOT_DIR" rev-parse HEAD 2>/dev/null || echo unknown)}"

if [[ ! -x "$BIN_PATH" ]]; then
    echo "error: binary not found at $BIN_PATH; run 'just build-macos' first" >&2
    exit 1
fi
if [[ -z "$VERSION" ]]; then
    echo "error: cannot read the version from Cargo.toml" >&2
    exit 1
fi

rm -rf "$APP_DIR"
mkdir -p "$APP_DIR/Contents/MacOS" "$APP_DIR/Contents/Resources"

cp "$BIN_PATH" "$APP_DIR/Contents/MacOS/$BIN_NAME"
chmod +x "$APP_DIR/Contents/MacOS/$BIN_NAME"
if [[ -f "$ICON_PATH" ]]; then
    cp "$ICON_PATH" "$APP_DIR/Contents/Resources/icon.icns"
else
    echo "note: no icon at $ICON_PATH; the app gets the generic icon" >&2
fi

sed \
    -e "s/__APP_NAME__/$APP_NAME/g" \
    -e "s/__BUNDLE_ID__/$BUNDLE_ID/g" \
    -e "s/__BIN_NAME__/$BIN_NAME/g" \
    -e "s/__VERSION__/$VERSION/g" \
    -e "s/__COMMIT__/$COMMIT/g" \
    "$TEMPLATE_PATH" > "$APP_DIR/Contents/Info.plist"

# Ad hoc self-sign (no Developer ID), so Gatekeeper's "unidentified developer" prompt is the
# only friction: an unsigned arm64 .app refuses to launch at all on Apple Silicon.
if command -v codesign >/dev/null 2>&1; then
    codesign --force --deep --sign - "$APP_DIR"
fi

echo "Bundled: $APP_DIR (version $VERSION, commit ${COMMIT:0:9})"
echo "First launch: right-click > Open (or 'xattr -cr \"$APP_DIR\"') to clear the unidentified-developer prompt."
