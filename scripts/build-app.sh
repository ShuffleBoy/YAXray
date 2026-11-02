#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${VERSION:-0.1.0}"
APP=build/YAXray.app
BIN="$APP/Contents/MacOS/yaxray"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

for arch in arm64 amd64; do
	CGO_ENABLED=1 GOOS=darwin GOARCH=$arch MACOSX_DEPLOYMENT_TARGET=13.0 \
		CGO_CFLAGS="-mmacosx-version-min=13.0" CGO_LDFLAGS="-mmacosx-version-min=13.0" \
		go build -trimpath -ldflags "-s -w" -o "build/yaxray-$arch" ./cmd/yaxray
done
lipo -create -output "$BIN" build/yaxray-arm64 build/yaxray-amd64
rm build/yaxray-arm64 build/yaxray-amd64

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleName</key><string>YAXray</string>
	<key>CFBundleDisplayName</key><string>YAXray</string>
	<key>CFBundleIdentifier</key><string>space.shff.yaxray</string>
	<key>CFBundleExecutable</key><string>yaxray</string>
	<key>CFBundlePackageType</key><string>APPL</string>
	<key>CFBundleShortVersionString</key><string>${VERSION}</string>
	<key>CFBundleVersion</key><string>${VERSION}</string>
	<key>LSMinimumSystemVersion</key><string>13.0</string>
	<key>LSUIElement</key><true/>
	<key>NSHighResolutionCapable</key><true/>
	<key>NSAppleEventsUsageDescription</key><string>YAXray shows dialogs and asks for the administrator password to install its system component.</string>
</dict>
</plist>
PLIST

codesign --force --deep --sign - "$APP"
echo "built $APP ($VERSION)"
