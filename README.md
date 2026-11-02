# YAXray

Xray client for the macOS menu bar. It doesn't touch system DNS, so NetBird keeps working while the VPN is on.

## Install

Download `YAXray-*-macos.zip` from [Releases](../../releases), unzip it and move `YAXray.app` to `/Applications`. The app isn't notarized, so macOS will refuse to open it until you clear the quarantine flag:

```sh
xattr -dr com.apple.quarantine /Applications/YAXray.app
```

## Build

You need Go and the Xcode Command Line Tools. The app runs on macOS 13 or newer.

```sh
make test
make install   # builds build/YAXray.app and copies it to /Applications
```
