#!/bin/zsh
set -euo pipefail

PROJECT_DIR=${0:A:h:h}
OUTPUT_DIR="${PROJECT_DIR}/Build"
APP_DIR="${OUTPUT_DIR}/Trace.app"
SDK_DIR="${SDKROOT:-$(xcrun --sdk macosx --show-sdk-path)}"
CACHE_DIR="${TMPDIR:-/tmp}/trace-clang-cache"


mkdir -p "${APP_DIR}/Contents/MacOS" "${APP_DIR}/Contents/Resources" "${CACHE_DIR}"

xcrun swiftc \
    -parse-as-library \
    -O \
    -sdk "${SDK_DIR}" \
    -module-cache-path "${CACHE_DIR}" \
    -target "$(uname -m)-apple-macos14.0" \
    "${PROJECT_DIR}"/Sources/Trace/*.swift \
    -o "${APP_DIR}/Contents/MacOS/Trace" \
    -framework SwiftUI \
    -framework AppKit \
    -framework AVFoundation \
    -framework CryptoKit \
    -framework ImageIO \
    -framework PDFKit \
    -framework Security \
    -framework UniformTypeIdentifiers

cp "${PROJECT_DIR}/Support/Info.plist" "${APP_DIR}/Contents/Info.plist"
codesign --force --deep --sign - "${APP_DIR}"

echo "${APP_DIR}"
