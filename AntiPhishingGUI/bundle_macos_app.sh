#!/usr/bin/env bash
# ==============================================================================
# 腳本名稱：bundle_macos_app.sh
# 功能說明：自動將 anti-phishing-gui 建置為 macOS 原生 .app 應用程式套件 (Bundle)
# 使用方式：./bundle_macos_app.sh
# ==============================================================================

set -euo pipefail

# 確保於 AntiPhishingGUI 目錄內執行
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== 開始製作 AntiPhishing macOS 應用程式 (.app) ==="

# 1. 檢查作業系統是否為 macOS
if [[ "$(uname)" != "Darwin" ]]; then
    echo "錯誤：本打包腳本僅支援在 macOS 系統環境下執行。" >&2
    exit 1
fi

# 2. 從 Cargo.toml 讀取專案版號
VERSION=$(grep -m 1 '^version =' Cargo.toml | sed -E 's/version = "(.*)"/\1/')
if [[ -z "$VERSION" ]]; then
    VERSION="2.1.0"
fi
echo "專案版本號：${VERSION}"

# 3. 建置 Release 二進位執行檔
echo "正在編譯 Release 版本 (cargo build --release)..."
cargo build --release

BIN_PATH="target/release/anti-phishing-gui"
if [[ ! -f "$BIN_PATH" ]]; then
    echo "錯誤：找不到編譯完成的執行檔 $BIN_PATH" >&2
    exit 1
fi

# 4. 定義 App Bundle 目錄結構
APP_NAME="AntiPhishing"
BUNDLE_DIR="${APP_NAME}.app"
CONTENTS_DIR="${BUNDLE_DIR}/Contents"
MACOS_DIR="${CONTENTS_DIR}/MacOS"
RESOURCES_DIR="${CONTENTS_DIR}/Resources"

echo "正在建立 ${BUNDLE_DIR} 目錄結構..."
rm -rf "$BUNDLE_DIR"
mkdir -p "$MACOS_DIR" "$RESOURCES_DIR"

# 5. 複製執行檔並設定執行權限
echo "複製執行檔至 ${MACOS_DIR}..."
cp "$BIN_PATH" "${MACOS_DIR}/anti-phishing-gui"
chmod +x "${MACOS_DIR}/anti-phishing-gui"

# 6. 產生 macOS 圖示檔 (AppIcon.icns)
SRC_ICON="AntiPhishing.png"
if [[ -f "$SRC_ICON" ]] && command -v sips >/dev/null 2>&1 && command -v iconutil >/dev/null 2>&1; then
    echo "正在從 ${SRC_ICON} 生成高畫質 AppIcon.icns..."
    ICONSET_DIR="target/AppIcon.iconset"
    rm -rf "$ICONSET_DIR"
    mkdir -p "$ICONSET_DIR"

    # 生成各尺寸圖示（包含標準解析度與 @2x Retina 解析度）
    sips -z 16 16     "$SRC_ICON" --out "${ICONSET_DIR}/icon_16x16.png" >/dev/null
    sips -z 32 32     "$SRC_ICON" --out "${ICONSET_DIR}/icon_16x16@2x.png" >/dev/null
    sips -z 32 32     "$SRC_ICON" --out "${ICONSET_DIR}/icon_32x32.png" >/dev/null
    sips -z 64 64     "$SRC_ICON" --out "${ICONSET_DIR}/icon_32x32@2x.png" >/dev/null
    sips -z 128 128   "$SRC_ICON" --out "${ICONSET_DIR}/icon_128x128.png" >/dev/null
    sips -z 256 256   "$SRC_ICON" --out "${ICONSET_DIR}/icon_128x128@2x.png" >/dev/null
    sips -z 256 256   "$SRC_ICON" --out "${ICONSET_DIR}/icon_256x256.png" >/dev/null
    sips -z 512 512   "$SRC_ICON" --out "${ICONSET_DIR}/icon_256x256@2x.png" >/dev/null 2>&1 || cp "$SRC_ICON" "${ICONSET_DIR}/icon_256x256@2x.png"

    iconutil -c icns "$ICONSET_DIR" -o "${RESOURCES_DIR}/AppIcon.icns"
    rm -rf "$ICONSET_DIR"
    echo "圖示生成完成。"
else
    echo "提示：未找到 sips/iconutil 工具或源圖示，略過自訂圖示生成。"
fi

# 7. 複製設定檔範本至 Resources
if [[ -f "config.example.toml" ]]; then
    cp "config.example.toml" "${RESOURCES_DIR}/config.example.toml"
fi

# 8. 產生 Info.plist
echo "產生 Info.plist 中繼資訊..."
cat <<EOF > "${CONTENTS_DIR}/Info.plist"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>anti-phishing-gui</string>
    <key>CFBundleIdentifier</key>
    <string>com.antiphishing.gui</string>
    <key>CFBundleName</key>
    <string>AntiPhishing</string>
    <key>CFBundleDisplayName</key>
    <string>AntiPhishing</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleSignature</key>
    <string>????</string>
    <key>CFBundleShortVersionString</key>
    <string>${VERSION}</string>
    <key>CFBundleVersion</key>
    <string>${VERSION}</string>
    <key>CFBundleIconFile</key>
    <string>AppIcon</string>
    <key>LSMinimumSystemVersion</key>
    <string>11.0</string>
    <key>NSHighResolutionCapable</key>
    <true/>
    <key>NSSupportsAutomaticGraphicsSwitching</key>
    <true/>
    <key>NSHumanReadableCopyright</key>
    <string>Copyright © 2026 AntiPhishing</string>
</dict>
</plist>
EOF

# 9. 本地 ad-hoc 簽名（確保 macOS 驗證通過且不報損壞）
if command -v codesign >/dev/null 2>&1; then
    echo "進行本機代碼簽名 (ad-hoc codesign)..."
    codesign --force --deep --sign - "$BUNDLE_DIR" >/dev/null 2>&1 || true
fi

# 10. 移除隔離與 Gatekeeper 屬性
if command -v xattr >/dev/null 2>&1; then
    xattr -cr "$BUNDLE_DIR" 2>/dev/null || true
fi

# 11. 製作 macOS DMG 安裝映像檔
DMG_NAME="AntiPhishing-${VERSION}-macos.dmg"
if command -v hdiutil >/dev/null 2>&1; then
    echo "正在製作 macOS DMG 安裝映像檔 (${DMG_NAME})..."
    DMG_STAGE="target/dmg_stage"
    rm -rf "$DMG_STAGE" "$DMG_NAME"
    mkdir -p "$DMG_STAGE"

    cp -R "$BUNDLE_DIR" "$DMG_STAGE/"
    ln -s /Applications "$DMG_STAGE/Applications"

    hdiutil create -volname "AntiPhishing" -srcfolder "$DMG_STAGE" -ov -format UDZO "$DMG_NAME" >/dev/null
    rm -rf "$DMG_STAGE"
    echo "DMG 製作完成：${SCRIPT_DIR}/${DMG_NAME}"
fi

echo ""
echo "=================================================================="
echo "🎉 打包成功！已於下列路徑生成："
echo "   應用程式套件：${SCRIPT_DIR}/${BUNDLE_DIR}"
if [[ -f "$DMG_NAME" ]]; then
    echo "   DMG 安裝映像檔：${SCRIPT_DIR}/${DMG_NAME}"
fi
echo ""
echo "💡 使用方式："
echo "   1. 雙擊 ${DMG_NAME}，將 AntiPhishing 圖示拖曳至 Applications 資料夾即可完成安裝。"
echo "   2. 亦可直接雙擊 ${BUNDLE_DIR} 執行，完全無需開啟終端機 (CLI)。"
echo "   3. 首次開啟時，GUI 會自動進入設定介面供您設定 IMAP 帳號與密碼。"
echo "      設定檔自動存放於：~/Library/Application Support/AntiPhishing/config.toml"
echo "=================================================================="

