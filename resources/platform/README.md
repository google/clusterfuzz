# Updating Platform Binaries

This directory contains prebuilt binaries (such as `llvm-symbolizer`) used for crash stack trace symbolization across platforms.

## Updating `llvm-symbolizer`

Prebuilt Clang toolchains can be downloaded directly from:
`https://commondatastorage.googleapis.com/chromium-browser-clang/{PLATFORM}/clang-{VERSION}.tar.xz`

### Target Platforms

| Platform | `$PLATFORM` | Target Path |
| :--- | :--- | :--- |
| Linux | `Linux_x64` | `resources/platform/linux/llvm-symbolizer` |
| macOS (Intel) | `Mac` | `resources/platform/mac/llvm-symbolizer` |
| macOS (ARM64) | `Mac_arm64` | `resources/platform/mac/llvm-symbolizer` |
| Windows | `Win` | `resources/platform/windows/llvm-symbolizer.exe` |

### Finding the Clang Version

To check the latest Clang revision from Chromium:
```bash
curl -s "https://chromium.googlesource.com/chromium/src/+/main/tools/clang/scripts/update.py?format=TEXT" \
  | base64 -d | grep -E "CLANG_(REVISION|SUB_REVISION)"
```
Combine the output as `<CLANG_REVISION>-<CLANG_SUB_REVISION>` (e.g., `llvmorg-24-init-3796-g20e97c4b-5`).

### Steps

Note: Add `.exe` to `llvm-symbolizer` for Windows.

```bash
# 1. Set platform and version
PLATFORM="Linux_x64"  # Linux_x64 | Mac | Mac_arm64 | Win
OS="linux"            # linux | mac | windows
VERSION="<VERSION>"   # e.g., llvmorg-24-init-3796-g20e97c4b-5

# 2. Download the archive
mkdir -p /tmp/clang
curl -s -o /tmp/clang/clang.tar.xz \
  "https://commondatastorage.googleapis.com/chromium-browser-clang/${PLATFORM}/clang-${VERSION}.tar.xz"

# 3. Extract llvm-symbolizer (use bin/llvm-symbolizer.exe for Windows)
tar -xJf /tmp/clang/clang.tar.xz -C /tmp/clang bin/llvm-symbolizer

# 4. Copy binary and set permissions (use llvm-symbolizer.exe for Windows)
cp "/tmp/clang/bin/llvm-symbolizer" "resources/platform/${OS}/llvm-symbolizer"
chmod 0755 "resources/platform/${OS}/llvm-symbolizer"

# 5. Clean up temporary files
rm -rf /tmp/clang
```

