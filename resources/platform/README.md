# Updating Platform Binaries

This directory contains prebuilt binaries (such as `llvm-symbolizer`) used for crash stack trace symbolization across platforms.

## Updating `llvm-symbolizer`

Prebuilt Clang toolchains can be downloaded directly from:
`https://commondatastorage.googleapis.com/chromium-browser-clang/{PLATFORM}/clang-{VERSION}.tar.xz`

### Target Platforms

| Platform | `$PLATFORM` | Target Path | Version |
| :--- | :--- | :--- | :--- |
| Linux | `Linux_x64` | `resources/platform/linux/llvm-symbolizer` | LLVM 18 |
| macOS (Intel) | `Mac` | `resources/platform/mac/llvm-symbolizer` | LLVM 8 |
| Windows | `Win` | `resources/platform/windows/llvm-symbolizer.exe` | LLVM 24 |

> TODO(b/559164517): Support macOS ARM64 llvm-symbolizer.

### Finding the Clang Version

To check the latest Clang revision from Chromium:
```bash
curl -s "https://chromium.googlesource.com/chromium/src/+/main/tools/clang/scripts/update.py?format=TEXT" \
  | base64 -d | grep -E "CLANG_(REVISION|SUB_REVISION)"
```
Combine the output as `<CLANG_REVISION>-<CLANG_SUB_REVISION>` (e.g., `llvmorg-24-init-7747-g62397f8b-1`).

### Steps

Note: Add `.exe` to `llvm-symbolizer` for Windows.

```bash
# 1. Set platform and version
PLATFORM="Win"        # Linux_x64 | Mac | Win
OS="windows"          # linux | mac | windows
VERSION="<VERSION>"   # e.g., llvmorg-24-init-7747-g62397f8b-1

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

