# Updating Platform Binaries

This directory contains prebuilt binaries (such as `llvm-symbolizer`) used for crash stack trace symbolization across platforms.

## Updating `llvm-symbolizer`

Platform symbolizer binaries are extracted from the Clang toolchain distributed via [CIPD](https://chrome-infra-packages.appspot.com/).

### Target Packages

| Platform | `$PLATFORM` | Target Path |
| :--- | :--- | :--- |
| Linux | `linux-amd64` | `resources/platform/linux/llvm-symbolizer` |
| macOS | `mac-amd64` | `resources/platform/mac/llvm-symbolizer` |
| Windows | `windows-amd64` | `resources/platform/windows/llvm-symbolizer.exe` |

### Steps

```bash
# 1. Set platform variables
PLATFORM="linux-amd64" # linux-amd64 | mac-amd64 | windows-amd64
OS="linux"             # linux | mac | windows

# 2. Export Clang toolchain from CIPD
mkdir -p /tmp/clang
cipd export -root /tmp/clang -ensure-file - <<CIPD_EOF
fuchsia/third_party/clang/${PLATFORM} latest
CIPD_EOF

# 3. Copy binary and set permissions
# Note: add .exe to llvm-symbolizer if windows (llvm-symbolizer.exe)
cp "/tmp/clang/bin/llvm-symbolizer" "resources/platform/${OS}/llvm-symbolizer"
chmod 0755 "resources/platform/${OS}/llvm-symbolizer"

# 4. Clean up temporary files
rm -rf /tmp/clang

# 5. Verify stack symbolizer tests
python3 butler.py py_unittest -t core -p stack_symbolizer_test.py
```

To list available package instances:
```bash
cipd instances "fuchsia/third_party/clang/${PLATFORM}" -limit 5
```

