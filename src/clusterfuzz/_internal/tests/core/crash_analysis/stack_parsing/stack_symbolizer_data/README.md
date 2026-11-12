# Test data for stack_symbolizer_test.py

Small Windows PE files used to test reading `ImageBase` and `SizeOfImage`.

| File            | Format | ImageBase     | SizeOfImage | Notes                                      |
| --------------- | ------ | ------------- | ----------- | ------------------------------------------ |
| `x64.dll`       | PE32+  | `0x180000000` | `0x3000`    | 64-bit DLL at the default base.            |
| `x64.exe`       | PE32+  | `0x140000000` | `0x3000`    | 64-bit EXE at the default base.            |
| `x86.dll`       | PE32   | `0x10000000`  | `0x3000`    | 32-bit DLL at the default base.            |
| `x86_large.exe` | PE32   | `0x400000`    | `0x804000`  | 32-bit EXE whose image is larger than its base. |
| `truncated.dll` | -      | -             | -           | `x64.dll` cut off right before `SizeOfImage`. |
| `not_pe.dll`    | -      | -             | -           | A text file.                               |

## Rebuilding

The binaries are built from this source, which has no dependencies:

```c
#ifdef LARGE_IMAGE
// Uninitialized data makes the image large in memory (SizeOfImage) without
// making the file large.
char large_buffer[LARGE_IMAGE];
#endif

int function(void) {
#ifdef LARGE_IMAGE
  return large_buffer[0];
#else
  return 0;
#endif
}
```

using `clang-cl` and `lld-link` from a Chromium checkout
(`third_party/llvm-build/Release+Asserts/bin`):

```
clang-cl /c /O1 /GS- /Zl --target=x86_64-pc-windows-msvc /Fox64.obj pe_test_binary.c
clang-cl /c /O1 /GS- /Zl --target=i686-pc-windows-msvc /Fox86.obj pe_test_binary.c
clang-cl /c /O1 /GS- /Zl --target=i686-pc-windows-msvc /DLARGE_IMAGE=0x800000 /Fox86_large.obj pe_test_binary.c

lld-link /nodefaultlib /Brepro /dll /noentry /export:function /out:x64.dll x64.obj
lld-link /nodefaultlib /Brepro /subsystem:console /entry:function /out:x64.exe x64.obj
lld-link /nodefaultlib /Brepro /dll /noentry /export:function /out:x86.dll x86.obj
lld-link /nodefaultlib /Brepro /subsystem:console /entry:function /out:x86_large.exe x86_large.obj
```

`truncated.dll` is the first 200 bytes of `x64.dll`.
