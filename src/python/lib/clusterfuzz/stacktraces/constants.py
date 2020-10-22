# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Stack parsing constants."""

import re

try:
  from clusterfuzz._internal.crash_analysis.stack_parsing import stack_parser
except ImportError:
  from crash_analysis.stack_parsing import stack_parser

C_CPP_EXTENSIONS = ['c', 'cc', 'cpp', 'cxx', 'h', 'hh', 'hpp', 'hxx']

# Patterns which cannot be compiled directly, or which are used for direct
# comparison.
CHECK_FAILURE_PATTERN = r'Check failed: '
JNI_ERROR_STRING = r'JNI DETECTED ERROR IN APPLICATION:'

# Common log prefix format for Google fatal logs.
GOOGLE_LOG_FATAL_PREFIX = r'^F\d{4}\s+\d{2}:\d{2}:\d{2}\.\d+\s+\d+\s+(.*):\d+\]'

# Compiled regular expressions.
ANDROID_ABORT_REGEX = re.compile(r'^Abort message: (.*)')
ANDROID_FATAL_EXCEPTION_REGEX = re.compile(r'.*FATAL EXCEPTION.*:')
ANDROID_KERNEL_ERROR_REGEX = re.compile(
    r'.*Internal error: (Oops)?( -|:) (BUG|[0-9a-fA-F]+)')
ANDROID_KERNEL_STACK_FRAME_REGEX = re.compile(
    # e.g. "[ 1998.156940] [<c0667574>] "
    r'[^(]*\[\<([x0-9a-fA-F]+)\>\]\s+'
    # e.g. "(msm_vidc_prepare_buf+0xa0/0x124)"; function (3), offset (4)
    r'\(?(([\w]+)\+([\w]+)/[\w]+)\)?')
ANDROID_KERNEL_TIME_REGEX = re.compile(r'^\[\s*\d+\.\d+\]\s')
# Parentheses are optional.
ANDROID_PROCESS_NAME_REGEX = re.compile(r'.*[(](.*)[)]$')
ANDROID_SEGV_REGEX = re.compile(r'.*signal.*\(SIG.*fault addr ([^ ]*)(.*)')
ASAN_INVALID_FREE_REGEX = re.compile(
    r'.*AddressSanitizer\: '
    r'attempting free on address which was not malloc\(\)-ed\: '
    r'([xX0-9a-fA-F]+)')
ASAN_DOUBLE_FREE_REGEX = re.compile(
    r'.*(AddressSanitizer).*double-free'
    r' on (unknown address |address |)([xX0-9a-fA-F]+)')
ASAN_MEMCPY_OVERLAP_REGEX = re.compile(
    r'.*(AddressSanitizer).*memcpy-param-overlap'
    r'[^\[]*([\[].*[)])')
ASAN_REGEX = re.compile(
    r'.*ERROR: (HWAddressSanitizer|AddressSanitizer)[: ]*[ ]*([^(:;]+)')
ASSERT_REGEX = re.compile(
    r'(?:\[.*?\]|.*\.(?:%s):.*)?' % ('|'.join(C_CPP_EXTENSIONS)) +
    r'\s*(?:ASSERT(?:ION)? FAIL(?:URE|ED)|panic): (.*)', re.IGNORECASE)
ASSERT_REGEX_GOOGLE = re.compile(GOOGLE_LOG_FATAL_PREFIX +
                                 r'.*assertion failed at\s.*\sin\s*.*: (.*)')
ASSERT_REGEX_GLIBC = re.compile(
    r'.*:\s*assertion [`\'"]?(.*?)[`\'"]? failed\.?$', re.IGNORECASE)
ASSERT_NOT_REACHED_REGEX = re.compile(r'^\s*SHOULD NEVER BE REACHED\s*$')
CFI_ERROR_REGEX = re.compile(
    r'(.*): runtime error: control flow integrity check for type (.*) '
    r'failed during (.*vtable address ([xX0-9a-fA-F]+)|.*)')
CFI_INVALID_DOWNCAST_REGEX = re.compile(r'.*note: vtable is of type (.*)')
CFI_INVALID_VPTR_REGEX = re.compile(r'.*note: invalid vtable$')
CFI_FUNC_DEFINED_HERE_REGEX = re.compile(r'.*note: .* defined here$')
CFI_NODEBUG_ERROR_MARKER_REGEX = re.compile(
    r'CFI: Most likely a control flow integrity violation;.*')
CHROME_CHECK_FAILURE_REGEX = re.compile(
    r'\s*[[][^]]*[:]([^](]*).*[]].*Check failed[:]\s*(.*)')
CHROME_STACK_FRAME_REGEX = re.compile(
    r'[ ]*(#(?P<frame_id>[0-9]+)[ ]'  # frame id (2)
    r'([xX0-9a-fA-F]+)[ ])'  # addr (3)
    r'([^/\\]+)$')  # rest, usually fun (4); may have off
CHROME_WIN_STACK_FRAME_REGEX = re.compile(
    r'[ ]*([^/\\]+) '  # fun (1)
    r'\[([xX0-9a-fA-F]+)\+'  # fun_base (2)
    r'(\d+)\]'  # off[dec] (3)
    r'( \((.*):(\d+)\))?')  # if available, file (5) and line (6)
CHROME_MAC_STACK_FRAME_REGEX = re.compile(
    r'(?P<frame_id>\d+)\s+'  # frame id (1)
    r'(([\w ]+)|(\?\?\?))\s+'  # image (2)
    r'([xX0-9a-fA-F]+)\s+'  # addr[hex] (5)
    r'([^/\\]+)\s*\+\s*'  # fun (6)
    r'(\d+)')  # off[dec] (7)
MSAN_TSAN_REGEX = re.compile(
    r'.*(ThreadSanitizer|MemorySanitizer):\s+(?!ABRT)(?!ILL)([^(:]+)')
FATAL_ERROR_CHECK_FAILURE = re.compile(
    r'#\s+(Check failed: |RepresentationChangerError: node #\d+:)?(.*)')
FATAL_ERROR_DCHECK_FAILURE = re.compile(r'#\s+(Debug check failed: )(.*)')
FATAL_ERROR_REGEX = re.compile(r'#\s*Fatal error in (.*)')
FATAL_ERROR_LINE_REGEX = re.compile(r'#\s*Fatal error in (.*), line [0-9]+')
FATAL_ERROR_UNREACHABLE = re.compile(r'# un(reachable|implemented) code')
GENERIC_SEGV_HANDLER_REGEX = re.compile(
    'Received signal 11 SEGV_[A-Z]+ ([0-9a-f]*)')
GOOGLE_CHECK_FAILURE_REGEX = re.compile(GOOGLE_LOG_FATAL_PREFIX +
                                        r'\s*Check failed[:]\s*(.*)')
GOOGLE_LOG_FATAL_REGEX = re.compile(GOOGLE_LOG_FATAL_PREFIX + r'\s*(.*)')
HWASAN_ALLOCATION_TAIL_OVERWRITTEN_ADDRESS_REGEX = re.compile(
    r'.*ERROR: HWAddressSanitizer: allocation-tail-overwritten; '
    r'heap object \[([xX0-9a-fA-F]+),.*of size')
JAVA_EXCEPTION_CRASH_STATE_REGEX = re.compile(r'\s*at (.*)\(.*\)')
KASAN_ACCESS_TYPE_REGEX = re.compile(r'(Read|Write) of size ([0-9]+)')
KASAN_ACCESS_TYPE_ADDRESS_REGEX = re.compile(
    r'(Read|Write) of size ([0-9]+) at (addr|address) ([a-f0-9]+)')
KASAN_CRASH_TYPE_ADDRESS_REGEX = re.compile(
    r'BUG: KASAN: (.*) (in|on).*(addr|address) ([a-f0-9]+)')
KASAN_CRASH_TYPE_FUNCTION_REGEX = re.compile(
    r'BUG: KASAN: (.*) (in|on).* ([\w]+)\+([\w]+)/([\w]+)')
KASAN_GPF_REGEX = re.compile(r'general protection fault:.*KASAN')
LIBFUZZER_DEADLY_SIGNAL_REGEX = re.compile(
    r'.*ERROR:\s*libFuzzer:\s*deadly signal')
LIBFUZZER_FUZZ_TARGET_EXITED_REGEX = re.compile(
    r'.*ERROR:\s*libFuzzer:\s*fuzz target exited')
LIBFUZZER_OVERWRITES_CONST_INPUT_REGEX = re.compile(
    r'.*ERROR:\s*libFuzzer:\s*fuzz target overwrites its const input')
LIBFUZZER_TIMEOUT_REGEX = re.compile(r'.*ERROR:\s*libFuzzer:\s*timeout')
LIBRARY_NOT_FOUND_ANDROID_REGEX = re.compile(
    r'.*: library ([`\'"])(.*)\1 not found')
LIBRARY_NOT_FOUND_LINUX_REGEX = re.compile(
    r'.*error while loading shared libraries: ([^:]*): '
    r'cannot open shared object file')
LINUX_GDB_CRASH_TYPE_REGEX = re.compile(r'Program received signal ([a-zA-Z]+),')
LINUX_GDB_CRASH_ADDRESS_REGEX = re.compile(r'rip[ ]+([xX0-9a-fA-F]+)')
LINUX_GDB_CRASH_ADDRESS_NO_REGISTERS_REGEX = re.compile(
    r'^(0[xX][0-9a-fA-F]+)\s+in\s+')
LSAN_DIRECT_LEAK_REGEX = re.compile(r'Direct leak of ')
LSAN_INDIRECT_LEAK_REGEX = re.compile(r'Indirect leak of ')
MAC_GDB_CRASH_ADDRESS_REGEX = re.compile(
    r'Reason:.*at address[^0-9]*([0-9a-zA-Z]+)')
OUT_OF_MEMORY_REGEX = re.compile(
    r'.*('
    r'# Allocation failed.*out of memory|'
    r'::OnNoMemory|'
    r'ERROR.*Sanitizer failed to allocate|'
    r'FatalProcessOutOfMemory|'
    r'FX_OutOfMemoryTerminate|'
    r'Out of memory\. Dying.|'
    r'Out of memory\. size=|'
    r'Sanitizer: allocation-size-too-big|'
    r'Sanitizer: calloc-overflow|'
    r'Sanitizer: calloc parameters overflow|'
    r'Sanitizer: requested allocation size.*exceeds maximum supported size|'
    r'allocator is out of memory trying to allocate|'
    r'blinkGCOutOfMemory|'
    r'couldnt allocate.*Out of memory|'
    r'libFuzzer: out-of-memory \(|'
    r'rss limit exhausted|'
    r'in rust_oom).*')
RUNTIME_ERROR_REGEX = re.compile(r'#\s*Runtime error in (.*)')
RUNTIME_ERROR_LINE_REGEX = re.compile(r'#\s*Runtime error in (.*), line [0-9]+')
RUST_ASSERT_REGEX = re.compile(r'thread\s.*\spanicked at \'([^\']*)',
                               re.IGNORECASE)
SAN_ABRT_REGEX = re.compile(r'.*[a-zA-Z]+Sanitizer: ABRT ')
SAN_BREAKPOINT_REGEX = re.compile(r'.*[a-zA-Z]+Sanitizer: breakpoint ')
SAN_CHECK_FAILURE_REGEX = re.compile(
    r'.*Sanitizer CHECK failed[:]\s*[^ ]*\s*(.*)')
SAN_CRASH_TYPE_ADDRESS_REGEX = re.compile(
    r'[ ]*([^ ]*|Atomic [^ ]*) of size ([^ ]*) at ([^ ]*)')
SAN_DEADLYSIGNAL_REGEX = re.compile(r'.*:DEADLYSIGNAL')
SAN_FPE_REGEX = re.compile(r'.*[a-zA-Z]+Sanitizer: FPE ')
SAN_ILL_REGEX = re.compile(r'.*[a-zA-Z]+Sanitizer: ILL ')
SAN_SEGV_CRASH_TYPE_REGEX = re.compile(
    r'.*The signal is caused by a ([A-Z]+) memory access.')
# FIXME: Replace when better ways to check signal crashes are available.
SAN_SIGNAL_REGEX = re.compile(r'.*SCARINESS: (\d+) \(signal\)', re.DOTALL)
SAN_STACK_FRAME_REGEX = re.compile(
    # frame id (1)
    r'\s*#(?P<frame_id>\d+)\s+'
    # addr (2)
    r'([xX0-9a-fA-F]+)\s+'
    # Format is [in {fun}[+{off}]] [{file}[:{line}[:{char}]]] [({mod}[+{off}])]
    # If there is fun and mod/file info, extract
    # fun+off, where fun (7, 5, 23), off (8)
    r'((in\s*(((.*)\+([xX0-9a-fA-F]+))|(.*)) '
    r'('
    # file:line:char, where file (12, 16), line (13, 17), char (14)
    r'(([^ ]+):(\d+):(\d+))|(([^ ]+):(\d+))'
    # or mod+off, where mod (19, 31), off (21, 32)
    r'|'
    r'(\(([^+]+)(\+([xX0-9a-fA-F]+))?\)))'
    r')'
    # If there is only fun info, extract
    r'|'
    r'(in\s*(((.*)\+([xX0-9a-fA-F]+))|(.*)))'
    # If there is only mod info, extract
    r'|'
    r'(\((((.*)\+([xX0-9a-fA-F]+))|(.*))\))'
    r')')
SAN_ADDR_REGEX = re.compile(r'.*(ERROR: [a-zA-Z]+Sanitizer)[: ]*(.*) on '
                            r'(unknown address |address |)([xX0-9a-fA-F]+)')
SAN_SEGV_REGEX = re.compile(r'.*([a-zA-Z]+Sanitizer).*(SEGV|access-violation) '
                            r'on unknown address ([xX0-9a-fA-F]+)')
SECURITY_CHECK_FAILURE_REGEX = re.compile(
    r'.*[[][^]]*[:]([^](]*).*[]].*Security CHECK failed[:]\s*(.*)\.\s*')
SECURITY_DCHECK_FAILURE_REGEX = re.compile(
    r'.*[[][^]]*[:]([^](]*).*[]].*Security DCHECK failed[:]\s*(.*)\.\s*')
UBSAN_DIVISION_BY_ZERO_REGEX = re.compile(r'.*division by zero.*')
UBSAN_FLOAT_CAST_OVERFLOW_REGEX = re.compile(r'.*outside the range of '
                                             r'representable values.*')
UBSAN_INCORRECT_FUNCTION_POINTER_REGEX = re.compile(
    r'.*call to function [^\s]+ through pointer to incorrect function type.*')
UBSAN_INDEX_OOB_REGEX = re.compile(r'.*out of bounds for type.*')
UBSAN_UNSIGNED_INTEGER_OVERFLOW_REGEX = re.compile(
    r'.*unsigned integer overflow.*')
UBSAN_INTEGER_OVERFLOW_REGEX = re.compile(
    r'.*(integer overflow|'
    r'(negation|division) of.*cannot be represented in type).*')
UBSAN_INVALID_BOOL_VALUE_REGEX = re.compile(
    r'.*not a valid value for type \'(bool|BOOL)\'.*')
UBSAN_INVALID_BUILTIN_REGEX = re.compile(r'.*, which is not a valid argument.*')
UBSAN_INVALID_ENUM_VALUE_REGEX = re.compile(r'.*not a valid value for type.*')
UBSAN_MISALIGNED_ADDRESS_REGEX = re.compile(r'.*misaligned address.*')
UBSAN_NO_RETURN_VALUE_REGEX = re.compile(
    r'.*reached the end of a value-returning function.*')
UBSAN_NULL_ARGUMENT_REGEX = re.compile(
    r'.*null pointer passed as .*, which is declared to never be null.*')
UBSAN_NULL_POINTER_READ_REGEX = re.compile(r'.*load of null pointer.*')
UBSAN_NULL_POINTER_REFERENCE_REGEX = re.compile(
    r'.*(binding to|access within|call on) null pointer.*')
UBSAN_NULL_POINTER_WRITE_REGEX = re.compile(r'.*store to null pointer.*')
UBSAN_OBJECT_SIZE_REGEX = re.compile(
    r'.*address .* with insufficient space for an object of type.*')
UBSAN_POINTER_OVERFLOW_REGEX = re.compile(
    r'.*((addition|subtraction) of unsigned offset |'
    r'pointer index expression with base |'
    r'applying non-zero offset [0-9]+ to null pointer|'
    r'applying zero offset to null pointer).*')
UBSAN_RETURNS_NONNULL_ATTRIBUTE_REGEX = re.compile(
    r'.*null pointer returned from function declared to never return null.*')
UBSAN_RUNTIME_ERROR_REGEX = re.compile(r'(.*): runtime error: (.*)')
UBSAN_SHIFT_ERROR_REGEX = re.compile(r'.*shift.*')
UBSAN_UNREACHABLE_REGEX = re.compile(
    r'.*execution reached an unreachable program point.*')
UBSAN_VLA_BOUND_REGEX = re.compile(
    r'.*variable length array bound evaluates to non-positive value.*')
UBSAN_VPTR_REGEX = re.compile(
    r'(.*): runtime error: '
    r'(member access within|member call on|downcast of)'
    r' address ([xX0-9a-fA-F]+) .* of type (.*)')
UBSAN_VPTR_INVALID_DOWNCAST_REGEX = re.compile(
    r'.*note: object is of type (.*)')
UBSAN_VPTR_INVALID_OFFSET_REGEX = re.compile(
    r'.*at offset (\d+) within object of type (.*)')
UBSAN_VPTR_INVALID_VPTR_REGEX = re.compile(r'.*note: object has invalid vptr')
V8_ABORT_FAILURE_REGEX = re.compile(r'^abort: (CSA_ASSERT failed:.*)')
V8_ABORT_METADATA_REGEX = re.compile(r'(.*) \[(.*):\d+\]$')
V8_CORRECTNESS_FAILURE_REGEX = re.compile(r'#\s*V8 correctness failure')
V8_CORRECTNESS_METADATA_REGEX = re.compile(
    r'#\s*V8 correctness ((configs|sources|suppression): .*)')
WINDOWS_CDB_STACK_FRAME_REGEX = re.compile(
    r'([0-9a-zA-Z`]+) '  # Child EBP or SP; remove ` if needed (1)
    r'([0-9a-zA-Z`]+) '  # RetAddr; remove ` if needed (2)
    r'([0-9a-zA-Z_]+)'  # mod (3)
    r'!(.*)\+'  # fun (4)
    r'([xX0-9a-fA-F]+)')  # off (5)
WINDOWS_CDB_STACK_START_REGEX = re.compile(r'ChildEBP RetAddr')
WINDOWS_CDB_CRASH_TYPE_ADDRESS_REGEX = re.compile(
    r'Attempt to (.*) [^ ]* address (.*)')
WINDOWS_CDB_CRASH_TYPE_REGEX = re.compile(
    r'.*DEFAULT_BUCKET_ID[ ]*[:][ ]*([a-zA-Z_]+)')
WINDOWS_CDB_STACK_OVERFLOW_REGEX = re.compile(
    r'.*ExceptionCode: .*\(Stack overflow\).*')

# Golang specific regular expressions.
GOLANG_DIVISION_BY_ZERO_REGEX = re.compile(
    r'^panic: runtime error: integer divide by zero.*')
GOLANG_INDEX_OUT_OF_RANGE_REGEX = re.compile(
    r'^panic: runtime error: index out of range.*')
GOLANG_INVALID_MEMORY_ADDRESS_REGEX = re.compile(
    r'^panic: runtime error: invalid memory address.*')
GOLANG_MAKESLICE_LEN_OUT_OF_RANGE_REGEX = re.compile(
    r'^panic: runtime error: makeslice: len out of range.*')
GOLANG_SLICE_BOUNDS_OUT_OF_RANGE_REGEX = re.compile(
    r'^panic: runtime error: slice bounds out of range.*')
GOLANG_STACK_OVERFLOW_REGEX = re.compile(r'^fatal error: stack overflow.*')

GOLANG_CRASH_TYPES_MAP = [
    (GOLANG_DIVISION_BY_ZERO_REGEX, 'Integer divide by zero'),
    (GOLANG_INDEX_OUT_OF_RANGE_REGEX, 'Index out of range'),
    (GOLANG_INVALID_MEMORY_ADDRESS_REGEX, 'Invalid memory address'),
    (GOLANG_MAKESLICE_LEN_OUT_OF_RANGE_REGEX, 'Makeslice: len out of range'),
    (GOLANG_SLICE_BOUNDS_OUT_OF_RANGE_REGEX, 'Slice bounds out of range'),
    (GOLANG_STACK_OVERFLOW_REGEX, 'Stack overflow'),
]

GOLANG_FATAL_ERROR_REGEX = re.compile(r'^fatal error: (.*)')

GOLANG_STACK_FRAME_FUNCTION_REGEX = re.compile(
    r'^([0-9a-zA-Z\.\-\_\\\/\(\)\*]+)\([x0-9a-f\s,\.]*\)$')

# Python specific regular expressions.
PYTHON_UNHANDLED_EXCEPTION = re.compile(
    r'^\s*=== Uncaught Python exception: ===$')

PYTHON_CRASH_TYPES_MAP = [
    (PYTHON_UNHANDLED_EXCEPTION, 'Uncaught exception'),
]

PYTHON_STACK_FRAME_FUNCTION_REGEX = re.compile(
    #  File "<embedded stdlib>/gzip.py", line 421, in _read_gzip_header
    r'^\s*File "([^"]+)", line (\d+), in (.+)$')

# Mappings of Android kernel error status codes to strings.
ANDROID_KERNEL_STATUS_TO_STRING = {
    0b0001: 'Alignment Fault',
    0b0100: 'Instruction Cache Maintenance Fault',
    0b1100: 'L1 Translation',
    0b1110: 'L2 Translation',
    0b0101: 'Translation Fault, Section',
    0b0111: 'Translation Fault, Page',
    0b0011: 'Access Flag Fault, Section',
    0b0110: 'Access Flag Fault, Page',
    0b1001: 'Domain Fault, Section',
    0b1011: 'Domain Fault, Page',
    0b1101: 'Permission Fault, Section',
    0b1111: 'Permissions Fault, Page',
}

# Ignore lists.
STACK_FRAME_IGNORE_REGEXES = [
    # Function names (exact match).
    r'^abort$',
    r'^exit$',
    r'^pthread\_create$',
    r'^pthread\_kill$',
    r'^raise$',
    r'^tgkill$',

    # Function names (startswith).
    r'^(|\_\_)aeabi\_',
    r'^(|\_\_)memcmp',
    r'^(|\_\_)memcpy',
    r'^(|\_\_)memmove',
    r'^(|\_\_)memset',
    r'^(|\_\_)strcmp',
    r'^(|\_\_)strcpy',
    r'^(|\_\_)strdup',
    r'^(|\_\_)strlen',
    r'^(|\_\_)strncpy',
    r'^\<null\>',
    r'^Abort\(',
    r'^CFCrash',
    r'^ExitCallback',
    r'^IsSandboxedProcess',
    r'^LLVMFuzzerTestOneInput',
    r'^MSanAtExitWrapper',
    r'^New',
    r'^RaiseException',
    r'^SbSystemBreakIntoDebugger',
    r'^SignalAction',
    r'^SignalHandler',
    r'^TestOneProtoInput',
    r'^V8\_Fatal',
    r'^WTF\:\:',
    r'^WTFCrash',
    r'^X11Error',
    r'^\_L\_unlock\_',
    r'^\_\$LT\$',
    r'^\_\_GI\_',
    r'^\_\_asan\:\:',
    r'^\_\_asan\_',
    r'^\_\_assert\_',
    r'^\_\_cxa\_atexit',
    r'^\_\_cxa\_rethrow',
    r'^\_\_cxa\_throw',
    r'^\_\_dump\_stack',
    r'^\_\_hwasan\:\:',
    r'^\_\_hwasan\_',
    r'^\_\_interceptor\_',
    r'^\_\_kasan\_',
    r'^\_\_libc\_',
    r'^\_\_lsan\:\:',
    r'^\_\_lsan\_',
    r'^\_\_msan\:\:',
    r'^\_\_msan\_',
    r'^\_\_pthread\_kill',
    r'^\_\_run\_exit\_handlers',
    r'^\_\_rust\_try',
    r'^\_\_sanitizer\:\:',
    r'^\_\_sanitizer\_',
    r'^\_\_tsan\:\:',
    r'^\_\_tsan\_',
    r'^\_\_ubsan\:\:',
    r'^\_\_ubsan\_',
    r'^\_asan\_',
    r'^\_hwasan\_',
    r'^\_lsan\_',
    r'^\_msan\_',
    r'^\_objc\_terminate',
    r'^\_sanitizer\_',
    r'^\_start',
    r'^\_tsan\_',
    r'^\_ubsan\_',
    r'^abort',
    r'^alloc\:\:',
    r'^android\.app\.ActivityManagerProxy\.',
    r'^android\.os\.Parcel\.',
    r'^art\:\:Thread\:\:CreateNativeThread',
    r'^asan\_',
    r'^calloc',
    r'^check\_memory\_region',
    r'^common\_exit',
    r'^delete',
    r'^demangling\_terminate\_handler',
    r'^dump\_backtrace',
    r'^dump\_stack',
    r'^exit\_or\_terminate\_process',
    r'^fpehandler\(',
    r'^free',
    r'^fuzzer\:\:',
    r'^g\_log',
    r'^generic\_cpp\_',
    r'^gsignal',
    r'^kasan\_',
    r'^libfuzzer\_sys\:\:initialize',
    r'^main',
    r'^malloc',
    r'^mozalloc\_',
    r'^new',
    r'^object\_err',
    r'^operator',
    r'^print\_trailer',
    r'^realloc',
    r'^rust_begin_unwind',
    r'^rust_oom',
    r'^scanf',
    r'^show\_stack',
    r'^std\:\:\_\_terminate',
    r'^std\:\:panic',
    r'^std\:\:process\:\:abort',
    r'^std\:\:sys\:\:unix\:\:abort',

    # Functions names (contains).
    r'.*ASAN\_OnSIGSEGV',
    r'.*BaseThreadInitThunk',
    r'.*DebugBreak',
    r'.*DefaultDcheckHandler',
    r'.*ForceCrashOnSigAbort',
    r'.*MemoryProtection\:\:CMemoryProtector',
    r'.*PartitionAlloc',
    r'.*RtlFreeHeap',
    r'.*RtlInitializeExceptionChain',
    r'.*RtlReportCriticalFailure',
    r'.*RtlUserThreadStart',
    r'.*RtlpHeapHandleError',
    r'.*RtlpLogHeapFailure',
    r'.*SkDebugf',
    r'.*StackDumpSignalHandler',
    r'.*\_\_android\_log\_assert',
    r'.*\_\_tmainCRTStartup',
    r'.*\_asan\_rtl\_',
    r'.*agent\:\:asan\:\:',
    r'.*allocator\_shim',
    r'.*asan\_Heap',
    r'.*asan\_check\_access',
    r'.*asan\_osx\_dynamic\.dylib',
    r'.*assert',
    r'.*base\:\:FuzzedDataProvider',
    r'.*base\:\:allocator',
    r'.*base\:\:android\:\:CheckException',
    r'.*base\:\:debug\:\:BreakDebugger',
    r'.*base\:\:debug\:\:CollectStackTrace',
    r'.*base\:\:debug\:\:StackTrace\:\:StackTrace',
    r'.*ieee754\-',
    r'.*libpthread',
    r'.*logger',
    r'.*logging\:\:CheckError',
    r'.*logging\:\:ErrnoLogMessage',
    r'.*logging\:\:LogMessage',
    r'.*stdext\:\:exception\:\:what',
    r'.*v8\:\:base\:\:OS\:\:Abort',

    # File paths.
    r'.*\ base\/callback',
    r'.*\/AOSP\-toolchain\/',
    r'.*\/bindings\/ToV8\.h',
    r'.*\/crosstool\/',
    r'.*\/gcc\/',
    r'.*\/glibc\-',
    r'.*\/jemalloc\/',
    r'.*\/libc\+\+',
    r'.*\/libc\/',
    r'.*\/llvm\-build\/',
    r'.*\/minkernel\/crts\/',
    r'.*\/sanitizer\_common\/',
    r'.*\/tcmalloc\/',
    r'.*\/vc\/include\/',
    r'.*\/vctools\/crt\/',
    r'.*\/win\_toolchain\/',
    r'.*libc\+\+\/',

    # Wrappers from honggfuzz/libhfuzz/memorycmp.c.
    r'.*\/memorycmp\.c',

    # Others (uncategorized).
    r'.*\+Unknown',
    r'.*\<unknown\ module\>',
    r'.*Inline\ Function\ \@',
    r'^\<unknown\>$',
    r'^\[vdso\]$',

    # Golang specific frames to ignore.
    r'^panic$',
    r'^runtime\.',

    # Fuchsia specific.
    r'^CrashTrampolineAsm',
    r'^libc\_io\_functions\_not\_implemented\_use\_fdio\_instead',
    r'^\<libclang\_rt.asan.so\>',
    r'^\_\_zx\_panic',
    r'^syslog\:\:LogMessage',

    # Android kernel stack frame ignores.
    r'^print_address_description$',
    r'^_etext$',
]

STACK_FRAME_IGNORE_REGEXES_IF_SYMBOLIZED = [
    r'.*libc\.so',
    r'.*libc\+\+\.so',
    r'.*libc\+\+\_shared\.so',
    r'.*libstdc\+\+\.so',
]

IGNORE_CRASH_TYPES_FOR_ABRT_BREAKPOINT_AND_ILLS = [
    'ASSERT',
    'CHECK failure',
    'DCHECK failure',
    'Fatal error',
    'Security CHECK failure',
    'Security DCHECK failure',
]

STATE_STOP_MARKERS = [
    'Direct leak of',
    'Uninitialized value was stored to memory at',
    'allocated by thread',
    'created by main thread at',
    'located in stack of thread',
    'previously allocated by',
]

UBSAN_CRASH_TYPES_MAP = [
    (UBSAN_DIVISION_BY_ZERO_REGEX, 'Divide-by-zero'),
    (UBSAN_FLOAT_CAST_OVERFLOW_REGEX, 'Float-cast-overflow'),
    (UBSAN_INCORRECT_FUNCTION_POINTER_REGEX, 'Incorrect-function-pointer-type'),
    (UBSAN_INDEX_OOB_REGEX, 'Index-out-of-bounds'),
    (UBSAN_INVALID_BOOL_VALUE_REGEX, 'Invalid-bool-value'),
    (UBSAN_INVALID_BUILTIN_REGEX, 'Invalid-builtin-use'),
    (UBSAN_MISALIGNED_ADDRESS_REGEX, 'Misaligned-address'),
    (UBSAN_NO_RETURN_VALUE_REGEX, 'No-return-value'),
    (UBSAN_NULL_ARGUMENT_REGEX, 'Invalid-null-argument'),
    (UBSAN_NULL_POINTER_READ_REGEX, 'Null-dereference READ'),
    (UBSAN_NULL_POINTER_REFERENCE_REGEX, 'Null-dereference'),
    (UBSAN_NULL_POINTER_WRITE_REGEX, 'Null-dereference WRITE'),
    (UBSAN_OBJECT_SIZE_REGEX, 'Object-size'),
    (UBSAN_POINTER_OVERFLOW_REGEX, 'Pointer-overflow'),
    (UBSAN_RETURNS_NONNULL_ATTRIBUTE_REGEX, 'Invalid-null-return'),
    (UBSAN_SHIFT_ERROR_REGEX, 'Undefined-shift'),
    (UBSAN_UNREACHABLE_REGEX, 'Unreachable code'),
    (UBSAN_UNSIGNED_INTEGER_OVERFLOW_REGEX, 'Unsigned-integer-overflow'),
    (UBSAN_VLA_BOUND_REGEX, 'Non-positive-vla-bound-value'),

    # The following types are supersets of other types, and should be placed
    # at the end to avoid subsuming crashes from the more specialized types.
    (UBSAN_INVALID_ENUM_VALUE_REGEX, 'Invalid-enum-value'),
    (UBSAN_INTEGER_OVERFLOW_REGEX, 'Integer-overflow'),
]

# Additional regexes for cleaning up format.
STRIP_STRUCTURE_REGEXES = [
    re.compile(r'^in (.*)'),  # sanitizers have prefix for function if present
    re.compile(r'^\((.*)\)$'),  # sanitizers wrap module if no function
]

# Other constants.
LINE_LENGTH_CAP = 80
MAX_CRASH_STATE_FRAMES = 3
MAX_CYCLE_LENGTH = 10
REPEATED_CYCLE_COUNT = 3

# Stackframe format specifications.
CHROME_STACK_FRAME_SPEC = stack_parser.StackFrameSpec(
    address=3, function_name=4)
CHROME_WIN_STACK_FRAME_SPEC = stack_parser.StackFrameSpec(
    function_name=1,
    function_base=2,
    function_offset=3,
    filename=5,
    fileline=6,
    base=10)
CHROME_MAC_STACK_FRAME_SPEC = stack_parser.StackFrameSpec(
    address=5, function_name=6, function_offset=7, module_name=2, base=10)
SAN_STACK_FRAME_SPEC = stack_parser.StackFrameSpec(
    address=2,
    function_name=[7, 5, 23],
    function_offset=8,
    filename=[12, 16],
    fileline=[13, 17],
    module_name=[19, 31],
    module_offset=[21, 32])
WINDOWS_CDB_STACK_FRAME_SPEC = stack_parser.StackFrameSpec(
    address=1, function_name=4, function_offset=5, module_name=3)
