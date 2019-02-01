# Copyright 2019 Google LLC
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
"""Stack analyzer module."""

import os
import re
import subprocess

from base import utils
from crash_analysis import crash_analyzer
from crash_analysis.stack_parsing import stack_parser
from crash_analysis.stack_parsing import stack_symbolizer
from system import environment

C_CPP_EXTENSIONS = ['c', 'cc', 'cpp', 'cxx', 'h', 'hh', 'hpp', 'hxx']

# Patterns which cannot be compiled directly, or which are used for direct
# comparison.
CHECK_FAILURE_PATTERN = r'Check failed: '
JNI_ERROR_STRING = r'JNI DETECTED ERROR IN APPLICATION:'

# Compiled regular expressions.
ANDROID_ABORT_REGEX = re.compile(r'^Abort message: (.*)')
ANDROID_FATAL_EXCEPTION_REGEX = re.compile(r'.*FATAL EXCEPTION.*:')
ANDROID_KERNEL_ERROR_REGEX = re.compile(
    r'.*Internal error: (Oops)?( -|:) (BUG|[0-9a-fA-F]+)')
ANDROID_KERNEL_STACK_FRAME_REGEX = re.compile(
    # e.g. "[ 1998.156940] [<c0667574>] "
    r'[^(]*\[\<([0-9a-fA-F]+)\>\]\s+'
    # e.g. "(msm_vidc_prepare_buf+0xa0/0x124)"; function (3), offset (4)
    r'\(?(([\w]+)\+([\w]+)/[\w]+)\)?')
# Parentheses are optional.
ANDROID_PROCESS_NAME_REGEX = re.compile(r'.*[(](.*)[)]$')
ANDROID_SEGV_REGEX = re.compile(r'.*signal.*\(SIG.*fault addr ([^ ]*)(.*)')
ASAN_BAD_FREE_REGEX = re.compile(
    r'.*AddressSanitizer\: '
    r'attempting free on address which was not malloc\(\)-ed\: '
    r'([xX0-9a-fA-F]+)')
ASAN_DOUBLE_FREE_REGEX = re.compile(
    r'.*(AddressSanitizer).*double-free'
    r' on (unknown address |address |)([xX0-9a-fA-F]+)')
ASAN_MEMCPY_OVERLAP_REGEX = re.compile(
    r'.*(AddressSanitizer).*memcpy-param-overlap'
    r'[^\[]*([\[].*[)])')
ASAN_REGEX = re.compile(r'.*(ERROR: AddressSanitizer)[: ]*' r'[ ]*([^(:]+)')
ASSERT_REGEX = re.compile(
    r'(?:\[.*?\]|.*\.(?:%s):.*)?' % ('|'.join(C_CPP_EXTENSIONS)) +
    r'\s*(?:ASSERT(?:ION)? FAIL(?:URE|ED)|panic): (.*)', re.IGNORECASE)
ASSERT_REGEX_GLIBC = re.compile(
    r'.*:\s*assertion [`\'"]?(.*?)[`\'"]? failed\.?$', re.IGNORECASE)
ASSERT_NOT_REACHED_REGEX = re.compile(r'^\s*SHOULD NEVER BE REACHED\s*$')
CFI_ERROR_REGEX = re.compile(
    r'(.*): runtime error: control flow integrity check for type (.*) '
    r'failed during (.*) \(vtable address ([xX0-9a-fA-F]+)\)')
CFI_INVALID_DOWNCAST_REGEX = re.compile(r'.*note: vtable is of type (.*)')
CFI_INVALID_VPTR_REGEX = re.compile(r'.*note: invalid vtable')
CFI_NODEBUG_ERROR_MARKER_REGEX = re.compile(
    r'CFI: Most likely a control flow integrity violation;.*')
CHECK_FAILURE_REGEX = re.compile(
    r'\s*[[][^]]*[:]([^](]*).*[]].*Check failed[:]\s*(.*)')
CHROME_STACK_FRAME_REGEX = re.compile(
    r'[ ]*(#(?P<frame_id>[0-9]+)[ ]'  # frame id (2)
    r'([xX0-9a-fA-F]+)[ ])'  # addr (3)
    r'(.+)')  # rest, usually fun (4); may have off
CHROME_WIN_STACK_FRAME_REGEX = re.compile(
    r'[ ]*(.+) '  # fun (1)
    r'\[([xX0-9a-fA-F]+)\+'  # fun_base (2)
    r'(\d+)\]'  # off[dec] (3)
    r'( \((.*):(\d+)\))?')  # if available, file (5) and line (6)
CHROME_MAC_STACK_FRAME_REGEX = re.compile(
    r'(?P<frame_id>\d+)\s+'  # frame id (1)
    r'(([\w ]+)|(\?\?\?))\s+'  # image (2)
    r'([xX0-9a-fA-F]+)\s+'  # addr[hex] (5)
    r'(.*)\s*\+\s*'  # fun (6)
    r'(\d+)')  # off[dec] (7)
CUSTOM_CRASH_STATE_REGEX = re.compile(r'.*custom-crash-state:\s*([^\s]+)')
MSAN_TSAN_REGEX = re.compile(
    r'.*(ThreadSanitizer|MemorySanitizer):[ ]*([^(:]+)')
FATAL_ERROR_CHECK_FAILURE = re.compile(
    r'#\s+(Check failed: |RepresentationChangerError: node #\d+:)?(.*)')
FATAL_ERROR_DCHECK_FAILURE = re.compile(r'#\s+(Debug check failed: )(.*)')
FATAL_ERROR_REGEX = re.compile(r'#\s*Fatal error in (.*)')
FATAL_ERROR_LINE_REGEX = re.compile(r'#\s*Fatal error in (.*), line [0-9]+')
FATAL_ERROR_UNREACHABLE = re.compile(r'# un(reachable|implemented) code')
GENERIC_SEGV_HANDLER_REGEX = re.compile(
    'Received signal 11 SEGV_[A-Z]+ ([0-9a-f]*)')
JAVA_EXCEPTION_CRASH_STATE_REGEX = re.compile(r'\s*at (.*)\(.*\)')
KASAN_ACCESS_TYPE_REGEX = re.compile(r'(Read|Write) of size ([0-9]+)')
KASAN_CRASH_TYPE_ADDRESS_REGEX = re.compile(
    r'BUG: KASAN: (.*) (in|on).*(addr|address) ([a-f0-9]+)')
KASAN_GPF_REGEX = re.compile(r'general protection fault:.*KASAN')
LIBFUZZER_TIMEOUT_REGEX = re.compile(r'.*ERROR:\s*libFuzzer:\s*timeout')
LINUX_GDB_CRASH_TYPE_REGEX = re.compile(r'Program received signal ([a-zA-Z]+),')
LINUX_GDB_CRASH_ADDRESS_REGEX = re.compile(r'rip[ ]+([xX0-9a-fA-F]+)')
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
    r'rss limit exhausted).*')
RUNTIME_ERROR_REGEX = re.compile(r'#\s*Runtime error in (.*)')
RUNTIME_ERROR_LINE_REGEX = re.compile(r'#\s*Runtime error in (.*), line [0-9]+')
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
    r'.*(integer overflow|negation of.*cannot be represented in type).*')
UBSAN_INVALID_BOOL_VALUE_REGEX = re.compile(
    r'.*not a valid value for type \'bool\'.*')
UBSAN_MISALIGNED_ADDRESS_REGEX = re.compile(r'.*misaligned address.*')
UBSAN_NO_RETURN_VALUE_REGEX = re.compile(
    r'.*reached the end of a value-returning function.*')
UBSAN_NULL_POINTER_READ_REGEX = re.compile(r'.*load of null pointer.*')
UBSAN_NULL_POINTER_REFERENCE_REGEX = re.compile(
    r'.*(binding to|access within|call on) null pointer.*')
UBSAN_NULL_POINTER_WRITE_REGEX = re.compile(r'.*store to null pointer.*')
UBSAN_OBJECT_SIZE_REGEX = re.compile(
    r'.*address .* with insufficient space for an object of type.*')
UBSAN_POINTER_OVERFLOW_REGEX = re.compile(
    r'.*((addition|subtraction) of unsigned offset |'
    r'pointer index expression with base ).*')
UBSAN_RUNTIME_ERROR_REGEX = re.compile(r'(.*): runtime error: (.*)')
UBSAN_SHIFT_ERROR_REGEX = re.compile(r'.*shift.*')
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
IGNORE_CONTAINS = [
    # Functions names.
    'ASAN_OnSIGSEGV',
    'BaseThreadInitThunk',
    'DebugBreak',
    'DefaultDcheckHandler',
    'ForceCrashOnSigAbort',
    'PartitionAlloc',
    'RtlReportCriticalFailure',
    'RtlFreeHeap',
    'RtlInitializeExceptionChain',
    'RtlUserThreadStart',
    'RtlpHeapHandleError',
    'RtlpLogHeapFailure',
    'SkDebugf',
    'StackDumpSignalHandler',
    '__android_log_assert',
    '__tmainCRTStartup',
    '_asan_rtl_',
    'allocator_shim',
    'asan_Heap',
    'asan_check_access',
    'asan_osx_dynamic.dylib',
    'assert',
    'ieee754-',
    'libpthread',
    'logger',
    'memcpy-ssse3-back.S',

    # Functions names with namespaces.
    'MemoryProtection::CMemoryProtector',
    'agent::asan::',
    'base::FuzzedDataProvider',
    'base::android::CheckException',
    'base::allocator',
    'base::debug::BreakDebugger',
    'base::debug::CollectStackTrace',
    'base::debug::StackTrace::StackTrace',
    'logging::ErrnoLogMessage',
    'logging::LogMessage',
    'stdext::exception::what',
    'v8::base::OS::Abort',

    # Others.
    '+Unknown',
    '<unknown module>',
    'Inline Function @',

    # File paths.
    ' base/callback',
    '/AOSP-toolchain/',
    '/bindings/ToV8.h',
    '/gcc/',
    '/glibc-',
    '/jemalloc/',
    '/libc++',
    '/libc/',
    '/llvm-build/',
    '/minkernel/crts/',
    '/sanitizer_common/',
    '/vc/include/',
    '/vctools/crt/',
    '/win_toolchain/',
    'libc++/',
]
IGNORE_EQUALS = [
    '<unknown>',
    '[vdso]',
    'abort',
    'pthread_kill',
    'raise',
    'tgkill',
]
IGNORE_STARTSWITH = [
    # Sanitizer functions.
    '__asan::',
    '__lsan::',
    '__msan::',
    '__tsan::',
    '__ubsan::',
    '__sanitizer::',
    '__asan_',
    '__lsan_',
    '__msan_',
    '__tsan_',
    '__ubsan_',
    '__sanitizer_',
    '_asan_',
    '_lsan_',
    '_msan_',
    '_tsan_',
    '_ubsan_',
    '_sanitizer_',

    # Others.
    '<null>',
    'Abort(',
    'CFCrash',
    'IsSandboxedProcess',
    'LLVMFuzzerTestOneInput',
    'New',
    'RaiseException',
    'SbSystemBreakIntoDebugger',
    'SignalAction',
    'SignalHandler',
    'V8_Fatal',
    'WTF::',
    'WTFCrash',
    'X11Error',
    '__assert_',
    '__cxa_rethrow',
    '__cxa_throw',
    '__dump_stack',
    '__interceptor_',
    '__libc_',
    '__pthread_kill',
    '_L_unlock_',
    '_objc_terminate',
    '_start',
    'abort',
    'android.app.ActivityManagerProxy.',
    'android.os.Parcel.',
    'asan_',
    'calloc',
    'check_memory_region',
    'common_exit',
    'delete',
    'demangling_terminate_handler',
    'dump_backtrace',
    'dump_stack',
    'exit_or_terminate_process',
    'fpehandler(',
    'free',
    'fuzzer::',
    'generic_cpp_',
    'g_log',
    'gsignal',
    'kasan_',
    'main',
    'malloc',
    'memcmp',
    'memcpy',
    'memmove',
    'memset',
    'mozalloc_',
    'new',
    'object_err',
    'operator',
    'print_trailer',
    'realloc',
    'scanf',
    'show_stack',
    'std::__terminate',
    'strcmp',
    'strcpy',
    'strlen',
]
IGNORE_CONTAINS_IF_SYMBOLIZED = [
    'libc.so',
    'libc++.so',
    'libc++_shared.so',
    'libstdc++.so',
]

IGNORE_CRASH_TYPES_FOR_ABRT_BREAKPOINT_AND_ILLS = [
    'ASSERT',
    'CHECK failure',
    'DCHECK failure',
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
    (UBSAN_INTEGER_OVERFLOW_REGEX, 'Integer-overflow'),
    (UBSAN_UNSIGNED_INTEGER_OVERFLOW_REGEX, 'Unsigned-integer-overflow'),
    (UBSAN_INVALID_BOOL_VALUE_REGEX, 'Invalid-bool-value'),
    (UBSAN_MISALIGNED_ADDRESS_REGEX, 'Misaligned-address'),
    (UBSAN_NO_RETURN_VALUE_REGEX, 'No-return-value'),
    (UBSAN_NULL_POINTER_READ_REGEX, 'Null-dereference READ'),
    (UBSAN_NULL_POINTER_REFERENCE_REGEX, 'Potential-null-reference'),
    (UBSAN_NULL_POINTER_WRITE_REGEX, 'Null-dereference WRITE'),
    (UBSAN_OBJECT_SIZE_REGEX, 'Object-size'),
    (UBSAN_POINTER_OVERFLOW_REGEX, 'Pointer-overflow'),
    (UBSAN_SHIFT_ERROR_REGEX, 'Undefined-shift'),
    (UBSAN_VLA_BOUND_REGEX, 'Non-positive-vla-bound-value'),
]

# Additional regexes for cleaning up format.
STRIP_STRUCTURE_REGEXES = [
    re.compile(r'^in (.*)'),  # sanitizers have prefix for function if present
    re.compile(r'^\((.*)\)$'),  # sanitizers wrap module if no function
]

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

# Other constants.
LINE_LENGTH_CAP = 80
MAX_CRASH_STATE_FRAMES = 3
MAX_CYCLE_LENGTH = 10
MAX_REDZONE_SIZE_FOR_OOMS_AND_HANGS = 64
REPEATED_CYCLE_COUNT = 3


class StackAnalyzerState(object):
  """Effectively a struct to store state while analyzing a crash stack."""

  def __init__(self, symbolized=True):
    self.crash_type = ''
    self.crash_address = ''
    self.crash_state = ''
    self.crash_stacktrace = ''
    self.frame_count = 0
    self.process_name = 'NULL'
    self.process_died = False
    self.tool = ''
    self.symbolized = symbolized
    self.frames = []
    self.raw_frames = []
    self.last_frame_id = -1

    # Additional tracking for Android bugs.
    self.found_java_exception = False

    # Additional tracking for bad casts.
    self.found_bad_cast_crash_end_marker = False

    # Additional tracking for check failures.
    self.check_failure_source_file = ''

    # Additional tracking for fatal errors.
    self.fatal_error_occurred = False


def filter_addresses_and_numbers(string):
  """Return a normalized string without unique addresses and numbers."""
  # Remove offset part from end of every line.
  result = re.sub(r'\+0x[0-9a-fA-F]+\n', '\n', string, re.DOTALL)

  # Replace sections that appear to be addresses with the string "ADDRESS".
  address_expression = r'0x[a-fA-F0-9]{4,}[U]*'
  address_replacement = r'ADDRESS'
  result = re.sub(address_expression, address_replacement, result)

  # Replace sections that appear to be numbers with the string "NUMBER".
  # Cases that we are avoiding:
  # - source.cc:1234
  # - libsomething-1.0.so (to avoid things like NUMBERso in replacements)
  number_expression = r'(^|[^:0-9.])[0-9.]{4,}($|[^A-Za-z0-9.])'
  number_replacement = r'\1NUMBER\2'
  return re.sub(number_expression, number_replacement, result)


def filter_crash_parameters(state):
  """Normalize crash parameters into generic format regardless of the tool
  used."""
  # Filter crash state represented in |state|.

  # Shorten JNI messages.
  if JNI_ERROR_STRING in state.crash_state:
    state.crash_state = state.crash_state.replace(JNI_ERROR_STRING, 'JNI:')

  if state.symbolized:
    # 1. Normalize addresses and numbers in crash_state.
    # Skip normalization for V8 correctness failures, which use the crash state
    # to store metadata containing numbers.
    if state.crash_type not in ['V8 correctness failure']:
      state.crash_state = filter_addresses_and_numbers(state.crash_state)

    # 2. Truncate each line in the crash state to avoid excessive length.
    original_crash_state = state.crash_state
    state.crash_state = ''
    for line in original_crash_state.splitlines():
      # Exclude bad-cast line for bad cast testcases.
      # FIXME: Find a way to make bad-cast lines shorter and then remove this.
      if line.startswith('Bad-cast'):
        state.crash_state += line + '\n'
      else:
        state.crash_state += line[:LINE_LENGTH_CAP] + '\n'

  # 3. Add a trailing \n if it does not exist in crash state.
  if state.crash_state and state.crash_state[-1] != '\n':
    state.crash_state += '\n'

  # 4. Don't return an empty crash state if we have a crash type. Either set to
  # NULL or use the crashing process name if available.
  if state.crash_type and not state.crash_state.strip():
    state.crash_state = state.process_name

  # Normalize access size parameter if greater than 16 bytes.
  m = re.match('([^0-9]+)([0-9]+)', state.crash_type, re.DOTALL)
  if m:
    num = int(m.group(2))
    if num > 16:
      num = '{*}'

    state.crash_type = (
        state.crash_type[:len(m.group(1))] + str(num) +
        state.crash_type[m.end():])

  # On some platforms crash address is unnecessarily long. We can truncate it.
  if (state.crash_address.startswith('0x0000') and
      len(state.crash_address) == 18):
    state.crash_address = '0x%s' % state.crash_address[len('0x0000'):]

  # Report null dereferences as such.
  if state.crash_address and state.crash_type.startswith('UNKNOWN'):
    int_crash_address = crash_analyzer.address_to_integer(state.crash_address)
    if crash_analyzer.is_null_dereference(int_crash_address):
      state.crash_type = state.crash_type.replace('UNKNOWN', 'Null-dereference')

  return state


def filter_stack_frame(stack_frame):
  """Filter stack frame."""
  # Filter out anonymous namespaces.
  anonymous_namespaces = [
      'non-virtual thunk to ',
      '(anonymous namespace)::',
      '`anonymous namespace\'::',
  ]
  for ns in anonymous_namespaces:
    stack_frame = stack_frame.replace(ns, '')

  # Rsplit around '!'.
  stack_frame = stack_frame.split('!')[-1]

  # Lsplit around '(', '['.
  m = re.match(r'(.*?)[\(\[].*', stack_frame)
  if m and m.group(1):
    return m.group(1).strip()

  # Lsplit around ' '.
  stack_frame = stack_frame.strip().split(' ')[0]

  return stack_frame


def ignore_stack_frame(stack_frame, symbolized):
  """Return true if stack frame should not used in determining the
  crash state."""
  # No data, should ignore.
  if not stack_frame:
    return True

  # Too short of a stack frame, nothing to do.
  if len(stack_frame) < 3:
    return True

  # Normalize path seperator in stack frame, this allows to ignore strings
  # properly cross-platform.
  normalized_stack_frame = stack_frame.replace('\\', '/')

  # Check if the stack frame matches one of the strings
  # in the ignore list.
  for ignore_string in IGNORE_EQUALS:
    if ignore_string == normalized_stack_frame:
      return True

  # Check if the stack frame begins with one of the startswith
  # strings in the ignore list.
  for ignore_string in IGNORE_STARTSWITH:
    if normalized_stack_frame.startswith(ignore_string):
      return True

  # Check if the stack frame contains one of the strings
  # in the ignore list.
  for ignore_string in IGNORE_CONTAINS:
    if ignore_string in normalized_stack_frame:
      return True

  if symbolized:
    for ignore_string in IGNORE_CONTAINS_IF_SYMBOLIZED:
      if ignore_string in normalized_stack_frame:
        return True

  return False


def should_ignore_line_for_crash_processing(line, state):
  """Check to see if a line should be displayed in a report, but ignored when
     processing crashes."""
  # If we detected that the process had died, we won't use any further stack
  # frames to make decision on crash parameters.
  if state.process_died:
    return True

  # Ignore console information messages, as they are not relevant to crash
  # parameters parsing.
  if ':INFO:CONSOLE' in line:
    return True

  # Ignore summary lines.
  if 'SUMMARY:' in line:
    return True

  # Ignore warnings from ASan, but not other sanitizer tools.
  if 'WARNING: AddressSanitizer' in line:
    return True

  # Exclusion for mprotect warning on address 0x00010000. This is a harmless
  # coverage buffer size warning, and is fixed in clang r234602.
  if 'failed to mprotect 0x00010000' in line:
    return True

  # Ignore certain lines printed by dump render tree.
  if 'text run at (' in line:
    return True

  # Ignore this unneeded JNI abort error message since it will be followed by
  # the needed stacktrace later.
  if 'Please include Java exception stack in crash report' in line:
    return True

  # Ignore DEADLYSIGNAL lines from sanitizers.
  if SAN_DEADLYSIGNAL_REGEX.match(line):
    return True

  return False


def update_state_on_match(compiled_regex,
                          line,
                          state,
                          new_type=None,
                          new_state=None,
                          new_frame_count=None,
                          new_address=None,
                          address_from_group=None,
                          type_from_group=None,
                          tool_from_group=None,
                          state_from_group=None,
                          address_filter=lambda s: s,
                          type_filter=lambda s: s,
                          reset=False):
  """Update the specified parts of the state if we have a match."""
  match = compiled_regex.match(line)
  if not match:
    return None

  if reset:
    state.crash_address = ''
    state.crash_state = ''
    state.frame_count = 0

  # Direct updates.
  if new_type is not None:
    state.crash_type = new_type

  if new_state is not None:
    state.crash_state = new_state

  if new_frame_count is not None:
    state.frame_count = new_frame_count

  if new_address is not None:
    state.crash_address = new_address

  # Updates from match groups.
  if type_from_group is not None:
    state.crash_type = type_filter(match.group(type_from_group)).strip()

  if address_from_group is not None:
    state.crash_address = address_filter(
        match.group(address_from_group)).strip()

  if tool_from_group is not None:
    state.tool = match.group(tool_from_group)

  if state_from_group is not None:
    state.crash_state = match.group(state_from_group)

  return match


def add_frame_on_match(compiled_regex,
                       line,
                       state,
                       group=0,
                       frame_filter=filter_stack_frame,
                       demangle=False,
                       can_ignore=True,
                       frame_spec=None,
                       frame_override_func=None):
  """Add a frame to the crash state if we have a match on this line."""
  match = compiled_regex.match(line)
  if not match:
    return None

  frame = match.group(group).strip()

  # Strip out unneeded structure. Remove this hack after modularizing tools.
  for regex in STRIP_STRUCTURE_REGEXES:
    structure_match = regex.match(frame)
    if structure_match:
      frame = structure_match.group(1)
      break

  # Demangle the frame if needed.
  if demangle and environment.is_posix():
    pipe = subprocess.Popen(
        ['c++filt', '-n', frame], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    frame, _ = pipe.communicate()

  # Try to parse the frame with the various stackframes.
  frame_struct = None
  if frame_spec is not None:
    frame_struct = frame_spec.parse_stack_frame(match)

    # Account for case when we have no symbols and hence don't want to strip
    # anonymous namespaces in the crash state.
    if (frame_struct and frame_struct.module_offset and
        not frame_struct.function_name):
      frame_filter = lambda s: s

    # Update stacktrace frames list with frame struct.
    new_thread = state.last_frame_id < 0
    try:
      # We have a 'frame_id' group, so pull the ID and check if we need to start
      # a new thread. Also update last_frame_id accordingly.
      frame_id = int(match.group('frame_id').strip())
      if frame_id < state.last_frame_id:
        new_thread = True
      state.last_frame_id = frame_id
    except IndexError:
      # If there is not 'frame_id' group, just stick everything into one thread.
      state.last_frame_id += 1

    if new_thread:
      state.frames.append([])
    state.frames[-1].append(frame_struct)

  if frame_override_func:
    frame = frame_override_func(frame, frame_struct)

  # If we are ignoring a frame, we still have a match. Don't add it to the
  # state, but notify the caller that we found something.
  if can_ignore and ignore_stack_frame(frame, state.symbolized):
    return match

  # Filter the frame and add to a list.
  filtered_frame = frame_filter(frame)
  state.raw_frames.append(filtered_frame)

  # Update the crash state only if we need more frames.
  if state.frame_count < MAX_CRASH_STATE_FRAMES:
    state.crash_state += filtered_frame + '\n'
    state.frame_count += 1

  return match


def fix_sanitizer_crash_type(crash_type):
  """Ensure that Sanitizer crashes use generic formats."""
  # General normalization.
  crash_type = crash_type.lower().replace('_', '-').capitalize()

  # Use more generic types for certain Sanitizer ones.
  crash_type = crash_type.replace('Int-divide-by-zero', 'Divide-by-zero')

  return crash_type


def fix_win_cdb_crash_type(crash_type):
  """Convert a Windows CDB crash type into ASAN like format."""
  # Strip application verifier string from crash type suffix.
  crash_type = utils.strip_from_right(crash_type, '_AVRF')

  # Standardize crash type with lowercase, hyphens and capitalization.
  crash_type = crash_type.replace('_', '-').lower().capitalize()

  # Change crash type to other common types.
  crash_type = crash_type.replace('Status-integer-overflow', 'Integer-overflow')
  crash_type = crash_type.replace('Status-integer-divide-by-zero',
                                  'Divide-by-zero')
  return crash_type


def fix_check_failure_string(failure_string):
  """Cleanup values that should not be included in CHECK failure strings."""
  # Remove |CHECK_FAILURE_PATTERN| from start of failure string.
  failure_string = utils.strip_from_left(failure_string, CHECK_FAILURE_PATTERN)

  # Cover example like "CHECK_EQ( (unsigned)ptr[0],1u) failed: 25 vs. 1".
  # This only happens on Android, where we cannot strip the
  # CHECK_FAILURE_PATTERN, so we looked for "failed:" as preceding string.
  failure_string = re.sub(r'(?<=failed): .*vs\..*$', r'', failure_string)

  # Cover example like len > 0 (-1 vs. 0).".
  failure_string = re.sub(r' \(.*vs\..*\)\.?$', r'', failure_string)

  # Strip unneeded chars at end.
  return failure_string.strip(' .\'"[]')


def fix_filename_string(filename_string):
  """Fix filename string to remove line number, path and other invalid chars."""
  # Remove invalid chars at ends first.
  filename_string = filename_string.strip(' .\'"[]')

  # Remove the source line number information.
  filename_string = filename_string.split(':')[0].split('(')[0]

  # Replace backslashes with forward slashes for platform consistency.
  filename_string = filename_string.replace('\\', '/')

  # Remove the path information.
  filename_string = os.path.basename(filename_string)

  return filename_string


def get_fault_description_for_android_kernel(code):
  """Return human readable fault description based on numeric FSR value."""
  # Convert code from string to number.
  try:
    code = int(code, 16)
  except:
    return 'BUG'

  # Figure out where is out-of-bounds read or write.
  if code & 0x800 == 0:
    fault = 'READ'
  else:
    fault = 'WRITE'
  fault += ' '

  # The full status code is bits 12, 10, and 0-3, but we're ignoring 12 and 10.
  status = code & 0b1111
  try:
    fault += ANDROID_KERNEL_STATUS_TO_STRING[status]
  except KeyError:
    fault += 'Unknown'

  fault += ' (%s)' % str(code)
  return 'Kernel failure\n' + fault


def filter_kasan_crash_type(crash_type):
  """Filter a KASan crash type."""
  return 'Kernel failure\n%s' % crash_type.replace(' ', '-').capitalize()


def update_state_on_check_failure(state, line, regex, crash_type):
  """Update the state if the crash is a CHECK failure."""
  check_match = update_state_on_match(
      regex, line, state, new_type=crash_type, reset=True, new_frame_count=1)
  if check_match:
    failure_string = fix_check_failure_string(check_match.group(2))
    source_file = fix_filename_string(check_match.group(1))
    state.crash_state = '%s in %s\n' % (failure_string, source_file)


def match_assert(line, state, regex):
  """Match an assert."""
  assert_match = update_state_on_match(
      regex, line, state, new_type='ASSERT', new_frame_count=1)
  if assert_match and assert_match.group(1):
    # For asserts, we want to actually use the match as the crash state.
    state.crash_state = assert_match.group(1) + '\n'


def update_crash_state_for_stack_overflow_if_needed(state):
  """For stack-overflow bugs, updates crash state based on cycle detected."""
  if state.crash_type != 'Stack-overflow':
    return

  num_frames = len(state.raw_frames)
  for frame_index in xrange(num_frames):
    for cycle_length in xrange(1, MAX_CYCLE_LENGTH + 1):
      # Create frame potential cycles of a given length starting from
      # |frame_index|.
      frame_potential_cycles = []
      end_reached = False
      for i in xrange(0, REPEATED_CYCLE_COUNT):
        start_index = frame_index + i * cycle_length
        end_index = frame_index + (i + 1) * cycle_length
        if end_index >= num_frames:
          end_reached = True
          break

        frame_potential_cycles.append(state.raw_frames[start_index:end_index])

      if end_reached:
        # Reached end while trying to find cycle, skip iteration.
        continue

      # Check if all the potential_cycles are equal. If yes, we found a cycle.
      potential_cycles_are_equal = all(
          frame_potential_cycle == frame_potential_cycles[0]
          for frame_potential_cycle in frame_potential_cycles)

      # Update crash state based on cycle detected.
      if potential_cycles_are_equal:
        state.crash_state = '\n'.join(
            frame_potential_cycles[0][:MAX_CRASH_STATE_FRAMES]) + '\n'
        return


def llvm_test_one_input_override(frame, frame_struct):
  """Override frame matching for LLVMFuzzerTestOneInput frames."""
  if not frame.startswith('LLVMFuzzerTestOneInput'):
    return frame

  if frame_struct and frame_struct.filename:
    # Use the filename as the frame instead.
    return frame.replace(
        'LLVMFuzzerTestOneInput',
        os.path.basename(frame_struct.filename.replace('\\', '/')))

  return frame


def get_crash_data(crash_data, symbolize_flag=True):
  """Get crash parameters from crash data.
  Crash parameters include crash type, address, state and stacktrace.
  If the stacktrace is not already symbolized, we will try to symbolize it
  unless |symbolize| flag is set to False. Symbolized stacktrace will contain
  inline frames, but we do exclude them for purposes of crash state generation
  (helps in testcase deduplication)."""
  # Decide whether to symbolize or not symbolize the input stacktrace.
  if symbolize_flag:
    crash_stacktrace_with_inlines = stack_symbolizer.symbolize_stacktrace(
        crash_data, enable_inline_frames=True)
    crash_stacktrace_without_inlines = stack_symbolizer.symbolize_stacktrace(
        crash_data, enable_inline_frames=False)
  else:
    # We are explicitly indicated to not symbolize using |symbolize_flag|. There
    # is no distinction between inline and non-inline frames for an unsymbolized
    # stacktrace.
    crash_stacktrace_with_inlines = crash_data
    crash_stacktrace_without_inlines = crash_data

  # Compose the StackAnalyzerState object.
  state = StackAnalyzerState(symbolized=symbolize_flag)
  state.crash_stacktrace += crash_stacktrace_with_inlines

  # We always want to detect v8 runtime errors in analyze task, and
  # we don't expect DETECT_V8_RUNTIME_ERRORS to be specified in jobs
  # since we opt fuzzers into it.
  if environment.get_value('TASK_NAME') == 'analyze':
    detect_v8_runtime_errors = True
  else:
    detect_v8_runtime_errors = environment.get_value('DETECT_V8_RUNTIME_ERRORS',
                                                     False)

  # Detect OOMs and hangs if flag is set and redzone is below certain size (only
  # applicable for ASan jobs).
  redzone_size = environment.get_value('REDZONE')
  detect_ooms_and_hangs = (
      environment.get_value('REPORT_OOMS_AND_HANGS') and
      (not redzone_size or redzone_size <= MAX_REDZONE_SIZE_FOR_OOMS_AND_HANGS))

  for line in crash_stacktrace_without_inlines.splitlines():
    if should_ignore_line_for_crash_processing(line, state):
      continue

    # Bail out from crash paramater parsing if we detect this is a out-of-memory
    # signature.
    if not detect_ooms_and_hangs and OUT_OF_MEMORY_REGEX.match(line):
      return StackAnalyzerState()

    # Ignore aborts, breakpoints and ills for asserts, check and dcheck
    # failures. These are intended, retain their original state.
    if (SAN_ABRT_REGEX.match(line) or SAN_BREAKPOINT_REGEX.match(line) or
        SAN_ILL_REGEX.match(line)):
      if state.crash_type in IGNORE_CRASH_TYPES_FOR_ABRT_BREAKPOINT_AND_ILLS:
        continue

    # Assertions always come first, before the actual crash stacktrace.
    match_assert(line, state, ASSERT_REGEX)
    match_assert(line, state, ASSERT_REGEX_GLIBC)

    # ASSERT_NOT_REACHED prints a single line error then triggers a crash. We
    # set the crash state here, but look for the stack after a crash on an
    # unknown address.
    update_state_on_match(
        ASSERT_NOT_REACHED_REGEX,
        line,
        state,
        new_type='ASSERT_NOT_REACHED',
        reset=True)

    # Platform specific: Linux gdb crash type format.
    update_state_on_match(
        LINUX_GDB_CRASH_TYPE_REGEX,
        line,
        state,
        type_from_group=1,
        type_filter=lambda s: s.upper())

    # Platform specific: Linux gdb crash address format.
    update_state_on_match(
        LINUX_GDB_CRASH_ADDRESS_REGEX, line, state, address_from_group=1)

    # Platform specific: Mac gdb style crash address format.
    update_state_on_match(
        MAC_GDB_CRASH_ADDRESS_REGEX, line, state, address_from_group=1)

    # Platform specific: Windows cdb style crash type and address format.
    if update_state_on_match(
        WINDOWS_CDB_CRASH_TYPE_ADDRESS_REGEX,
        line,
        state,
        type_from_group=1,
        address_from_group=2,
        type_filter=lambda s: s.upper()):
      # Use a consistent format for CDB stacks.
      state.crash_address = '0x%s' % state.crash_address

    # MemorySanitizer / ThreadSanitizer crashes.
    # Make sure to skip the end marker |SUMMARY:|.
    if ' suppressions' not in line and ' warnings' not in line:
      update_state_on_match(
          MSAN_TSAN_REGEX,
          line,
          state,
          reset=True,
          tool_from_group=1,
          type_from_group=2,
          type_filter=lambda s: s.capitalize())

    # LSan can report multiple stacks, so do not clear existing state unless
    # this is a report for an indirect leak. Direct leaks are higher priority.
    if not state.crash_type or state.crash_type == 'Indirect-leak':
      update_state_on_match(
          LSAN_DIRECT_LEAK_REGEX,
          line,
          state,
          new_type='Direct-leak',
          reset=True)

    # It's possible that we have a cycle that causes us to only detect
    # indirect leaks, and LSan reports them after any direct leaks. If an
    # indirect leak accompanies a direct leak, we don't care about it.
    if not state.crash_type:
      update_state_on_match(
          LSAN_INDIRECT_LEAK_REGEX,
          line,
          state,
          new_type='Indirect-leak',
          reset=True)

    # UndefinedBehavior Sanitizer VPTR (bad-cast) crash.
    if not state.crash_type:
      ubsan_vptr_match = update_state_on_match(
          UBSAN_VPTR_REGEX,
          line,
          state,
          new_type='Bad-cast',
          new_frame_count=0,
          address_from_group=3)
      if ubsan_vptr_match:
        state.crash_state = 'Bad-cast to %s' % (
            ubsan_vptr_match.group(4)).strip("'")
        state.found_bad_cast_crash_end_marker = False

    # Get source type information for bad-cast.
    if (state.crash_type == 'Bad-cast' and
        not state.found_bad_cast_crash_end_marker):
      downcast_match = UBSAN_VPTR_INVALID_DOWNCAST_REGEX.match(line)
      if not downcast_match:
        downcast_match = CFI_INVALID_DOWNCAST_REGEX.match(line)
      if downcast_match:
        state.crash_state += ' from %s' % (downcast_match.group(1)).strip("'")
        state.found_bad_cast_crash_end_marker = True

      if (UBSAN_VPTR_INVALID_VPTR_REGEX.match(line) or
          CFI_INVALID_VPTR_REGEX.match(line)):
        state.crash_state += ' from invalid vptr'
        state.found_bad_cast_crash_end_marker = True

      # Ubsan's -fsanitize=vptr crash extra info for member access.
      invalid_offset_match = UBSAN_VPTR_INVALID_OFFSET_REGEX.match(line)
      if invalid_offset_match:
        state.crash_state += (' from base class subobject at offset %s' %
                              invalid_offset_match.group(1))
        state.found_bad_cast_crash_end_marker = True

      if state.found_bad_cast_crash_end_marker:
        state.crash_state += '\n'
        state.frame_count += 1

    # CFI bad-cast crash.
    if not state.crash_type:
      cfi_bad_cast_match = update_state_on_match(
          CFI_ERROR_REGEX,
          line,
          state,
          new_type='Bad-cast',
          new_frame_count=0,
          address_from_group=4)
      if cfi_bad_cast_match:
        state.crash_state = 'Bad-cast to %s' % (
            cfi_bad_cast_match.group(2).strip("'"))
        state.found_bad_cast_crash_end_marker = False

    # CFI bad-cast crash without extra debugging information.
    if not state.crash_type:
      update_state_on_match(
          CFI_NODEBUG_ERROR_MARKER_REGEX,
          line,
          state,
          new_type='Bad-cast',
          new_frame_count=0)

    # Other UndefinedBehavior Sanitizer crash.
    ubsan_runtime_match = UBSAN_RUNTIME_ERROR_REGEX.match(line)
    if ubsan_runtime_match and not state.crash_type:
      reason = ubsan_runtime_match.group(2)
      state.crash_type = 'UNKNOWN'

      for ubsan_crash_regex, ubsan_crash_type in UBSAN_CRASH_TYPES_MAP:
        update_state_on_match(
            ubsan_crash_regex, reason, state, new_type=ubsan_crash_type)

      state.crash_address = ''
      state.crash_state = ''
      state.frame_count = 0

    # AddressSanitizer for memory overlap crash.
    update_state_on_match(
        ASAN_MEMCPY_OVERLAP_REGEX,
        line,
        state,
        new_type='Memcpy-param-overlap',
        reset=True,
        address_from_group=2)

    # Sanitizer SEGV crashes.
    segv_match = SAN_SEGV_REGEX.match(line)
    if segv_match:
      temp_crash_address = segv_match.group(3)
      if 'ASSERT' in state.crash_type:
        # We usually use the last crash from the stacktrace for the crash
        # state, but when we see an UNKNOWN crash triggered by an ASSERT, we
        # don't want to overwrite the type, state, and address.
        int_crash_address = crash_analyzer.address_to_integer(
            temp_crash_address)
        if (crash_analyzer.is_assert_crash_address(int_crash_address) or
            SAN_SIGNAL_REGEX.match(crash_data)):
          continue

      state.crash_type = 'UNKNOWN'
      state.crash_address = temp_crash_address
      state.crash_state = ''
      state.frame_count = 0
      continue

    # AddressSanitizer free on non malloc()-ed address.
    if update_state_on_match(
        ASAN_BAD_FREE_REGEX,
        line,
        state,
        new_type='Bad-free',
        reset=True,
        address_from_group=1):
      continue

    # AddressSanitizer double free crash.
    if update_state_on_match(
        ASAN_DOUBLE_FREE_REGEX,
        line,
        state,
        new_type='Heap-double-free',
        reset=True,
        address_from_group=3):
      continue

    # Sanitizer floating point exception.
    if update_state_on_match(
        SAN_FPE_REGEX,
        line,
        state,
        new_type='Floating-point-exception',
        reset=True):
      continue

    # Sanitizer regular crash (includes ills, abrt, etc).
    update_state_on_match(
        SAN_ADDR_REGEX,
        line,
        state,
        type_from_group=2,
        address_from_group=4,
        reset=True,
        type_filter=fix_sanitizer_crash_type)

    # Overwrite Unknown-crash type with more generic UNKNOWN type.
    if state.crash_type == 'Unknown-crash':
      state.crash_type = 'UNKNOWN'

    # Sanitizer SEGV type for unknown crashes.
    segv_type_match = SAN_SEGV_CRASH_TYPE_REGEX.match(line)
    if segv_type_match and state.crash_type == 'UNKNOWN':
      segv_type = segv_type_match.group(1)
      if segv_type != 'UNKNOWN':
        state.crash_type += ' ' + segv_type

    # Sanitizer crash type and address format.
    crash_type_and_address_match = update_state_on_match(
        SAN_CRASH_TYPE_ADDRESS_REGEX, line, state, address_from_group=3)
    if crash_type_and_address_match and not state.crash_type.startswith(
        'UNKNOWN'):
      state.crash_type += '\n%s %s' % (crash_type_and_address_match.group(
          1).upper(), crash_type_and_address_match.group(2))

    # Android SEGVs.
    # Exclude fatal signal lines from resetting state when we already have one.
    # Fatal signal lines can often follow the same stack we already processed
    # before. If we process these, we will lose the crash state.
    state_needs_change = (not state.crash_type.startswith('UNKNOWN') or
                          'Fatal signal' not in line)
    if state_needs_change:
      android_segv_match = update_state_on_match(
          ANDROID_SEGV_REGEX, line, state, new_type='UNKNOWN', reset=True)
      if android_segv_match:
        state.found_java_exception = False

        # Set the crash address for SEGVs.
        if 'SIGSEGV' in line:
          state.crash_address = android_segv_match.group(1)
          if not state.crash_address.startswith('0x'):
            state.crash_address = '0x%s' % state.crash_address

        # Set process name (if available).
        process_name_match = ANDROID_PROCESS_NAME_REGEX.match(
            android_segv_match.group(2))
        if process_name_match:
          state.process_name = process_name_match.group(1).capitalize()

    # Android SIGABRT handling.
    android_abort_match = update_state_on_match(
        ANDROID_ABORT_REGEX,
        line,
        state,
        new_type='CHECK failure',
        new_address='')
    if android_abort_match:
      state.found_java_exception = True
      abort_string = android_abort_match.group(1)
      parts = abort_string.split(' ', 1)
      if len(parts) == 2:
        check_failure_string = parts[1]
        filename_without_fatal = parts[0].replace('FATAL:', '')
        stack_frame = '%s in %s' % (fix_check_failure_string(
            check_failure_string), fix_filename_string(filename_without_fatal))
      else:
        stack_frame = fix_check_failure_string(abort_string)
      state.crash_state = stack_frame + '\n'
      state.frame_count = 1

    # Android Kernel Errors are only checked if KASan isn't supported for this
    # job type. They can potentially overwrite the KASan report which contains
    # more useful information.
    if not environment.get_value('KASAN'):
      update_state_on_match(
          ANDROID_KERNEL_ERROR_REGEX,
          line,
          state,
          new_type='Kernel failure',
          reset=True,
          type_from_group=3,
          type_filter=get_fault_description_for_android_kernel)

    # Generic KASan errors.
    if update_state_on_match(
        KASAN_CRASH_TYPE_ADDRESS_REGEX,
        line,
        state,
        type_from_group=1,
        address_from_group=4,
        type_filter=filter_kasan_crash_type):
      state.crash_address = '0x%s' % state.crash_address

    # KASan GPFs.
    update_state_on_match(
        KASAN_GPF_REGEX,
        line,
        state,
        new_type='Kernel failure\nGeneral-protection-fault')

    # For KASan crashes, additional information about a bad access may come
    # from a later line. Update the type if this happens.
    if state.crash_type.startswith('Kernel failure'):
      kasan_access_match = KASAN_ACCESS_TYPE_REGEX.match(line)
      if kasan_access_match:
        state.crash_type += ' %s %s' % (kasan_access_match.group(1).upper(),
                                        kasan_access_match.group(2))

    # Sanitizer tool check failure.
    san_check_match = update_state_on_match(
        SAN_CHECK_FAILURE_REGEX,
        line,
        state,
        new_type='Sanitizer CHECK failure',
        new_address='',
        new_frame_count=MAX_CRASH_STATE_FRAMES)
    if san_check_match:
      state.crash_state = '%s\n' % san_check_match.group(1)
      state.process_died = True
      continue

    # Security check failures.
    update_state_on_check_failure(state, line, SECURITY_CHECK_FAILURE_REGEX,
                                  'Security CHECK failure')
    update_state_on_check_failure(state, line, SECURITY_DCHECK_FAILURE_REGEX,
                                  'Security DCHECK failure')

    # Timeout/OOM detected by libFuzzer.
    if detect_ooms_and_hangs:
      update_state_on_match(
          LIBFUZZER_TIMEOUT_REGEX, line, state, new_type='Timeout', reset=True)
      update_state_on_match(
          OUT_OF_MEMORY_REGEX,
          line,
          state,
          new_type='Out-of-memory',
          reset=True)

    # The following parsing signatures don't lead to crash state overwrites.
    if not state.crash_type:
      # Windows cdb stack overflow.
      update_state_on_match(
          WINDOWS_CDB_STACK_OVERFLOW_REGEX,
          line,
          state,
          new_type='Stack-overflow')

      # Windows cdb generic type regex.
      update_state_on_match(
          WINDOWS_CDB_CRASH_TYPE_REGEX,
          line,
          state,
          type_from_group=1,
          type_filter=fix_win_cdb_crash_type)

      # Generic ASan regex.
      update_state_on_match(
          ASAN_REGEX,
          line,
          state,
          reset=True,
          type_from_group=2,
          type_filter=fix_sanitizer_crash_type)

      # Android fatal exceptions.
      if update_state_on_match(
          ANDROID_FATAL_EXCEPTION_REGEX,
          line,
          state,
          new_type='Fatal Exception',
          reset=True):
        state.found_java_exception = True

      # Check failures.
      update_state_on_check_failure(state, line, CHECK_FAILURE_REGEX,
                                    'CHECK failure')

      # V8 fatal errors.
      fatal_error_match = update_state_on_match(
          FATAL_ERROR_REGEX, line, state, new_type='Fatal error', reset=True)
      if fatal_error_match:
        state.crash_state = filter_stack_frame(fatal_error_match.group(1))
        state.fatal_error_occurred = True

      # V8 runtime errors.
      if detect_v8_runtime_errors:
        runtime_error_match = (
            update_state_on_match(
                RUNTIME_ERROR_REGEX,
                line,
                state,
                new_type='RUNTIME_ASSERT',
                reset=True))
        if runtime_error_match:
          state.crash_state = filter_stack_frame(runtime_error_match.group(1))
          state.fatal_error_occurred = True

      # V8 abort errors.
      abort_error_match = update_state_on_match(
          V8_ABORT_FAILURE_REGEX, line, state, new_type='ASSERT', reset=True)
      if abort_error_match:
        abort_error = abort_error_match.group(1)
        match = V8_ABORT_METADATA_REGEX.match(abort_error)
        if match:
          abort_error = match.group(1)
          abort_filename = fix_filename_string(match.group(2))
          state.crash_state = '%s\n%s' % (abort_error, abort_filename)
        else:
          state.crash_state = abort_error
        state.frame_count = MAX_CRASH_STATE_FRAMES

      # V8 correctness failure errors.
      update_state_on_match(
          V8_CORRECTNESS_FAILURE_REGEX,
          line,
          state,
          new_type='V8 correctness failure',
          reset=True)

      # Generic SEGV handler errors.
      update_state_on_match(
          GENERIC_SEGV_HANDLER_REGEX,
          line,
          state,
          new_type='UNKNOWN',
          address_from_group=1,
          address_filter=lambda s: '0x' + s,
          reset=True)

    if state.fatal_error_occurred:
      error_line_match = update_state_on_match(
          FATAL_ERROR_LINE_REGEX, line, state, new_type='Fatal error')
      if not error_line_match and detect_v8_runtime_errors:
        error_line_match = update_state_on_match(
            RUNTIME_ERROR_LINE_REGEX, line, state, new_type='RUNTIME_ASSERT')

      if error_line_match:
        state.check_failure_source_file = fix_filename_string(
            error_line_match.group(1))
        state.crash_state = '%s\n' % state.check_failure_source_file
        continue

      if state.check_failure_source_file:
        # Generic fatal errors should be replaced by CHECK failures.
        check_failure_match = update_state_on_match(
            FATAL_ERROR_DCHECK_FAILURE,
            line,
            state,
            new_type='DCHECK failure',
            reset=True)

        if not check_failure_match:
          new_type = state.crash_type
          if state.crash_type == 'Fatal error':
            new_type = 'CHECK failure'
          check_failure_match = update_state_on_match(
              FATAL_ERROR_CHECK_FAILURE,
              line,
              state,
              new_type=new_type,
              reset=True)

        if check_failure_match and check_failure_match.group(2).strip():
          failure_string = fix_check_failure_string(
              check_failure_match.group(2))
          state.crash_state = '%s in %s\n' % (failure_string,
                                              state.check_failure_source_file)
          state.frame_count = 1

        new_state = '%s\n' % state.check_failure_source_file
        update_state_on_match(
            FATAL_ERROR_UNREACHABLE,
            line,
            state,
            new_state=new_state,
            new_type='Unreachable code',
            reset=True)

    # Check cases with unusual stack start markers.
    update_state_on_match(
        WINDOWS_CDB_STACK_START_REGEX,
        line,
        state,
        new_state='',
        new_frame_count=0)

    # Stack frame parsing signatures.
    # Don't allow more stack frames if a certain stop marker is seen.
    if (state.crash_state and
        utils.sub_string_exists_in(STATE_STOP_MARKERS, line)):
      state.frame_count = MAX_CRASH_STATE_FRAMES
      continue

    # No stack frame parsing required until we get a crash type.
    if not state.crash_type:
      continue

    # For JNI errors, don't use stack frames for crash state from art/runtime,
    # since it helps to do testcase de-duplication.
    if JNI_ERROR_STRING in state.crash_state and '/art/runtime/' in line:
      continue

    # Timeouts/OOMs.
    if state.crash_type == 'Timeout' or state.crash_type == 'Out-of-memory':
      add_frame_on_match(
          CUSTOM_CRASH_STATE_REGEX, line, state, group=1, can_ignore=False)
      continue

    # Platform specific: Windows cdb style stack frame.
    if add_frame_on_match(
        WINDOWS_CDB_STACK_FRAME_REGEX,
        line,
        state,
        group=4,
        frame_spec=WINDOWS_CDB_STACK_FRAME_SPEC):
      continue

    # Platform specific: Linux and mac gdb, ASAN, MSAN, UBSAN style
    # stack frame. Try the regex with symbols first i.e. with
    # addresses and function names.
    if add_frame_on_match(
        SAN_STACK_FRAME_REGEX,
        line,
        state,
        group=3,
        frame_spec=SAN_STACK_FRAME_SPEC,
        frame_override_func=llvm_test_one_input_override):
      continue

    # Chrome symbolized stack frame regex.
    if add_frame_on_match(
        CHROME_STACK_FRAME_REGEX,
        line,
        state,
        group=4,
        frame_spec=CHROME_STACK_FRAME_SPEC):
      continue

    # Chrome symbolized stack frame regex (Mac only).
    if add_frame_on_match(
        CHROME_MAC_STACK_FRAME_REGEX,
        line,
        state,
        group=6,
        demangle=True,
        frame_spec=CHROME_MAC_STACK_FRAME_SPEC):
      continue

    # Chrome symbolized stack frame regex (Windows only).
    if add_frame_on_match(
        CHROME_WIN_STACK_FRAME_REGEX,
        line,
        state,
        group=1,
        frame_spec=CHROME_WIN_STACK_FRAME_SPEC):
      continue

    # Android java exception stack frames.
    if (state.found_java_exception and
        state.crash_type in ['CHECK failure', 'Fatal Exception'] and
        add_frame_on_match(
            JAVA_EXCEPTION_CRASH_STATE_REGEX, line, state, group=1)):
      continue

    # Android kernel stack frame.
    android_kernel_match = add_frame_on_match(
        ANDROID_KERNEL_STACK_FRAME_REGEX, line, state, group=2)
    if android_kernel_match:
      # Update address from the first stack frame unless we already have
      # more detailed information from KASan.
      if state.frame_count == 1 and not environment.get_value('KASAN'):
        state.crash_address = '0x%s' % android_kernel_match.group(1)
      continue

    # V8 correctness fuzzer metadata.
    if add_frame_on_match(
        V8_CORRECTNESS_METADATA_REGEX,
        line,
        state,
        group=1,
        frame_filter=lambda s: s):
      continue

  # Detect cycles in stack overflow bugs and update crash state.
  update_crash_state_for_stack_overflow_if_needed(state)

  # Convert crash parameters into a generic format regardless of the tool used.
  filter_crash_parameters(state)

  return state
