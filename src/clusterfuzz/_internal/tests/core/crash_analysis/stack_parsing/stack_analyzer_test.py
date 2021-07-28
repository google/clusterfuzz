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
"""Tests for the stack analyzer module."""

import os
import unittest

from clusterfuzz._internal.crash_analysis import crash_analyzer
from clusterfuzz._internal.crash_analysis.stack_parsing import stack_analyzer
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.tests.test_libs import helpers

DATA_DIRECTORY = os.path.join(os.path.dirname(__file__), 'stack_analyzer_data')
TEST_JOB_NAME = 'test'


class StackAnalyzerTestcase(unittest.TestCase):
  """Stack analyzer tests."""

  # pylint: disable=unused-argument
  @staticmethod
  def _mock_symbolize_stacktrace(stacktrace, enable_inline_frames=True):
    """No-op mocked version of symbolize_stacktrace."""
    return stacktrace

  # pylint: enable=unused-argument

  def setUp(self):
    """Set environment variables used by stack analyzer tests."""
    helpers.patch_environ(self)
    helpers.patch(self, [
        'clusterfuzz._internal.crash_analysis.stack_parsing.stack_symbolizer.'
        'symbolize_stacktrace', 'clusterfuzz._internal.metrics.logs.log_error',
        'clusterfuzz._internal.platforms.android.kernel_utils.'
        'get_kernel_prefix_and_full_hash'
    ])

    os.environ['JOB_NAME'] = TEST_JOB_NAME

    self.mock.symbolize_stacktrace.side_effect = self._mock_symbolize_stacktrace
    self.mock.get_kernel_prefix_and_full_hash.return_value = None, None

  def _read_test_data(self, name):
    """Helper function to read test data."""
    with open(os.path.join(DATA_DIRECTORY, name)) as handle:
      return handle.read()

  def _validate_get_crash_data(self, data, expected_type, expected_address,
                               expected_state, expected_stacktrace,
                               expected_security_flag):
    """Test all outputs from a call to get_crash_data."""
    actual_state = stack_analyzer.get_crash_data(data)
    actual_security_flag = crash_analyzer.is_security_issue(
        data, actual_state.crash_type, actual_state.crash_address)

    self.assertEqual(actual_state.crash_type, expected_type)
    self.assertEqual(actual_state.crash_address, expected_address)
    self.assertEqual(actual_state.crash_state, expected_state)

    self.assertEqual(actual_state.crash_stacktrace, expected_stacktrace)
    self.assertEqual(actual_security_flag, expected_security_flag)

  def test_symbolized_asan_null_dereference(self):
    """Test for a Null-dereference derived from a simple symbolized ASan
    report."""
    data = self._read_test_data('symbolized_asan_null_dereference.txt')
    expected_type = 'Null-dereference'
    expected_address = '0x000000000018'
    expected_state = ('blink::FontMetrics::ascent\n'
                      'blink::RenderListMarker::updateMargins\n'
                      'blink::RenderListItem::updateMarkerLocation\n')
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_symbolized_asan_unknown(self):
    """Test for a simple symbolized ASan report."""
    data = self._read_test_data('symbolized_asan_unknown.txt')
    expected_type = 'UNKNOWN'
    expected_address = '0x000000010018'
    expected_state = ('blink::FontMetrics::ascent\n'
                      'blink::RenderListMarker::updateMargins\n'
                      'blink::RenderListItem::updateMarkerLocation\n')
    expected_stacktrace = data
    expected_security_flag = True

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_address_in_state(self):
    """Test for an unsymbolized ASan report."""
    data = self._read_test_data('address_in_state.txt')
    expected_state = 'GetHandleVerifier\n' * 3

    actual_state = stack_analyzer.get_crash_data(data)
    self.assertEqual(actual_state.crash_state, expected_state)

  def test_variable_length_write(self):
    """Test that large writes are replaced with {*}."""
    data = self._read_test_data('variable_length_write.txt')
    expected_type = 'Stack-use-after-return\nWRITE {*}'

    actual_state = stack_analyzer.get_crash_data(data)
    self.assertEqual(actual_state.crash_type, expected_type)

  def test_android_asan_null_dereference_read(self):
    """Test for a Null-dereference READ derived from ASan UNKNOWN READ."""
    data = self._read_test_data('android_asan_null_dereference_read.txt')
    expected_type = 'Null-dereference READ'
    expected_address = '0x00000011'
    expected_state = ('_JavaVM::AttachCurrentThread\n'
                      'javaAttachThread\n'
                      'android::AndroidRuntime::javaThreadShell\n')
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_android_asan_null_dereference_write(self):
    """Test for a Null-dereference WRITE derived from ASan UNKNOWN WRITE."""
    data = self._read_test_data('android_asan_null_dereference_write.txt')
    expected_type = 'Null-dereference WRITE'
    expected_address = '0x00000011'
    expected_state = ('_JavaVM::AttachCurrentThread\n'
                      'javaAttachThread\n'
                      'android::AndroidRuntime::javaThreadShell\n')
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_android_asan_uaf(self):
    """Basic test for Android ASAN format."""
    data = self._read_test_data('android_asan_uaf.txt')
    expected_type = 'Heap-use-after-free\nREAD 2'
    expected_address = '0xac80d400'
    expected_state = ('android::AString::setTo\n'
                      'android::AString::AString\n'
                      'android::MediaHTTP::connect\n')
    expected_stacktrace = data
    expected_security_flag = True

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_android_asan_unknown_read(self):
    """Test for an ASan UNKNOWN READ report."""
    data = self._read_test_data('android_asan_unknown_read.txt')
    expected_type = 'UNKNOWN READ'
    expected_address = '0x74000011'
    expected_state = ('_JavaVM::AttachCurrentThread\n'
                      'javaAttachThread\n'
                      'android::AndroidRuntime::javaThreadShell\n')
    expected_stacktrace = data
    expected_security_flag = True

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_android_asan_unknown_write(self):
    """Test for an ASan UNKNOWN WRITE report."""
    data = self._read_test_data('android_asan_unknown_write.txt')
    expected_type = 'UNKNOWN WRITE'
    expected_address = '0x74000011'
    expected_state = ('_JavaVM::AttachCurrentThread\n'
                      'javaAttachThread\n'
                      'android::AndroidRuntime::javaThreadShell\n')
    expected_stacktrace = data
    expected_security_flag = True

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_android_kernel(self):
    """Basic test for Android kernel format."""
    data = self._read_test_data('android_kernel.txt')
    expected_type = 'Kernel failure\nREAD Translation Fault, Section (5)'
    expected_address = '0x12345678'
    expected_state = ('top_frame\nnext_frame\nlast_frame\n')
    expected_stacktrace = data
    expected_security_flag = True

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_android_kernel_no_parens(self):
    """Basic test for Android kernel format with a slightly different stacktrace
    format (no parentheses)."""
    data = self._read_test_data('android_kernel_no_parens.txt')
    expected_type = 'Kernel failure\nREAD Translation Fault, Section (5)'
    expected_address = '0x12345678'
    expected_state = ('top_frame\nnext_frame\nlast_frame\n')
    expected_stacktrace = data
    expected_security_flag = True

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_android_null_stack(self):
    """Test for a null state."""
    data = self._read_test_data('android_null_stack.txt')
    expected_type = 'UNKNOWN'
    expected_address = '0xb6e43000'
    expected_state = 'Surfaceflinger\n'
    expected_stacktrace = data
    expected_security_flag = True

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_unknown_module(self):
    """Test state the format for crashes where we only have an address."""
    data = self._read_test_data('unknown_module.txt')
    expected_state = 'NULL'

    actual_state = stack_analyzer.get_crash_data(data)
    self.assertEqual(actual_state.crash_state, expected_state)

  def test_ubsan_bad_cast_downcast(self):
    """Test the ubsan bad cast downcast format."""
    data = self._read_test_data('ubsan_bad_cast_downcast.txt')
    expected_type = 'Bad-cast'
    expected_address = '0x2aa9a6abc480'
    expected_state = ('Bad-cast to blink::AXMenuList from blink::AXList\n'
                      'blink::RenderMenuList::didUpdateActiveOption\n'
                      'blink::RenderMenuList::setTextFromOption\n')
    expected_stacktrace = data
    expected_security_flag = True

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_ubsan_bad_cast_member_call(self):
    """Test the ubsan bad cast member call format."""
    data = self._read_test_data('ubsan_bad_cast_member_call.txt')
    expected_type = 'Bad-cast'
    expected_address = '0x15577a7fc900'
    expected_state = ('Bad-cast to net::QuicSpdySession from net::QuicSession\n'
                      'net::QuicSpdyStream::~QuicSpdyStream\n'
                      'net::QuicChromiumClientStream::~QuicChromiumClientStream'
                      '\n')
    expected_stacktrace = data
    expected_security_flag = True

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_ubsan_divide_by_zero(self):
    """Test the ubsan division by zero format."""
    data = self._read_test_data('ubsan_divide_by_zero.txt')
    expected_type = 'Divide-by-zero'
    expected_state = ('mpeg_decode_postinit\n'
                      'decode_chunks\n'
                      'mpeg_decode_frame\n')
    expected_address = ''
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_ubsan_incorrect_function_pointer_type(self):
    """Test the ubsan incorrect function pointer type format."""
    data = self._read_test_data('ubsan_incorrect_function_pointer_type.txt')
    expected_type = 'Incorrect-function-pointer-type'
    expected_address = ''
    expected_state = ('gl::GetGLProcAddress\n'
                      'gl::DriverGL::InitializeStaticBindings\n'
                      'gl::InitializeStaticGLBindingsGL\n')
    expected_stacktrace = data
    expected_security_flag = True

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_ubsan_index_oob(self):
    """Test the ubsan index out-of-bounds format."""
    data = self._read_test_data('ubsan_index_oob.txt')
    expected_type = 'Index-out-of-bounds'
    expected_address = ''
    expected_state = ('CPDF_StreamParser::ParseNextElement\n'
                      'CPDF_StreamContentParser::Parse\n'
                      'CPDF_ContentParser::Continue\n')
    expected_stacktrace = data
    expected_security_flag = True

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_ubsan_integer_overflow_addition(self):
    """Test the ubsan integer overflow due to addition format."""
    data = self._read_test_data('ubsan_integer_overflow_addition.txt')
    expected_type = 'Integer-overflow'
    expected_address = ''
    expected_state = ('gfx::Point::operator+=\n'
                      'gfx::Rect::Inset\n'
                      'cc::PictureLayerTiling::ComputeTilePriorityRects\n')
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_ubsan_integer_overflow_negation(self):
    """Test the ubsan integer overflow due to negation format."""
    data = self._read_test_data('ubsan_integer_overflow_negation.txt')
    expected_type = 'Integer-overflow'
    expected_address = ''
    expected_state = ('blink::CSSSelectorParser::consumeANPlusB\n'
                      'blink::CSSSelectorParser::consumePseudo\n'
                      'blink::CSSSelectorParser::consumeSimpleSelector\n')
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_ubsan_invalid_bool_value(self):
    """Test the ubsan bool format."""
    data = self._read_test_data('ubsan_invalid_bool_value.txt')
    expected_type = 'Invalid-bool-value'
    expected_state = ('tsm_screen_tab_left\nparse_data\ntsm_vte_input\n')
    expected_address = ''
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_ubsan_misaligned_address(self):
    """Test the ubsan alignment format."""
    data = self._read_test_data('ubsan_misaligned_address.txt')
    expected_type = 'Misaligned-address'
    expected_state = ('pnm_decode_frame\n'
                      'decode_simple_internal\n'
                      'decode_simple_receive_frame\n')
    expected_address = ''
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_ubsan_non_positive_vla_bound_value(self):
    """Test the ubsan non-positive variable length array bound format."""
    data = self._read_test_data('ubsan_non_positive_vla_bound_value.txt')
    expected_type = 'Non-positive-vla-bound-value'
    expected_address = ''
    expected_state = ('boom_internal\nanother_boom\nboom\n')
    expected_stacktrace = data
    expected_security_flag = True

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_ubsan_null_pointer_member_access(self):
    """Test the ubsan null format for member access within null pointer."""
    data = self._read_test_data('ubsan_null_pointer_member_access.txt')
    expected_type = 'Null-dereference'
    expected_state = ('xmlFAParseCharClassEsc\n'
                      'xmlFAParseAtom\n'
                      'xmlFAParsePiece\n')
    expected_address = ''
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_ubsan_null_pointer_member_call(self):
    """Test the ubsan null format for member call on null pointer."""
    data = self._read_test_data('ubsan_null_pointer_member_call.txt')
    expected_type = 'Null-dereference'
    expected_state = (
        'base::trace_event::internal::HeapDumpWriter::AddEntryForBucket\n'
        'base::trace_event::internal::HeapDumpWriter::Summarize\n'
        'base::trace_event::ExportHeapDump\n')
    expected_address = ''
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_ubsan_null_pointer_read(self):
    """Test the ubsan null format for load of null pointer."""
    data = self._read_test_data('ubsan_null_pointer_read.txt')
    expected_type = 'Null-dereference READ'
    expected_state = ('SHPReadOGRObject\n'
                      'SHPReadOGRFeature\n'
                      'OGRShapeLayer::GetNextFeature\n')
    expected_address = ''
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_ubsan_null_pointer_reference_binding(self):
    """Test the ubsan null format for reference binding to null pointer."""
    data = self._read_test_data('ubsan_null_pointer_reference_binding.txt')
    expected_type = 'Null-dereference'
    expected_state = ('woff2::ConvertWOFF2ToTTF\n'
                      'convert_woff2ttf_fuzzer.cc\n')
    expected_address = ''
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_ubsan_null_pointer_write(self):
    """Test the ubsan null format for store to null pointer."""
    data = self._read_test_data('ubsan_null_pointer_write.txt')
    expected_type = 'Null-dereference WRITE'
    expected_state = ('SHPReadOGRObject\n'
                      'SHPReadOGRFeature\n'
                      'OGRShapeLayer::GetNextFeature\n')
    expected_address = ''
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_ubsan_object_size(self):
    """Test the ubsan object-size format."""
    data = self._read_test_data('ubsan_object_size.txt')
    expected_type = 'Object-size'
    expected_address = ''
    expected_state = ('boom_internal\nanother_boom\nboom\n')
    expected_stacktrace = data
    expected_security_flag = True

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_ubsan_pointer_overflow(self):
    """Test the ubsan pointer overflow format."""
    data = self._read_test_data('ubsan_pointer_overflow.txt')
    expected_type = 'Pointer-overflow'
    expected_address = ''
    expected_state = ('SkRasterPipelineBlitter::blitMask\n'
                      'blitClippedMask\n'
                      'draw_nine_clipped\n')
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_ubsan_pointer_overflow_null_zero_offset(self):
    """Test the null pointer with zero offset case for pointer overflow."""
    data = self._read_test_data('ubsan_pointer_overflow_null_zero_offset.txt')
    expected_type = 'Pointer-overflow'
    expected_address = ''
    expected_state = ('cff_subfont_load\ncff_font_load\ncff_face_init\n')
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_ubsan_pointer_overflow_null_nonzero_offset(self):
    """Test the null pointer with nonzero offset case for pointer overflow."""
    data = self._read_test_data(
        'ubsan_pointer_overflow_null_nonzero_offset.txt')
    expected_type = 'Pointer-overflow'
    expected_address = ''
    expected_state = ('courgette::DisassemblerWin32::ParseRelocs\n'
                      'courgette::DisassemblerWin32::ExtractAbs32Locations\n'
                      'courgette::Disassembler::CreateProgram\n')
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_java_exception(self):
    """Tests for Java exceptions found by Jazzer."""
    data = self._read_test_data('java_IllegalStateException.txt')
    expected_type = 'Uncaught exception'
    expected_address = ''
    expected_state = ('ExampleValueProfileFuzzer.mustNeverBeCalled\n'
                      'ExampleValueProfileFuzzer.fuzzerTestOneInput\n')

    expected_stacktrace = data
    expected_security_flag = False
    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_java_manual_security_exception(self):
    """Tests for Java exceptions manually marked as security issues."""
    data = self._read_test_data('java_severity_medium_exception.txt')
    expected_type = 'Uncaught exception'
    expected_address = ''
    expected_state = ('com.example.JsonSanitizerFuzzer.fuzzerTestOneInput\n'
                      'com.google.gson.Gson.fromJson\n'
                      'com.google.gson.Gson.fromJson\n')

    expected_stacktrace = data
    expected_security_flag = True
    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_java_fatal_exception(self):
    """Test for the java fatal exception format."""
    data = self._read_test_data('java_fatal_exception.txt')
    expected_type = 'Fatal Exception'
    expected_address = ''
    expected_state = ('java.util.ArrayList$ArrayListIterator.next\n'
                      'com.android.systemui.statusbar.policy.'
                      'SecurityControllerImpl.fireCallbacks\n'
                      'com.android.systemui.statusbar.policy.'
                      'SecurityControllerImpl.-wrap0\n')
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_msan_uninitialized_value(self):
    """Test the MSan uninitialized value format."""
    data = self._read_test_data('msan_uninitialized_value.txt')
    expected_type = 'Use-of-uninitialized-value'
    expected_address = ''
    expected_state = (
        'content::BrowserMessageFilter::Send\n'
        'ChromeNetBenchmarkingMessageFilter::OnMessageReceived\n'
        'content::BrowserMessageFilter::Internal::OnMessageReceived\n')
    expected_stacktrace = data
    expected_security_flag = True

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_tsan_data_race(self):
    """Test the TSan data race format."""
    data = self._read_test_data('tsan_data_race.txt')
    expected_type = 'Data race\nWRITE 4'
    expected_address = '0x7f15d580f30c'
    expected_state = ('sqlite3StatusSet\n'
                      'pcache1Alloc\n'
                      'pcache1AllocPage\n')
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_assert(self):
    """Test the Blink assertion failure format."""
    environment.set_value('ASSERTS_HAVE_SECURITY_IMPLICATION', False)

    data = self._read_test_data('assert.txt')
    expected_type = 'ASSERT'
    expected_address = ''
    expected_state = ('start.compareTo(end) <= 0\n'
                      'void blink::normalizePositionsAlgorithm'
                      '<blink::PositionAlgorithm<blink::EditingS\n'
                      'blink::VisibleSelection::normalizePositions\n')
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_stack_filtering(self):
    """Test ignore lists and stack frame filtering."""
    data = self._read_test_data('stack_filtering.txt')
    expected_state = ('base::OnTotallyStillHaveMemory\n'
                      'content::ChildDiscardableSharedMemoryManager::'
                      'AllocateLockedDiscardableSharedMemory\n'
                      'content::ChildDiscardableSharedMemoryManager::'
                      'AllocateLockedDiscardableMemory\n')

    actual_state = stack_analyzer.get_crash_data(data, symbolize_flag=False)
    self.assertEqual(actual_state.crash_state, expected_state)

  def test_ignore_abort_frames(self):
    """Test that abort frames are ignored."""
    data = self._read_test_data('ignore_abort_frames.txt')
    expected_type = 'Abrt'
    expected_address = '0x000000000001'
    expected_state = ('nlohmann::basic_json<std::__1::map, std::__1::vector, '
                      'std::__1::basic_string<cha\n'
                      'nlohmann::basic_json<std::__1::map, std::__1::vector, '
                      'std::__1::basic_string<cha\n'
                      'nlohmann::basic_json<std::__1::map, std::__1::vector, '
                      'std::__1::basic_string<cha\n')
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_ignore_honggfuzz(self):
    """Test that frames from honggfuzz wrappers are ignored."""
    data = self._read_test_data('ignore_honggfuzz.txt')
    expected_type = 'Segv on unknown address'
    expected_address = ''
    expected_state = ('function1\nfunction2\nfunction3\n')
    expected_stacktrace = data
    expected_security_flag = True

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_ignore_libc_if_symbolized(self):
    """Test that we ignore certain shared libraries if symbolized."""
    data = self._read_test_data('ignore_libc_if_symbolized.txt')
    expected_state = (
        'blink::LayoutRubyBase::adjustInlineDirectionLineBounds\n'
        'blink::LayoutBlockFlow::updateLogicalWidthForAlignment\n'
        'blink::LayoutBlockFlow::computeInlineDirectionPositionsForSegment\n')

    actual_state = stack_analyzer.get_crash_data(data)

    self.assertEqual(actual_state.crash_state, expected_state)

  def test_ignore_libcplusplus_abi(self):
    """Test that we ignore libc++ frames."""
    data = self._read_test_data('ignore_libcplusplus.txt')
    expected_type = 'Abrt'
    expected_address = '0x7fff94dd7f06'
    expected_state = (
        'sfntly::BitmapSizeTable::Builder::Initialize\n'
        'sfntly::BitmapSizeTable::Builder::GetIndexSubTableBuilders\n'
        'InitializeBitmapBuilder\n')
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_ignore_llvm(self):
    """Test that llvm frames are ignored."""
    data = self._read_test_data('ignore_llvm.txt')
    expected_type = 'Heap-use-after-free\nREAD 8'
    expected_address = '0x6120000746b0'
    expected_state = ('cc::SurfaceManager::UnregisterBeginFrameSource\n'
                      'cc::Display::~Display\n'
                      '~Display\n')
    expected_stacktrace = data
    expected_security_flag = True

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_ignore_sanitizer(self):
    """Test that sanitizer frames are ignored."""
    data = self._read_test_data('ignore_sanitizer.txt')
    expected_type = 'Null-dereference READ'
    expected_address = '0x000000000010'
    expected_state = ('GetHandleVerifier\n'
                      'GetHandleVerifier\n'
                      'GetHandleVerifier\n')
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_ignore_vdso(self):
    """Test that vdso frames are ignored."""
    data = self._read_test_data('ignore_vdso.txt')
    expected_type = 'CHECK failure'
    expected_address = ''
    expected_state = ('static_cast<unsigned>(text_offset + text_length) '
                      '<= text.length() in SimplifiedB\n'
                      'blink::SimplifiedBackwardsTextIteratorAlgorithm'
                      '<blink::EditingAlgorithm<blink::N\n'
                      'blink::SimplifiedBackwardsTextIteratorAlgorithm'
                      '<blink::EditingAlgorithm<blink::N\n')
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_ignore_win_frames(self):
    """Test that sanitizer frames are ignored."""
    data = self._read_test_data('ignore_win_frames.txt')
    expected_type = 'Stack-buffer-overflow\nREAD 1'
    expected_address = '0x00201b12d49f'
    expected_state = ('v8::internal::GenerateSourceString\n'
                      'regexp-builtins.cc\n')
    expected_stacktrace = data
    expected_security_flag = True

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_keep_libc_if_unsymbolized(self):
    """Test that certain libraries are kept for unsymbolized stacks."""
    data = self._read_test_data('keep_libc_if_unsymbolized.txt')
    expected_state = ('/system/lib/libc.so+0x0003a1b0\n'
                      '/system/lib/libc.so+0x000173c1\n'
                      '/system/lib/libc.so+0x00017fd3\n')

    actual_state = stack_analyzer.get_crash_data(data, symbolize_flag=False)

    self.assertEqual(actual_state.crash_state, expected_state)

  def test_v8_check(self):
    """Test the v8 fatal error format."""
    # This logic is fairly similar to that of RUNTIME_ASSERT detection. Ensure
    # that we do not falsely detect CHECKs as RUNTIME_ASSERTs.
    os.environ['DETECT_V8_RUNTIME_ERRORS'] = 'True'

    data = self._read_test_data('v8_check.txt')
    expected_type = 'CHECK failure'
    expected_address = ''
    expected_state = '!IsImpossible(mark_bit) in mark-compact.h\n'
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_v8_check_eq(self):
    """Test the v8 fatal error format on a failed CHECK_EQ."""
    data = self._read_test_data('v8_check_eq.txt')
    expected_type = 'CHECK failure'
    expected_address = ''
    expected_state = 'a == b in verifier.cc\n'
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_v8_check_windows(self):
    """Test the v8 fatal error format on Windows."""
    data = self._read_test_data('v8_check_windows.txt')
    expected_type = 'CHECK failure'
    expected_address = ''
    expected_state = ('!field_type->NowStable() in objects-debug.cc\n')
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_v8_check_security(self):
    """Test the v8 CHECK failure with security implications."""
    os.environ['CHECKS_HAVE_SECURITY_IMPLICATION'] = 'True'

    data = self._read_test_data('v8_check_symbolized.txt')
    expected_type = 'CHECK failure'
    expected_address = ''
    expected_state = (
        'old_target->kind() == new_target->kind() in objects-debug.cc\n'
        'v8::internal::Code::VerifyRecompiledCode\n'
        'ReplaceCode\n')

    expected_stacktrace = data
    expected_security_flag = True

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_v8_check_trap(self):
    """Test v8 CHECK failures that trigger SIGTRAP."""
    data = self._read_test_data('v8_check_trap.txt')
    expected_type = 'CHECK failure'
    expected_address = ''
    expected_state = (
        'interpreter_result.result() == result_compiled in foo.cc\n'
        'v8::internal::wasm::fuzzer::InterpretAndExecuteModule\n'
        'v8::internal::wasm::fuzzer::WasmExecutionFuzzer::FuzzWasmModule\n')

    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_v8_check_no_sourcefile(self):
    """Test v8 CHECK failures without source file information (e.g. from
    official builds)."""
    data = self._read_test_data('v8_check_no_sourcefile.txt')
    expected_type = 'CHECK failure'
    expected_address = ''
    expected_state = (
        'interpreter_result.result() == result_compiled\n'
        'v8::internal::wasm::fuzzer::InterpretAndExecuteModule\n'
        'v8::internal::wasm::fuzzer::WasmExecutionFuzzer::FuzzWasmModule\n')

    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_v8_dcheck(self):
    """Test the v8 DCHECK failure."""
    data = self._read_test_data('v8_dcheck_symbolized.txt')
    expected_type = 'DCHECK failure'
    expected_address = ''
    expected_state = (
        'old_target->kind() == new_target->kind() in objects-debug.cc\n'
        'v8::internal::Code::VerifyRecompiledCode\n'
        'ReplaceCode\n')

    expected_stacktrace = data
    expected_security_flag = True

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_v8_fatal_error_no_check(self):
    """Test the v8 fatal error format for non-CHECK failures."""
    data = self._read_test_data('v8_fatal_error_no_check.txt')
    expected_type = 'Fatal error'
    expected_address = ''
    expected_state = 'Cannot create a handle without a HandleScope\n'
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_v8_fatal_error_partial(self):
    """Test a v8 fatal error with only part of the output printed."""
    data = self._read_test_data('v8_fatal_error_partial.txt')
    expected_type = 'Fatal error'
    expected_address = ''
    expected_state = 'objects-inl.h\n'
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_v8_abort_with_source(self):
    """Test the v8 abort error format with source file and line information."""
    data = self._read_test_data('v8_abort_with_source.txt')
    expected_type = 'ASSERT'
    expected_address = ''
    expected_state = (
        'CSA_ASSERT failed: IsFastElementsKind(LoadElementsKind(array))\n'
        'code-stub-assembler.cc\n')
    expected_stacktrace = data
    expected_security_flag = False

    environment.set_value('ASSERTS_HAVE_SECURITY_IMPLICATION', False)
    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_v8_abort_without_source(self):
    """Test the v8 abort error format without source file and line
    information."""
    data = self._read_test_data('v8_abort_without_source.txt')
    expected_type = 'ASSERT'
    expected_address = ''
    expected_state = (
        'CSA_ASSERT failed: IsFastElementsKind(LoadElementsKind(array))\n')
    expected_stacktrace = data
    expected_security_flag = False

    environment.set_value('ASSERTS_HAVE_SECURITY_IMPLICATION', False)
    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_v8_oom(self):
    """Test a v8 JavaScript out of memory condition."""
    data = self._read_test_data('v8_oom.txt')
    expected_type = ''
    expected_address = ''
    expected_state = ''
    expected_stacktrace = ''
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_v8_process_oom(self):
    """Test a v8 process out of memory condition."""
    data = self._read_test_data('v8_process_oom.txt')
    expected_type = ''
    expected_address = ''
    expected_state = ''
    expected_stacktrace = ''
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_v8_representation_changer_error(self):
    """Tests a v8 RepresentationChangerError."""
    data = self._read_test_data('v8_representation_changer_error.txt')
    expected_type = 'CHECK failure'
    expected_address = ''
    expected_state = ('Int64Constant of kRepWord64 (Internal) cannot be '
                      'changed to kRepTagged in repres\n')
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_v8_unreachable_code(self):
    """Test the v8 unreachable code format."""
    data = self._read_test_data('v8_unreachable_code.txt')
    expected_type = 'Unreachable code'
    expected_address = ''
    expected_state = 'typer.cc\n'
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_v8_unimplemented_code(self):
    """Test the v8 unreachable code format."""
    data = self._read_test_data('v8_unimplemented_code.txt')
    expected_type = 'Unreachable code'
    expected_address = ''
    expected_state = 'simulator-arm.cc\n'
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_v8_unknown_fatal_error(self):
    """Test a generic fatal error."""
    data = self._read_test_data('v8_unknown_fatal_error.txt')
    expected_type = 'Fatal error'
    expected_address = ''
    expected_state = ('something that isn\'t supported yet in '
                      'simulator-arm.cc\n')
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_v8_runtime_error(self):
    """Test a v8 runtime error."""
    os.environ['DETECT_V8_RUNTIME_ERRORS'] = 'True'

    data = self._read_test_data('v8_runtime_error.txt')
    expected_type = 'RUNTIME_ASSERT'
    expected_address = ''
    expected_state = 'args[0]->IsJSFunction() in runtime-test.cc\n'
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_v8_runtime_error_not_detected(self):
    """Ensure that v8 runtime errors are not detected if the flag is not set."""
    data = self._read_test_data('v8_runtime_error.txt')
    expected_type = ''
    expected_address = ''
    expected_state = ''
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_v8_runtime_error_analyze_task(self):
    """Ensure that v8 runtime errors are detected under analyze_task"""
    os.environ['TASK_NAME'] = 'analyze'

    data = self._read_test_data('v8_runtime_error.txt')
    expected_type = 'RUNTIME_ASSERT'
    expected_address = ''
    expected_state = 'args[0]->IsJSFunction() in runtime-test.cc\n'
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_v8_correctness_error(self):
    """Test a v8 correctness fuzzer error."""
    data = self._read_test_data('v8_correctness_failure.txt')
    expected_type = 'V8 correctness failure'
    expected_address = ''
    expected_state = ('configs: x64,fullcode:x64,ignition_staging\n'
                      'sources: deadbeef,beefdead,abcd1234\n'
                      'suppression: crbug.com/123456\n')
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_generic_segv(self):
    """Test a SEGV caught by a generic signal handler."""
    data = self._read_test_data('generic_segv.txt')
    expected_type = 'UNKNOWN'
    expected_address = '0x7f6b0c580000'
    expected_state = 'NULL'
    expected_stacktrace = data
    expected_security_flag = True

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_ignore_asan_warning(self):
    """Ensure that ASan warning lines are ignored."""
    data = self._read_test_data('ignore_asan_warning.txt')

    actual_state = stack_analyzer.get_crash_data(data)

    self.assertNotIn('Failed to allocate', actual_state.crash_type)
    self.assertTrue(actual_state.crash_state and
                    'NULL' not in actual_state.crash_state)

  def test_lsan_direct_leak(self):
    """Test the LSan direct leak format."""
    data = self._read_test_data('lsan_direct_leak.txt')
    expected_type = 'Direct-leak'
    expected_address = ''
    expected_state = 'xmlStrndup\nxmlStrdup\nxmlGetPropNodeValueInternal\n'
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_lsan_indirect_leak_cycle(self):
    """Test the LSan format when we only have indirect leaks."""
    data = self._read_test_data('lsan_indirect_leak_cycle.txt')
    expected_type = 'Indirect-leak'
    expected_address = ''
    expected_state = ('xmlNewDocElementContent\n'
                      'xmlParseElementMixedContentDecl\n'
                      'xmlParseElementContentDecl\n')
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_lsan_multiple_leaks(self):
    """Test the LSan direct leak format."""
    data = self._read_test_data('lsan_multiple_leaks.txt')
    expected_type = 'Direct-leak'
    expected_address = ''
    expected_state = 'pepper::AutoBuffer::AllocateBuffer\n'
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_lsan_single_frame_stacks(self):
    """Test the LSan direct leak format."""
    data = self._read_test_data('lsan_single_frame_stacks.txt')
    expected_type = 'Direct-leak'
    expected_address = ''
    expected_state = 'f\n'
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_cfi_bad_cast_virtual_call(self):
    """Test the CFI output format."""
    data = self._read_test_data('cfi_bad_cast.txt')
    expected_type = 'Bad-cast'
    expected_address = '0x000000000000'
    expected_state = ('Bad-cast to blink::LayoutObject from invalid vptr\n'
                      'blink::LayoutObject::containingBlock\n'
                      'blink::LayoutBox::topLeftLocation\n')
    expected_stacktrace = data
    expected_security_flag = True

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_cfi_bad_cast_indirect_function_call(self):
    """Test the CFI output format."""
    data = self._read_test_data('cfi_bad_cast_indirect_fc.txt')
    expected_type = 'Bad-cast'
    expected_address = ''
    expected_state = (
        'Bad-cast to void (*(struct VkInstance_T *, const char *))(void)\n'
        'vkGetInstanceProcAddrStub$8d185785d173e702d91e2893e143a6d9.cfi\n'
        'volkGenLoadLoader\n')
    expected_stacktrace = data
    expected_security_flag = True

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_cfi_bad_cast_invalid_vtable(self):
    """Test the CFI output format for an invalid vptr."""
    data = self._read_test_data('cfi_invalid_vtable.txt')
    expected_type = 'Bad-cast'
    expected_address = '0x000000422710'
    expected_state = 'Bad-cast to B from invalid vptr\n'
    expected_stacktrace = data
    expected_security_flag = True

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_cfi_unrelated_vtable(self):
    """Test the CFI output format from an unrelated vtable."""
    data = self._read_test_data('cfi_unrelated_vtable.txt')
    expected_type = 'Bad-cast'
    expected_address = '0x000000422710'
    expected_state = 'Bad-cast to B from A\n'
    expected_stacktrace = data
    expected_security_flag = True

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_cfi_nodebug(self):
    """Test the CFI output format with no debug information."""
    data = self._read_test_data('cfi_nodebug.txt')
    expected_type = 'Bad-cast'
    expected_address = ''
    expected_state = 'abc::def\nfoo\nbar\n'
    expected_stacktrace = data
    expected_security_flag = True

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_asan_in_drt_string(self):
    """Test that "AddressSanitizer" in text don't cause crash detection."""
    data = self._read_test_data('asan_in_drt_string.txt')
    expected_type = ''
    expected_address = ''
    expected_state = ''
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_assert_in_drt_string(self):
    """Test that "AddressSanitizer" in text don't cause crash detection."""
    data = self._read_test_data('assert_in_drt_string.txt')
    expected_type = ''
    expected_address = ''
    expected_state = ''
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_asan_breakpoint(self):
    """Test the ASan breakpoint format."""
    data = self._read_test_data('asan_breakpoint.txt')
    expected_type = 'Breakpoint'
    expected_state = ('blink::PluginInfo::GetMimeClassInfo\n'
                      'blink::DOMPlugin::item\n'
                      'blink::V8Plugin::itemMethodCallback\n')
    expected_address = '0xba0f4780'
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_asan_breakpoint_with_check_failure(self):
    """Test the ASan breakpoint format with CHECK failure."""
    data = self._read_test_data('asan_breakpoint_with_check.txt')
    expected_type = 'CHECK failure'
    expected_state = ('i < size() in Vector.h\n'
                      'blink::PluginInfo::GetMimeClassInfo\n'
                      'blink::DOMPlugin::item\n')
    expected_address = ''
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_asan_bus(self):
    """Test the ASan SIGBUS format."""
    data = self._read_test_data('asan_bus.txt')
    expected_type = 'Bus'
    expected_state = ('storeColor\n'
                      'glgProcessColor\n'
                      '__glgProcessPixelsWithProcessor_block_invoke\n')
    expected_address = '0x603000250000'
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_asan_fpe(self):
    """Test the ASan FPE format."""
    data = self._read_test_data('asan_fpe.txt')
    expected_type = 'Floating-point-exception'
    expected_state = ('ash::WindowGrid::PositionWindows\n'
                      'ash::WindowSelector::Init\n'
                      'ash::WindowSelectorController::ToggleOverview\n')
    expected_address = ''
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_ubsan_fpe(self):
    """Test the UBSan FPE format."""
    data = self._read_test_data('ubsan_fpe.txt')
    expected_type = 'Floating-point-exception'
    expected_state = ('ash::WindowGrid::PositionWindows\n'
                      'ash::WindowSelector::Init\n'
                      'ash::WindowSelectorController::ToggleOverview\n')
    expected_address = ''
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_asan_ill(self):
    """Test the ASan ILL format."""
    data = self._read_test_data('asan_ill.txt')
    expected_type = 'Ill'
    expected_state = ('boom_internal\nboom_intermediate\nboom\n')
    expected_address = '0x631000001001'
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_ubsan_ill(self):
    """Test the UBSan ILL format."""
    data = self._read_test_data('ubsan_ill.txt')
    expected_type = 'Ill'
    expected_state = ('boom_internal\nboom_intermediate\nboom\n')
    expected_address = '0x631000001001'
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_asan_ill_null_address(self):
    """Test the ASan ILL format with a null address."""
    data = self._read_test_data('asan_ill_null_address.txt')
    expected_type = 'Ill'
    expected_state = ('boom_internal\nboom_intermediate\nboom\n')
    expected_address = '0x000000000000'
    expected_stacktrace = data
    expected_security_flag = True

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_asan_gsignal(self):
    """Test the ASan gsignal format."""
    data = self._read_test_data('asan_gsignal.txt')
    expected_type = 'UNKNOWN'
    expected_state = (
        'url::UIDNAWrapper::UIDNAWrapper\n'
        'base::DefaultLazyInstanceTraits<url::UIDNAWrapper>::New\n'
        'base::internal::LeakyLazyInstanceTraits<url::UIDNAWrapper>::New\n')
    expected_address = '0x03e9000039cd'
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_asan_stack_overflow(self):
    """Test the ASan stack overflow format."""
    data = self._read_test_data('asan_stack_overflow.txt')
    expected_type = 'Stack-overflow'
    expected_state = ('CPDF_ColorSpace::Load\n'
                      'CPDF_DocPageData::GetColorSpace\n'
                      'CPDF_IndexedCS::v_Load\n')
    expected_address = '0x7ffc533cef30'
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

    # In the past, we have ignored stack overflows explicitly. Ensure that
    # the current behavior is to detect them.
    self.assertTrue(crash_analyzer.is_memory_tool_crash(data))

  def test_asan_stack_overflow_2(self):
    """Test the ASan stack overflow format."""
    data = self._read_test_data('asan_stack_overflow2.txt')
    expected_type = 'Stack-overflow'
    expected_state = ('begin_parse_string\n'
                      'finish_lithdr_notidx_v\n'
                      'begin_parse_string\n')
    expected_address = '0x7ffca4df4b38'
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_asan_stack_overflow_3(self):
    """Test the ASan stack overflow format."""
    data = self._read_test_data('asan_stack_overflow3.txt')
    expected_type = 'Stack-overflow'
    expected_state = ('begin_parse_string\n'
                      'finish_lithdr_notidx_v\n'
                      'begin_parse_string\n')
    expected_address = '0x7ffca4df4b38'
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_asan_invalid_free(self):
    """Test the ASan bad free format."""
    data = self._read_test_data('asan_invalid_free.txt')
    expected_type = 'Invalid-free'
    expected_state = ('_gnutls_buffer_append_printf\n'
                      'print_cert\n'
                      'gnutls_x509_crt_print\n')
    expected_address = '0x00000a5742f0'
    expected_stacktrace = data
    expected_security_flag = True

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_asan_double_free(self):
    """Test the ASan bad free format."""
    data = self._read_test_data('asan_double_free.txt')
    expected_type = 'Heap-double-free'
    expected_state = ('clear\n'
                      'CPDF_DocPageData::Clear\n'
                      'CPDF_DocPageData::~CPDF_DocPageData\n')
    expected_address = '0x610000022b80'
    expected_stacktrace = data
    expected_security_flag = True

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_libfuzzer_deadly_signal(self):
    """Test for libfuzzer deadly signal."""
    data = self._read_test_data('libfuzzer_deadly_signal.txt')
    expected_type = 'Fatal-signal'
    expected_state = 'NULL'
    expected_address = ''
    expected_stacktrace = data
    expected_security_flag = False
    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_libfuzzer_fuzz_target_exited(self):
    """Test for unexpected fuzz target exit."""
    data = self._read_test_data('libfuzzer_fuzz_target_exited.txt')
    expected_type = 'Unexpected-exit'
    expected_state = 'clearsilver_fuzzer_file.cc\n'
    expected_address = ''
    expected_stacktrace = data
    expected_security_flag = False
    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_fuchsia_asan(self):
    """Test for Fuchsia ASan crashes."""
    # TODO(flowerhack): Once the duplicated frames issue is fixed for Fuchsia,
    # update this test to recognize proper frames.
    data = self._read_test_data('fuchsia_asan.txt')
    expected_type = 'Heap-buffer-overflow\nWRITE 1'
    expected_state = 'foo_function\nfoo_function\nbar_function\n'
    expected_address = '0x663fa3bcf198'
    expected_stacktrace = data
    expected_security_flag = True
    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_fuchsia_reproducible_crash(self):
    """Test for Fuchsia ASan crashes found via reproduction."""
    # TODO(flowerhack): right now, we get the logs from reproducer runs, and
    # then post-process them to be in a format ClusterFuzz understands. Once we
    # patch Fuchsia to emit logs properly the first time, update this test
    # accordingly.
    data = self._read_test_data('fuchsia_reproducible_crash.txt')
    expected_type = 'Fatal-signal'
    expected_state = 'foo_function\nbar_function\nbasic.cc\n'
    expected_address = ''
    expected_stacktrace = data
    expected_security_flag = False
    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_fuchsia_ignore(self):
    """Test for ignoring Fuchsia frames."""
    data = self._read_test_data('fuchsia_ignore.txt')
    expected_type = 'Fatal-signal'
    expected_state = ('frame::Fake::Fake\n'
                      'frame::Fake::Fake2\n'
                      'async::TestLoop::Run\n')
    expected_address = ''
    expected_stacktrace = data
    expected_security_flag = False
    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_windows_asan_divide_by_zero(self):
    """Test for Windows ASan divide by zero crashes."""
    data = self._read_test_data('windows_asan_divide_by_zero.txt')
    expected_type = 'Divide-by-zero'
    expected_state = (
        'blink::LayoutMultiColumnSet::PageRemainingLogicalHeightForOffset\n'
        'blink::LayoutFlowThread::PageRemainingLogicalHeightForOffset\n'
        'blink::LayoutBox::PageRemainingLogicalHeightForOffset\n')
    expected_address = '0x00000000'
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_cdb_divide_by_zero(self):
    """Test the CDB format for divide by zero crashes."""
    data = self._read_test_data('cdb_divide_by_zero.txt')
    expected_type = 'Divide-by-zero'
    expected_state = ('ForStatementNode::DetermineLoopIterations<int>\n'
                      'ForStatementNode::VerifySelf\n'
                      'ParseTreeNode::VerifyNode\n')
    expected_address = ''
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_cdb_integer_overflow(self):
    """Test the CDB format for safe integer overflow crashes."""
    data = self._read_test_data('cdb_integer_overflow.txt')
    expected_type = 'Integer-overflow'
    expected_state = ('Js::TaggedInt::Divide\n'
                      'Js::InterpreterStackFrame::ProfiledDivide\n'
                      'Js::InterpreterStackFrame::Process\n')
    expected_address = ''
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_cdb_read(self):
    """Test the Windows CDB format for an invalid read."""
    data = self._read_test_data('cdb_read.txt')
    expected_type = 'READ'
    expected_state = 'crash\nggg\nfff\n'
    expected_address = '0x000000000000'
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_cdb_read_x64(self):
    """Test the 64-bit Windows CDB format for an invalid read."""
    data = self._read_test_data('cdb_read_x64.txt')
    expected_type = 'READ'
    expected_state = 'Ordinal101\nCreateCoreWebView\nOrdinal107\n'
    expected_address = '0x000000000010'
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_cdb_other(self):
    """Test the CDB format for crashes that are not read/write AVs."""
    data = self._read_test_data('cdb_other.txt')
    expected_type = 'Heap-corruption'
    expected_state = ('CScriptTimers::ExecuteTimer\n'
                      'CWindow::FireTimeOut\n'
                      'CPaintBeat::ProcessTimers\n')
    expected_address = ''
    expected_stacktrace = data
    expected_security_flag = True

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_cdb_stack_overflow(self):
    """Test the CDB stack overflow format."""
    data = self._read_test_data('cdb_stack_overflow.txt')
    expected_type = 'Stack-overflow'
    expected_state = 'RunHTMLApplication\n'
    expected_address = ''
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_gsignal_at_first_stack_frame(self):
    """Test that gsignal is at the first stack frame."""
    data = self._read_test_data('gsignal_at_first_stack_frame.txt')
    expected_type = 'UNKNOWN'
    expected_address = '0x5668a000177a5'
    expected_state = ('AbbreviatedMonthsMap\nget\nGetInstance\n')
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_sanitizer_signal_abrt(self):
    """Test abort signal from sanitizer for functional bug."""
    data = self._read_test_data('sanitizer_signal_abrt.txt')
    expected_type = 'Abrt'
    expected_address = ''
    expected_state = ('/tmp/coredump\n/tmp/coredump\n')
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_sanitizer_signal_abrt_unknown(self):
    """Test abort signal on unknown address from sanitizer for functional
    bug."""
    data = self._read_test_data('sanitizer_signal_abrt_unknown.txt')
    expected_type = 'Abrt'
    expected_address = '0x000000000001'
    expected_state = 'NULL'
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_syzkaller_kasan(self):
    """Test syzkaller kasan."""
    data = self._read_test_data('kasan_syzkaller.txt')
    expected_type = 'Kernel failure\nUse-after-free\nREAD 8'
    expected_state = ('sock_wake_async\n'
                      'sock_def_readable\n'
                      'unix_dgram_sendmsg\n')
    expected_address = '0xffffffc01640e9d0'
    expected_stacktrace = data
    expected_security_flag = True

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_syzkaller_kasan_android(self):
    """Test syzkaller kasan."""
    data = self._read_test_data('kasan_syzkaller_android.txt')
    expected_type = 'Kernel failure\nNull-ptr-deref\nWRITE 4'
    expected_state = ('sockfs_setattr\nnotify_change2\nchown_common\n')
    expected_address = '0x00000000027c'
    expected_stacktrace = data
    expected_security_flag = True

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_kasan_gpf(self):
    """Test a KASan GPF."""
    data = self._read_test_data('kasan_gpf.txt')
    expected_type = 'Kernel failure\nGeneral-protection-fault'
    expected_state = ('keyring_destroy\n'
                      'key_garbage_collector\n'
                      'process_one_work\n')
    expected_address = ''
    expected_stacktrace = data
    expected_security_flag = True

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_kasan_null(self):
    """Test a KASan NULL deref."""
    data = self._read_test_data('kasan_null.txt')
    expected_type = 'Kernel failure\nUser-memory-access\nWRITE 4'
    expected_state = ('snd_seq_fifo_clear\n'
                      'snd_seq_ioctl_remove_events\n'
                      'snd_seq_do_ioctl\n')
    expected_address = '0x000000000040'
    expected_stacktrace = data
    expected_security_flag = True

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_kasan_oob_read(self):
    """Test a KASan out-of-bounds read."""
    data = self._read_test_data('kasan_oob_read.txt')
    expected_type = 'Kernel failure\nOut-of-bounds-access\nREAD 1'
    expected_state = ('platform_match\n'
                      '__device_attach_driver\n'
                      'bus_for_each_drv\n')
    expected_address = '0xffffffc002583240'
    expected_stacktrace = data
    expected_security_flag = True

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_kasan_uaf(self):
    """Test a KASan use-after-free."""
    data = self._read_test_data('kasan_uaf.txt')
    expected_type = 'Kernel failure\nUse-after-free\nREAD 4'
    expected_state = ('ip6_append_data\nudpv6_sendmsg\ninet_sendmsg\n')
    expected_address = '0xffff88005031ee80'
    expected_stacktrace = data
    expected_security_flag = True

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_asan_null_dereference_read(self):
    """Test a Null-dereference READ derived from ASan UNKNOWN READ access."""
    data = self._read_test_data('asan_null_dereference_read.txt')
    expected_type = 'Null-dereference READ'
    expected_state = ('content::NavigationEntryImpl::site_instance\n'
                      'content::NavigationControllerImpl::ClassifyNavigation\n'
                      'content::NavigationControllerImpl::'
                      'RendererDidNavigate\n')
    expected_address = '0x000000000008'
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_asan_null_dereference_write(self):
    """Test a Null-dereference WRITE derived from ASan UNKNOWN WRITE access."""
    data = self._read_test_data('asan_null_dereference_write.txt')
    expected_type = 'Null-dereference WRITE'
    expected_state = ('SetTaskInfo\n'
                      'base::Timer::Start\n'
                      'Start<views::MenuController>\n')
    expected_address = '0x000000000178'
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_asan_null_dereference_unknown(self):
    """Test a Null-dereference derived from ASan UNKNOWN access of unknown type
    (READ/WRITE)."""
    data = self._read_test_data('asan_null_dereference_unknown.txt')
    expected_type = 'Null-dereference'
    expected_state = (
        'blink::Member<blink::StyleEngine>::get\n'
        'blink::Document::styleEngine\n'
        'blink::Document::updateLayoutTreeIgnorePendingStylesheets\n')
    expected_address = '0x000000000530'
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_asan_null_dereference_win_read(self):
    """Test a Null-dereference READ derived from ASan UNKNOWN READ
    access-violation on windows."""
    data = self._read_test_data('asan_null_dereference_win_read.txt')
    expected_type = 'Null-dereference READ'
    expected_state = ('blink::SVGEnumerationBase::calculateAnimatedValue\n'
                      'blink::SVGAnimateElement::calculateAnimatedValue\n'
                      'blink::SVGAnimationElement::updateAnimation\n')
    expected_address = '0x00000008'
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_asan_null_dereference_win_write(self):
    """Test a Null-dereference WRITE derived from ASan UNKNOWN WRITE
    access-violation on windows."""
    data = self._read_test_data('asan_null_dereference_win_write.txt')
    expected_type = 'Null-dereference WRITE'
    expected_state = ('blink::SVGEnumerationBase::calculateAnimatedValue\n'
                      'blink::SVGAnimateElement::calculateAnimatedValue\n'
                      'blink::SVGAnimationElement::updateAnimation\n')
    expected_address = '0x00000008'
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_asan_unknown_crash_read_null(self):
    """Test an ASan Unknown-crash READ access from nullptr."""
    data = self._read_test_data('asan_unknown_crash_read.txt')
    expected_type = 'Null-dereference'
    expected_state = ('void rawspeed::FujiDecompressor::copy_line'
                      '<rawspeed::FujiDecompressor::copy_line\n'
                      'rawspeed::FujiDecompressor::copy_line_to_xtrans\n'
                      'rawspeed::FujiDecompressor::fuji_decode_strip\n')
    expected_address = '0x000000000006'
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_asan_unknown_crash_write(self):
    """Test an ASan Unknown-crash WRITE access."""
    data = self._read_test_data('asan_unknown_crash_write.txt')
    expected_type = 'UNKNOWN'
    expected_state = ('void rawspeed::FujiDecompressor::copy_line'
                      '<rawspeed::FujiDecompressor::copy_line\n'
                      'rawspeed::FujiDecompressor::copy_line_to_xtrans\n'
                      'rawspeed::FujiDecompressor::fuji_decode_strip\n')
    expected_address = '0x000000123456'
    expected_stacktrace = data
    expected_security_flag = True

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_asan_unknown_read(self):
    """Test an ASan UNKNOWN READ access."""
    data = self._read_test_data('asan_unknown_read.txt')
    expected_type = 'UNKNOWN READ'
    expected_state = ('content::NavigationEntryImpl::site_instance\n'
                      'content::NavigationControllerImpl::ClassifyNavigation\n'
                      'content::NavigationControllerImpl::'
                      'RendererDidNavigate\n')
    expected_address = '0x000000010008'
    expected_stacktrace = data
    expected_security_flag = True

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_asan_unknown_write(self):
    """Test an ASan UNKNOWN WRITE accces."""
    data = self._read_test_data('asan_unknown_write.txt')
    expected_type = 'UNKNOWN WRITE'
    expected_state = ('SetTaskInfo\n'
                      'base::Timer::Start\n'
                      'Start<views::MenuController>\n')
    expected_address = '0x000000010178'
    expected_stacktrace = data
    expected_security_flag = True

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_asan_unknown_unknown(self):
    """Test an ASan UNKNOWN access of unknown type (READ/WRITE)."""
    data = self._read_test_data('asan_unknown_unknown.txt')
    expected_type = 'UNKNOWN'
    expected_state = (
        'blink::Member<blink::StyleEngine>::get\n'
        'blink::Document::styleEngine\n'
        'blink::Document::updateLayoutTreeIgnorePendingStylesheets\n')
    expected_address = '0x000000010530'
    expected_stacktrace = data
    expected_security_flag = True

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_asan_unknown_win_read(self):
    """Test an ASan UNKNOWN READ access-violation on windows."""
    data = self._read_test_data('asan_unknown_win_read.txt')
    expected_type = 'UNKNOWN READ'
    expected_state = ('blink::SVGEnumerationBase::calculateAnimatedValue\n'
                      'blink::SVGAnimateElement::calculateAnimatedValue\n'
                      'blink::SVGAnimationElement::updateAnimation\n')
    expected_address = '0x00010008'
    expected_stacktrace = data
    expected_security_flag = True

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_asan_unknown_win_write(self):
    """Test an ASan UNKNOWN WRITE access-violation on windows."""
    data = self._read_test_data('asan_unknown_win_write.txt')
    expected_type = 'UNKNOWN WRITE'
    expected_state = ('blink::SVGEnumerationBase::calculateAnimatedValue\n'
                      'blink::SVGAnimateElement::calculateAnimatedValue\n'
                      'blink::SVGAnimationElement::updateAnimation\n')
    expected_address = '0x00010008'
    expected_stacktrace = data
    expected_security_flag = True

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_security_check_failure(self):
    """Test a security CHECK failure (i.e. Blink RELEASE_ASSERT)."""
    data = self._read_test_data('security_check_failure.txt')
    expected_type = 'Security CHECK failure'
    expected_address = ''
    expected_state = ('startPosition.compareTo(endPosition) <= 0 in '
                      'Serialization.cpp\n'
                      'blink::CreateMarkupAlgorithm<>::createMarkup\n'
                      'blink::createMarkup\n')
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_security_dcheck_failure(self):
    """Test a security DCHECK failure."""
    data = self._read_test_data('security_dcheck_failure.txt')
    expected_type = 'Security DCHECK failure'
    expected_address = ''
    expected_state = ('!terminated_ in latency_info.cc\n'
                      'ui::LatencyInfo::AddLatencyNumberWithTimestampImpl\n'
                      'ui::LatencyInfo::AddLatencyNumberWithTimestamp\n')
    expected_stacktrace = data
    expected_security_flag = True

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_security_dcheck_failure_with_abrt(self):
    """Test a security DCHECK failure with SIGABRT stack."""
    data = self._read_test_data('security_dcheck_failure_with_abrt.txt')
    expected_type = 'Security DCHECK failure'
    expected_address = ''
    expected_state = ('!root_parent->IsSVGElement() || '
                      '!ToSVGElement(root_parent) ->elements_with_relat\n'
                      'blink::SVGElement::RemovedFrom\n'
                      'blink::ContainerNode::NotifyNodeRemoved\n')
    expected_stacktrace = data
    expected_security_flag = True

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_check_failure_with_string_vs_string(self):
    """Test a check failure with string vs string."""
    data = self._read_test_data('check_failure_with_string_vs_string.txt')
    expected_type = 'CHECK failure'
    expected_address = ''
    expected_state = ('start <= end in text_iterator.cc\n'
                      'blink::TextIteratorAlgorithm<blink::EditingAlgorithm'
                      '<blink::FlatTreeTraversal> >\n'
                      'blink::TextIteratorAlgorithm<blink::EditingAlgorithm'
                      '<blink::FlatTreeTraversal> >\n')
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_check_failure_vs_no_closing(self):
    """Test a check failure with string vs string (no closing bracket)."""
    data = self._read_test_data('check_failure_vs_no_closing.txt')
    expected_type = 'CHECK failure'
    expected_address = ''
    expected_state = ('record1 == record2 in file.cc\n'
                      'blink::TextIteratorAlgorithm<blink::EditingAlgorithm'
                      '<blink::FlatTreeTraversal> >\n'
                      'blink::TextIteratorAlgorithm<blink::EditingAlgorithm'
                      '<blink::FlatTreeTraversal> >\n')
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_check_failure_with_msan_abrt(self):
    """Test a check failure with MSan SIGABRT stack."""
    data = self._read_test_data('check_failure_with_msan_abrt.txt')
    expected_type = 'CHECK failure'
    expected_address = ''
    expected_state = ('i < length_ in string_piece.h\n'
                      'base::BasicStringPiece<std::__1::basic_string<char, '
                      'std::__1::char_traits<char>,\n'
                      'base::internal::JSONParser::ConsumeStringRaw\n')
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_android_security_dcheck_failure(self):
    """Test an android security DCHECK failure."""
    data = self._read_test_data('android_security_dcheck_failure.txt')
    expected_type = 'Security DCHECK failure'
    expected_address = ''
    expected_state = ('offset + length <= impl.length() in StringView.h\n'
                      'set\n'
                      'StringView\n')
    expected_stacktrace = data
    expected_security_flag = True

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_check_failure_android_media(self):
    """Test a CHECK failure in Android Media."""
    data = self._read_test_data('check_failure_android_media.txt')
    expected_type = 'CHECK failure'
    expected_address = ''
    expected_state = (
        'CHECK_EQ( (unsigned)ptr[0],1u) failed in MPEG4Extractor.cpp\n'
        'android::MPEG4Source::MPEG4Source\n'
        'android::MPEG4Extractor::getTrack\n')
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_check_failure_android_media2(self):
    """Test a CHECK failure on Android."""
    data = self._read_test_data('check_failure_android_media2.txt')
    expected_type = 'CHECK failure'
    expected_address = ''
    expected_state = (
        'CHECK(mFormat->findInt32(kKeyCryptoDefaultIVSize, &ivlength)) failed '
        'in MPEG4Ext\n'
        'android::MPEG4Source::parseSampleAuxiliaryInformationOffsets\n'
        'android::MPEG4Source::parseChunk\n')
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_check_failure_chrome(self):
    """Test a CHECK failure with a Chrome symbolized stacktrace."""
    data = self._read_test_data('check_failure_chrome.txt')
    expected_type = 'CHECK failure'
    expected_address = ''
    expected_state = ('!terminated_ in latency_info.cc\n'
                      'ui::LatencyInfo::AddLatencyNumberWithTimestampImpl\n'
                      'ui::LatencyInfo::AddLatencyNumberWithTimestamp\n')
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_check_failure_chrome_android(self):
    """Test a CHECK failure with a Chrome on Android symbolized stacktrace."""
    data = self._read_test_data('check_failure_chrome_android.txt')
    expected_type = 'CHECK failure'
    expected_address = ''
    expected_state = ('Timed out waiting for GPU channel in '
                      'compositor_impl_android.cc\n')
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_check_failure_chrome_android2(self):
    """Test a CHECK failure with a Chrome on Android symbolized stacktrace."""
    data = self._read_test_data('check_failure_chrome_android2.txt')
    expected_type = 'CHECK failure'
    expected_address = ''
    expected_state = ('lifecycle().state() < '
                      'DocumentLifecycle::LayoutClean in FrameView.cpp\n'
                      'blink::FrameView::checkLayoutInvalidationIsAllowed\n'
                      'blink::FrameView::setNeedsLayout\n')
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_check_failure_chrome_mac(self):
    """Test a CHECK failure with a Chrome on Mac symbolized stacktrace."""
    if not environment.is_posix():
      self.skipTest('This test needs c++filt for demangling and is only '
                    'applicable for posix platforms.')

    data = self._read_test_data('check_failure_chrome_mac.txt')
    expected_type = 'CHECK failure'
    expected_address = ''
    expected_state = ('max_start_velocity > 0 in fling_curve.cc\n'
                      'ui::FlingCurve::FlingCurve\n'
                      'ui::WebGestureCurveImpl::CreateFromDefaultPlatformCurve'
                      '\n')
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_check_failure_chrome_win(self):
    """Test a CHECK failure with a Chrome on Windows symbolized stacktrace."""
    data = self._read_test_data('check_failure_chrome_win.txt')
    expected_type = 'CHECK failure'
    expected_address = ''
    expected_state = ('it != device_change_subscribers_.end() in '
                      'media_stream_dispatcher_host.cc\n'
                      'content::MediaStreamDispatcherHost::'
                      'OnCancelDeviceChangeNotifications\n'
                      'IPC::MessageT<MediaStreamHostMsg_'
                      'CancelDeviceChangeNotifications_Meta,std::tuple\n')
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_check_failure_with_assert_message(self):
    """Test the CHECK failure with assert message format."""

    data = self._read_test_data('check_failure_with_assert_message.txt')
    expected_type = 'CHECK failure'
    expected_address = ''
    expected_state = (
        'host->listeners_.IsEmpty() in render_process_host_impl.cc\n'
        'content::RenderProcessHostImpl::CheckAllTerminated\n'
        'content::BrowserMainLoop::ShutdownThreadsAndCleanUp\n')
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_check_failure_with_comparison(self):
    """Test for special CHECK failure formats (CHECK_EQ, CHECK_LE, etc.)."""
    data = self._read_test_data('check_failure_with_comparison.txt')
    expected_type = 'CHECK failure'
    expected_address = ''
    expected_state = 'len > 0 in zygote_linux.cc\n'
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_check_failure_with_comparison2(self):
    """Test for special CHECK failure formats (CHECK_EQ, CHECK_LE, etc.)."""
    data = self._read_test_data('check_failure_with_comparison2.txt')
    expected_type = 'CHECK failure'
    expected_address = ''
    expected_state = ('layout_snapped_paint_offset == snapped_paint_offset '
                      'in compositing_layer_propert\n')
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_check_failure_with_handle_sigill_disabled(self):
    """Test the CHECK failure crash with ASAN_OPTIONS=handle_sigill=0."""
    data = self._read_test_data('check_failure_with_handle_sigill=0.txt')
    expected_type = 'CHECK failure'
    expected_address = ''
    expected_state = (
        'length == 0 || (length > 0 && data != __null) in vector.h\n')
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_check_failure_with_handle_sigill_enabled(self):
    """Test the CHECK failure crash with ASAN_OPTIONS=handle_sigill=1."""
    data = self._read_test_data('check_failure_with_handle_sigill=1.txt')
    expected_type = 'CHECK failure'
    expected_address = ''
    expected_state = (
        'length == 0 || (length > 0 && data != __null) in vector.h\n'
        'v8::internal::Vector<unsigned char const>::Vector\n'
        'v8::internal::wasm::ModuleWireBytes::ModuleWireBytes\n')
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_check_failure_with_fuzzer_data(self):
    """Test the CHECK failure crash with fuzzer data."""
    for data in [('F0813 00:29:27.775753  384244 file.cc:130] '
                  'Check failed: query failed: "fuzzed456$data"'),
                 ('F0813 00:29:27.775753  384244 file.cc:130] '
                  'Check failed: query failed: \'fuzzed456$data\''),
                 ('F0813 00:29:27.775753  384244 file.cc:130] '
                  'Check failed: query failed = \'fuzzed456$data\''),
                 ('F0813 00:29:27.775753  384244 file.cc:130] '
                  'Check failed: query failed = "fuzzed456$data"')]:
      expected_type = 'CHECK failure'
      expected_address = ''
      expected_state = ('query failed in file.cc\n')
      expected_stacktrace = data
      expected_security_flag = False

      self._validate_get_crash_data(data, expected_type, expected_address,
                                    expected_state, expected_stacktrace,
                                    expected_security_flag)

  def test_oom(self):
    """Test an out of memory stacktrace."""
    data = self._read_test_data('oom.txt')
    expected_type = ''
    expected_address = ''
    expected_state = ''
    expected_stacktrace = ''
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_oom2(self):
    """Test an out of memory stacktrace."""
    data = self._read_test_data('oom2.txt')
    expected_type = ''
    expected_address = ''
    expected_state = ''
    expected_stacktrace = ''
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_oom3(self):
    """Test an out of memory stacktrace."""
    data = self._read_test_data('oom3.txt')
    expected_type = ''
    expected_address = ''
    expected_state = ''
    expected_stacktrace = ''
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_oom4(self):
    """Test an out of memory stacktrace."""
    os.environ['FUZZ_TARGET'] = 'pdf_jpx_fuzzer'
    os.environ['REPORT_OOMS_AND_HANGS'] = 'True'

    data = self._read_test_data('oom4.txt')
    expected_type = 'Out-of-memory'
    expected_address = ''
    expected_state = 'pdf_jpx_fuzzer\n'
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_libfuzzer_timeout_enabled(self):
    """Test a libFuzzer timeout stacktrace (with reporting enabled)."""
    os.environ['FUZZ_TARGET'] = 'pdfium_fuzzer'
    os.environ['REPORT_OOMS_AND_HANGS'] = 'True'

    data = self._read_test_data('libfuzzer_timeout.txt')
    expected_type = 'Timeout'
    expected_address = ''
    expected_state = 'pdfium_fuzzer\n'
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_libfuzzer_timeout_disabled(self):
    """Test a libFuzzer timeout stacktrace (with reporting disabled)."""
    data = self._read_test_data('libfuzzer_timeout.txt')
    expected_type = ''
    expected_address = ''
    expected_state = ''
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_libfuzzer_oom_without_redzone(self):
    """Test a libFuzzer OOM stacktrace with no redzone."""
    os.environ['FUZZ_TARGET'] = 'freetype2_fuzzer'
    os.environ['REPORT_OOMS_AND_HANGS'] = 'True'

    data = self._read_test_data('libfuzzer_oom.txt')
    expected_type = 'Out-of-memory'
    expected_address = ''
    expected_state = 'freetype2_fuzzer\n'
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

    data = self._read_test_data('libfuzzer_oom_malloc.txt')
    expected_stacktrace = data
    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_libfuzzer_oom_with_small_redzone(self):
    """Test a libFuzzer OOM stacktrace with redzone equal or smaller than 64."""
    os.environ['FUZZ_TARGET'] = 'freetype2_fuzzer'
    os.environ['REPORT_OOMS_AND_HANGS'] = 'True'
    os.environ['REDZONE'] = '64'

    data = self._read_test_data('libfuzzer_oom.txt')
    expected_type = 'Out-of-memory'
    expected_address = ''
    expected_state = 'freetype2_fuzzer\n'
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

    data = self._read_test_data('libfuzzer_oom_malloc.txt')
    expected_stacktrace = data
    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_libfuzzer_oom_with_higher_redzone(self):
    """Test a libFuzzer OOM stacktrace with redzone greater than 64."""
    data = self._read_test_data('libfuzzer_oom.txt')
    os.environ['REPORT_OOMS_AND_HANGS'] = 'True'
    os.environ['REDZONE'] = '256'
    expected_type = ''
    expected_address = ''
    expected_state = ''
    expected_stacktrace = ''
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

    data = self._read_test_data('libfuzzer_oom_malloc.txt')
    expected_stacktrace = ''
    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_glibc_assertion(self):
    """Test assertion (glibc)."""
    data = self._read_test_data('assert_glibc.txt')
    expected_type = 'ASSERT'
    expected_address = ''
    expected_state = ('record\n'
                      'DuplicateRecordAndInsertInterval\n'
                      'DoDpPhrasing\n')
    expected_stacktrace = data
    expected_security_flag = False

    environment.set_value('ASSERTS_HAVE_SECURITY_IMPLICATION', False)
    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_glibc_assertion_with_glib(self):
    """Test assertion (glibc) with glib frames."""
    data = self._read_test_data('assert_glibc_with_glib.txt')
    expected_type = 'ASSERT'
    expected_address = ''
    expected_state = ('g_utf8_validate (tag, -1, NULL)\n'
                      'gst_tag_list_from_vorbiscomment\n'
                      'tag_list_from_vorbiscomment_packet\n')
    expected_stacktrace = data
    expected_security_flag = False

    environment.set_value('ASSERTS_HAVE_SECURITY_IMPLICATION', False)
    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_chromium_log_assert(self):
    """Tests assertion (chromium's LOG_ASSERT)."""
    data = self._read_test_data('assert_chromium_log.txt')
    expected_type = 'ASSERT'
    expected_address = ''
    expected_state = (
        'parsed_output == double_parsed_output. Parser/Writer mismatch.\n'
        'correctness_fuzzer.cc\n')
    expected_stacktrace = data
    expected_security_flag = False

    environment.set_value('ASSERTS_HAVE_SECURITY_IMPLICATION', False)
    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_asan_container_overflow(self):
    """Test an ASan container overflow."""
    data = self._read_test_data('asan_container_overflow_read.txt')
    expected_type = 'Container-overflow\nREAD 4'
    expected_address = '0x61000006be40'
    expected_state = ('SkSL::Compiler::addDefinitions\n'
                      'SkSL::Compiler::scanCFG\n'
                      'SkSL::Compiler::internalConvertProgram\n')
    expected_stacktrace = data
    expected_security_flag = True

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_cobalt_check(self):
    """Test a cobalt check failure crash.."""
    data = self._read_test_data('cobalt_check.txt')
    expected_type = 'CHECK failure'
    expected_address = ''
    expected_state = ('space_width_ > 0 in font_list.cc\n'
                      'cobalt::dom::FontList::GenerateSpaceWidth\n'
                      'cobalt::dom::FontList::GetSpaceWidth\n')
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_ubsan_unsigned_integer_overflow(self):
    """Test that we analyze Unsigned-integer-overflow correctly."""
    data = self._read_test_data('ubsan_unsigned_integer_overflow.txt')
    expected_type = 'Unsigned-integer-overflow'
    expected_address = ''
    expected_state = ('xmlHashComputeKey\n'
                      'xmlHashAddEntry3\n'
                      'xmlAddEntity\n')
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_libfuzzer_llvm_test_one_input(self):
    """Test that we use the filename as the crash state instead of
    LLVMFuzzerTestOneInput."""
    data = self._read_test_data(
        'libfuzzer_llvm_fuzzer_test_one_input_crash.txt')
    expected_type = 'Abrt'
    expected_address = '0x03e900003b7b'
    expected_state = ('deflate_set_dictionary_fuzzer.cc\n')
    expected_stacktrace = data
    expected_security_flag = False
    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_webkit_wtfcrash(self):
    """Test that WTFCrash is ignored."""
    data = self._read_test_data('wtfcrash.txt')
    expected_type = 'Ill'
    expected_address = '0x000002ade51c'
    expected_state = (
        'JSC::BuiltinExecutables::createExecutable\n'
        'JSC::BuiltinExecutables::typedArrayPrototypeEveryCodeExecutable\n'
        'JSC::typedArrayPrototypeEveryCodeGenerator\n')

    expected_stacktrace = data
    expected_security_flag = False
    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_v8_javascript_assertion_should_pass(self):
    """Don't detect the string Assertion in javascript output as a failure."""
    data = self._read_test_data('v8_javascript_assertion_should_pass.txt')

    self._validate_get_crash_data(data, '', '', '', data, False)

  def test_asan_assert_failure(self):
    """Test asan assertions formatted as 'assert failure: ...'."""
    data = self._read_test_data('asan_assert_failure.txt')
    expected_type = 'ASSERT'
    expected_address = ''
    expected_state = (
        'ss_len == 0 || ss_len >= offsetof(struct sockaddr_un, sun_path) + 1\n'
        'Envoy::Network::Address::addressFromSockAddr\n'
        'Envoy::Network::Address::addressFromFd\n')

    expected_stacktrace = data
    expected_security_flag = True
    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_glib_assert_failure(self):
    """Test glib assertions formatted as 'assert failure: ...'."""
    data = self._read_test_data('glib_assert_failure.txt')
    expected_type = 'ASSERT'
    expected_address = ''
    expected_state = ('(j < i)\n'
                      'ast_array_get_pattern\n'
                      'array_get_pattern\n')

    expected_stacktrace = data
    expected_security_flag = True
    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_assert_with_panic_keyword(self):
    """Test assertions formatted as 'panic: ...'."""
    data = self._read_test_data('assert_with_panic_keyword.txt')
    expected_type = 'ASSERT'
    expected_address = ''
    expected_state = (
        'not reached\n'
        'Envoy::Upstream::ClusterManagerImpl::ClusterManagerImpl\n'
        'Envoy::Upstream::ValidationClusterManager::ValidationClusterManager\n')

    expected_stacktrace = data
    expected_security_flag = True
    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_ignore_regex(self):
    """Test ignore regex work as expected."""

    def _mock_config_get(_, param, default):
      """Handle test configuration options."""
      if param == 'stacktrace.stack_frame_ignore_regexes':
        return [r'Envoy\:\:Upstream\:\:ClusterManagerImpl']
      return default

    helpers.patch(
        self, ['clusterfuzz._internal.config.local_config.ProjectConfig.get'])
    self.mock.get.side_effect = _mock_config_get

    data = self._read_test_data('assert_with_panic_keyword.txt')
    expected_type = 'ASSERT'
    expected_address = ''
    expected_state = (
        'not reached\n'
        'Envoy::Upstream::ValidationClusterManager::ValidationClusterManager\n'
        'Envoy::Upstream::ValidationClusterManagerFactory::'
        'clusterManagerFromProto\n')

    expected_stacktrace = data
    expected_security_flag = True
    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_check_failure_google(self):
    """Test check failure format for internal google."""
    data = self._read_test_data('check_failure_google.txt')
    expected_type = 'CHECK failure'
    expected_address = ''
    expected_state = ('std::is_sorted(foo.begin(), foo.end()) in file.cc\n'
                      'Frame\n'
                      'path.cc\n')

    expected_stacktrace = data
    expected_security_flag = False
    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_assert_google(self):
    """Test check failure format for internal google."""
    data = self._read_test_data('assert_failure_google.txt')
    expected_type = 'ASSERT'
    expected_address = ''
    expected_state = ('Blah.empty() && "Failure!"\nFrame\npath.cc\n')

    expected_stacktrace = data
    expected_security_flag = True
    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_log_fatal_google(self):
    """Test log fatal format for internal google."""
    data = self._read_test_data('log_fatal_google.txt')
    expected_type = 'Fatal error'
    expected_address = ''
    expected_state = ('Log fatal in file.h\nFrame\npath.cc\n')

    expected_stacktrace = data
    expected_security_flag = False
    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_golang_asan_panic(self):
    """Test golang stacktrace with panic and ASan."""
    data = self._read_test_data('golang_asan_panic.txt')
    expected_type = 'ASSERT'
    expected_address = ''
    expected_state = 'asn1: string not valid UTF-8\nasn1.Fuzz\n'

    expected_stacktrace = data
    expected_security_flag = True
    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_golang_sigsegv_panic(self):
    """Test golang stacktrace with panic and SIGSEGV."""
    data = self._read_test_data('golang_sigsegv_panic.txt')
    expected_type = 'Invalid memory address'
    expected_address = ''
    expected_state = 'math.glob..func1\nmath.init.ializers\n'

    expected_stacktrace = data
    expected_security_flag = True
    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_golang_libfuzzer_panic(self):
    """Test golang stacktrace with panic and libFuzzer's deadly signal."""
    data = self._read_test_data('golang_libfuzzer_panic.txt')
    expected_type = 'ASSERT'
    expected_address = ''
    expected_state = (
        'parse //%B9%B9%B9%B9%B9%01%00%00%00%00%00%00%00%B9%B9%B9%B9%B9%B9%B9%B'
        '9%B9%B9%B9\nurl.Fuzz\n')

    expected_stacktrace = data
    expected_security_flag = True
    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_golang_panic_with_type_assertions_in_frames(self):
    """Test golang stacktrace with panic with type assertions in stack frames.
    """
    data = self._read_test_data(
        'golang_panic_with_type_assertions_in_frames.txt')
    expected_type = 'ASSERT'
    expected_address = ''
    expected_state = ('index > windowEnd\n'
                      'flate.(*compressor).deflate\n'
                      'flate.(*compressor).syncFlush\n')

    expected_stacktrace = data
    expected_security_flag = True
    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_golang_fatal_error_stack_overflow(self):
    """Test golang stacktrace with fatal error caused by stack overflow."""
    data = self._read_test_data('golang_fatal_error_stack_overflow.txt')
    expected_type = 'Stack overflow'
    expected_address = ''
    expected_state = ('ast.(*scanner).next\n'
                      'ast.(*scanner).scanIdent\n'
                      'ast.(*scanner).Scan\n')

    expected_stacktrace = data
    expected_security_flag = False
    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_golang_panic_custom_short_message(self):
    """Test golang stacktrace with panic and custom short message."""
    data = self._read_test_data('golang_panic_custom_short_message.txt')
    expected_type = 'ASSERT'
    expected_address = ''
    expected_state = 'bad hex char\nprog.fromHexChar\nprog.hexToByte\n'

    expected_stacktrace = data
    expected_security_flag = True
    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_golang_panic_runtime_error_invalid_memory_address(self):
    """Test golang stacktrace with panic caused by invalid memory address."""
    data = self._read_test_data(
        'golang_panic_runtime_error_invalid_memory_address.txt')
    expected_type = 'Invalid memory address'
    expected_address = ''
    expected_state = ('repro.(*context).reproMinimizeProg\n'
                      'repro.(*context).repro\n'
                      'repro.Run\n')

    expected_stacktrace = data
    expected_security_flag = True
    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_golang_panic_runtime_error_index_out_of_range(self):
    """Test golang stacktrace with panic caused by index out of range."""
    data = self._read_test_data(
        'golang_panic_runtime_error_index_out_of_range.txt')
    expected_type = 'Index out of range'
    expected_address = ''
    expected_state = ('http.(*conn).serve.func1\n'
                      'http.HandlerFunc.ServeHTTP\n'
                      'http.(*ServeMux).ServeHTTP\n')
    expected_stacktrace = data
    expected_security_flag = False
    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_golang_panic_runtime_error_index_out_of_range_with_msan(self):
    """Test golang stacktrace with panic caused by index out of range
    with memory sanitizer."""
    data = self._read_test_data(
        'golang_panic_runtime_error_index_out_of_range_with_msan.txt')
    expected_type = 'Index out of range'
    expected_address = ''
    expected_state = ('http.(*conn).serve.func1\n'
                      'http.HandlerFunc.ServeHTTP\n'
                      'http.(*ServeMux).ServeHTTP\n')
    expected_stacktrace = data
    expected_security_flag = False
    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_golang_panic_runtime_error_slice_bounds_out_of_range(self):
    """Test golang stacktrace with panic caused by slice bounds out of range."""
    data = self._read_test_data(
        'golang_panic_runtime_error_slice_bounds_out_of_range.txt')
    expected_type = 'Slice bounds out of range'
    expected_address = ''
    expected_state = ('json.(*decodeState).unquoteBytes\n'
                      'json.(*decodeState).literalStore\n'
                      'json.(*decodeState).object\n')

    expected_stacktrace = data
    expected_security_flag = False
    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_golang_panic_runtime_error_integer_divide_by_zero(self):
    """Test golang stacktrace with panic caused by integer divide by zero."""
    data = self._read_test_data(
        'golang_panic_runtime_error_integer_divide_by_zero.txt')
    expected_type = 'Integer divide by zero'
    expected_address = ''
    expected_state = ('go-bsbmp.(*SensorBMP180).ReadPressureMult10Pa\n'
                      'go-bsbmp.(*BMP).ReadAltitude\n')

    expected_stacktrace = data
    expected_security_flag = False
    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_golang_panic_runtime_error_makeslice_len_out_of_range(self):
    """Test golang stacktrace with panic caused by makeslice len out of range.
    """
    data = self._read_test_data(
        'golang_panic_runtime_error_makeslice_len_out_of_range.txt')
    expected_type = 'Makeslice: len out of range'
    expected_address = ''
    expected_state = 'gc.newliveness\ngc.liveness\ngc.compile\n'

    expected_stacktrace = data
    expected_security_flag = False
    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_golang_generic_fatal_error_and_asan_abrt(self):
    """Test golang stacktrace with a generic fatal error and ASan's ABRT
    signature that should be ignored for known golang crashes."""
    data = self._read_test_data('golang_generic_fatal_error_and_asan_abrt.txt')
    expected_type = 'Fatal error'
    expected_address = ''
    expected_state = 'error message here\njson.(*decodeState).unquoteBytes\n'

    expected_stacktrace = data
    expected_security_flag = False
    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_golang_generic_panic_and_asan_abrt(self):
    """Test golang stacktrace with a generic panic and ASan's ABRT signature
    that should be ignored for known golang crashes."""
    data = self._read_test_data('golang_generic_panic_and_asan_abrt.txt')
    expected_type = 'ASSERT'
    expected_address = ''
    expected_state = 'error message here\njson.(*decodeState).unquoteBytes\n'

    expected_stacktrace = data
    expected_security_flag = True
    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_golang_new_crash_type_and_asan_abrt(self):
    """Test golang stacktrace with an unknown message and ASan's ABRT signature
    that should be captured for unknown golang crashes."""
    data = self._read_test_data('golang_new_crash_type_and_asan_abrt.txt')
    expected_type = 'Abrt'
    expected_address = '0x000000000001'
    expected_state = 'NULL'

    expected_stacktrace = data
    expected_security_flag = False
    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_hwasan_allocation_tail_overwritten(self):
    """Test HWASan allocation tail overwritten crash."""
    data = self._read_test_data('hwasan_allocation_tail_overwritten.txt')
    expected_type = 'Allocation-tail-overwritten'
    expected_address = '0x00444b02b180'
    expected_state = 'frame1\nframe2\nframe3\n'

    expected_stacktrace = data
    expected_security_flag = True
    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_hwasan_tag_mismatch(self):
    """Test HWASan tag mismatch crash."""
    data = self._read_test_data('hwasan_tag_mismatch.txt')
    expected_type = 'Tag-mismatch\nREAD 8'
    expected_address = '0x0040e1287be0'
    expected_state = 'frame1\nframe2\nframe3\n'

    expected_stacktrace = data
    expected_security_flag = True
    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_missing_library_android(self):
    """Test for missing library crash (Android)."""
    data = self._read_test_data('missing_library_android.txt')
    expected_type = 'Missing-library'
    expected_address = ''
    expected_state = 'libvts_codecoverage.so\n'

    expected_stacktrace = data
    expected_security_flag = False
    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_missing_library_linux(self):
    """Test for missing library crash (Linux)."""
    data = self._read_test_data('missing_library_linux.txt')
    expected_type = 'Missing-library'
    expected_address = ''
    expected_state = 'libtest.so.1\n'

    expected_stacktrace = data
    expected_security_flag = False
    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_undetected_ubsan_error_logs_error(self):
    """Ensure that we log an error if we see an unknown UBSan error type."""
    data = self._read_test_data('ubsan_unknown_logs_error.txt')
    expected_type = 'UNKNOWN'
    expected_address = ''
    expected_state = 'a\nb\nc\n'
    expected_stacktrace = data
    expected_security_flag = False

    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

    self.mock.log_error.assert_called_once_with(
        'Unknown UBSan crash type: '
        'unsupported ubsan error that needs a new signature')

  def test_libfuzzer_overwrites_const_input(self):
    """Test for libFuzzer when target tries to overwrite const input."""
    os.environ['FUZZ_TARGET'] = 'ap-mgmt'
    data = self._read_test_data('libfuzzer_overwrites_const_input.txt')
    expected_type = 'Overwrites-const-input'
    expected_address = ''
    expected_state = 'ap-mgmt\n'

    expected_stacktrace = data
    expected_security_flag = False
    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_python_unhandled_exception(self):
    """Test python stacktrace with an unhandled exception."""
    data = self._read_test_data('python_unhandled_exception.txt')
    expected_type = 'Uncaught exception'
    expected_address = ''
    expected_state = '_read_exact\n_read_gzip_header\nread\n'

    expected_stacktrace = data
    expected_security_flag = False
    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_gdb_sigtrap(self):
    """Test for GDB stack."""
    data = self._read_test_data('gdb_sigtrap.txt')
    expected_type = 'SIGTRAP'
    expected_address = '0x000000000ac8'
    expected_state = (
        'xymodem_trnasfer\nLoadImageFromUsb30\nLoadBL1FromUsb30\n')
    expected_stacktrace = data
    expected_security_flag = True
    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_gdb_sigtrap_and_libfuzzer(self):
    """Test for GDB stack with libfuzzer."""
    data = self._read_test_data('gdb_sigtrap_and_libfuzzer.txt')
    expected_type = 'SIGTRAP'
    expected_address = '0x000000000ac8'
    expected_state = (
        'xymodem_trnasfer\nLoadImageFromUsb30\nLoadBL1FromUsb30\n')
    expected_stacktrace = data
    expected_security_flag = True
    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_rust_assert(self):
    """Test for assertion in Rust."""
    environment.set_value('ASSERTS_HAVE_SECURITY_IMPLICATION', False)

    data = self._read_test_data('rust_assert.txt')
    expected_type = 'ASSERT'
    expected_address = ''
    expected_state = (
        'Error: could not find an available port\n'
        'libra_config::utils::get_available_port::h7d7baacfb554bae8\n'
        'libra_json_rpc::fuzzing::fuzzer::hde487212e06dd4fd\n')
    expected_stacktrace = data
    expected_security_flag = False
    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_rust_oom(self):
    """Test for out of memory in Rust."""
    os.environ['REPORT_OOMS_AND_HANGS'] = 'True'

    data = self._read_test_data('rust_oom.txt')
    expected_type = 'Out-of-memory'
    expected_address = ''
    expected_state = (
        'mp4parse::fallible::TryVec$LT$T$GT$::reserve::h1159314b25b06f7c\n'
        'mp4parse::fallible::try_read_up_to::h64a356817b37893a\n'
        'mp4parse::fallible::TryRead::read_into_try_vec::h1a15ad50dda088e3\n')
    expected_stacktrace = data
    expected_security_flag = False
    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_rust_ignores(self):
    """Test that uninteresting frames are ignored for Rust."""
    environment.set_value('ASSERTS_HAVE_SECURITY_IMPLICATION', False)

    data = self._read_test_data('rust_ignores.txt')
    expected_type = 'ASSERT'
    expected_address = ''
    expected_state = (
        'called `Result::unwrap()` on an `Err` value: failed directive on '
        'wasmtime/crates\n'
        'wasmtime_fuzzing::oracles::spectest::ha380505b8ea313d4\n')
    expected_stacktrace = data
    expected_security_flag = False
    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_linux_kernel_library_libfuzzer(self):
    """Test Linux Kernel Library fuzzed with libfuzzer."""
    data = self._read_test_data('lkl_libfuzzer.txt')
    expected_type = 'Kernel failure\nSlab-out-of-bounds\nWRITE 4'
    expected_state = (
        'hid_generic_probe\nreally_probe\n__device_attach_driver\n')
    expected_address = '0x7f2a8ad06d18'
    expected_stacktrace = data
    expected_security_flag = True
    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_linux_kernel_library_libfuzzer_symbolized(self):
    """Test Linux Kernel Library fuzzed with libfuzzer symbolized."""
    data = self._read_test_data('lkl_libfuzzer_symbolized.txt')
    expected_type = 'Kernel failure\nSlab-out-of-bounds\nWRITE 4'
    expected_state = ('__hidinput_change_resolution_multipliers\n'
                      'hidinput_connect\n'
                      'hid_connect\n')
    expected_address = '0x7f5256480ddc'
    expected_stacktrace = data
    expected_security_flag = True
    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_linux_kernel_library_libfuzzer_unsymbolized(self):
    """Test Linux Kernel Library fuzzed with libfuzzer unsymbolized."""
    data = self._read_test_data('lkl_libfuzzer_unsymbolized.txt')
    expected_type = 'Kernel failure\nSlab-out-of-bounds\nWRITE 4'
    expected_state = ('hid_generic_probe\n'
                      'really_probe\n'
                      '__device_attach_driver\n')
    expected_address = '0x7f58af2ac9ec'
    expected_stacktrace = data
    expected_security_flag = True
    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)

  def test_swift(self):
    """Test swift stacktrace."""
    data = self._read_test_data('swift_invalid_free.txt')
    expected_type = 'Invalid-free'
    expected_state = ('SwiftProtobuf.BinaryDecoder.\n'
                      'SwiftProtobuf.BinaryDecoder.decodeSingularGroupField'
                      '<A where A: SwiftProtobuf.Me\n'
                      'protocol witness for SwiftProtobuf.Decoder.'
                      'decodeSingularGroupField<A where A1: \n')
    expected_address = '0x555f65177ff0'
    expected_stacktrace = data
    expected_security_flag = True
    self._validate_get_crash_data(data, expected_type, expected_address,
                                  expected_state, expected_stacktrace,
                                  expected_security_flag)
