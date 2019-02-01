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
"""show tests."""
# pylint: disable=protected-access
import datetime
import os
import unittest

from datastore import data_types
from handlers.testcase_detail import show
from libs import helpers
from tests.test_libs import helpers as test_helpers
from tests.test_libs import test_utils


class ParseSuspectedClsTest(unittest.TestCase):
  """Test _parse_suspected_cls."""

  def test_empty(self):
    """Test when we have no predator result."""
    self.assertIsNone(show._parse_suspected_cls(None))

  def test_all_present(self):
    """Ensure that we work properly when all expected fields are present."""
    raw_predator_result = {}
    raw_predator_result['result'] = {
        'found': True,
        'suspected_project': 'suspected-project',
        'suspected_components': ['A', 'B>C'],
        'suspected_cls': ['dummy cl'],
        'feedback_url': 'https://feedback/',
        'error_message': 'error string',
        'unused': 'unused',
    }

    # Note that this doesn't contain the "unused" field.
    expected_parsed_result = {
        'found': True,
        'suspected_project': 'suspected-project',
        'suspected_components': ['A', 'B>C'],
        'changelists': ['dummy cl'],
        'feedback_url': 'https://feedback/',
        'error_message': 'error string',
    }

    self.assertDictEqual(
        show._parse_suspected_cls(raw_predator_result), expected_parsed_result)

  def test_all_missing(self):
    """Ensure that we work properly if no expected fields are present."""
    raw_predator_result = {'result': {}}
    expected_parsed_result = {
        'found': None,
        'suspected_project': None,
        'suspected_components': None,
        'changelists': None,
        'feedback_url': None,
        'error_message': None,
    }

    self.assertDictEqual(
        show._parse_suspected_cls(raw_predator_result), expected_parsed_result)


class GetStackFramesTest(unittest.TestCase):
  """Test get_stack_frames."""

  def test_normal(self):
    """Test getting normal crash state."""
    self.assertEqual(show.get_stack_frames(['testtest']), ['testtest'])

  def test_bad_cast(self):
    """Test getting bad-cast."""
    lines = [
        'Bad-cast to content::RenderWidgetHostViewChildFrame1',
        'Bad-cast to content::RenderWidgetHostViewChildFrame1 from',
        ('Bad-cast to content::RenderWidgetHostViewChildFrame1 from'
         ' content::RenderWidgetHostViewAura'),
        ('Bad-cast to base::IsValueInRangeForNumericType<int>('
         ' std::floor(rect.x() * x_scale)) from invalid ptr')
    ]
    self.assertEqual(
        show.get_stack_frames(lines), [
            'content::RenderWidgetHostViewChildFrame1',
            'content::RenderWidgetHostViewChildFrame1',
            'content::RenderWidgetHostViewChildFrame1',
            ('base::IsValueInRangeForNumericType<int>( std::floor(rect.x()'
             ' * x_scale))'),
        ])

  def test_in(self):
    """Test getting frame in file."""
    lines = [
        'char_upper_api in file_path.cc',
        ('base::IsValueInRangeForNumericType<int>( std::floor(rect.x()'
         ' * x_scale)) in rect')
    ]
    self.assertEqual(
        show.get_stack_frames(lines), [
            'char_upper_api',
            ('base::IsValueInRangeForNumericType<int>( std::floor(rect.x()'
             ' * x_scale))')
        ])


class ConvertToLinesTest(unittest.TestCase):
  """Test convert_to_lines."""

  def test_empty(self):
    """Test empty trace."""
    self.assertEqual([], show.convert_to_lines('', [], ''))
    self.assertEqual([], show.convert_to_lines(' \n ', [], ''))

  def test_convert(self):
    """Test convert."""
    expected = [
        show.Line(1, 'a', False),
        show.Line(2, 'b', True),
        show.Line(3, 'c', True),
        show.Line(4, 'd', False),
        show.Line(5, 'e', False),
    ]
    self.assertEqual(expected,
                     show.convert_to_lines('a\nb\nc\nd\ne', ['b', 'c'], 'd'))

  def _test_special_type(self, crash_type):
    expected = [
        show.Line(1, 'a', False),
        show.Line(2, 'ERROR: something', True),
        show.Line(3, 'c', False),
        show.Line(4, 'SUMMARY: test', False),
        show.Line(5, 'e', False),
    ]
    self.assertEqual(
        expected,
        show.convert_to_lines('a\nERROR: something\nc\nSUMMARY: test\ne',
                              ['dontcare'], crash_type))

  def test_convert_out_of_memory(self):
    """Test convert out-of-memory."""
    self._test_special_type('Out-of-memory something')

  def test_convert_timeout(self):
    """Test convert timeout."""
    self._test_special_type('Timeout something')

  def test_convert_hang(self):
    """Test convert hang."""
    self._test_special_type('Hang something')

  def test_convert_v8_correctness(self):
    """Test convert V8 correctness failure."""
    self._test_special_type('V8 correctness failure something')


class PreviewStacktraceTest(unittest.TestCase):
  """Test _preview_stacktrace."""

  def _make(self, array):
    """Create either Line from a tuple or Gap from an int."""
    preview_lines_with_gaps = []
    line_number = 1
    for line in array:
      if isinstance(line, basestring):
        preview_lines_with_gaps.append(
            show.Line(line_number, line, line.startswith('t-')))
        line_number += 1
      else:
        line_number += line
        preview_lines_with_gaps.append(show.Gap(line))
    return preview_lines_with_gaps

  def test_empty(self):
    """Test empty stacktrace."""
    self.assertListEqual(show._preview_stacktrace([], 10, 3), [])

  def test_no_preview_small(self):
    """Test no preview because the stacktrace is so small."""
    lines = self._make(
        ['a', 'b', 'x', 'x', 'x', 't-c', 't-d', 't-e', 'x', 'x', 'x'])
    self.assertListEqual(show._preview_stacktrace(lines, 11, 5), [])

  def test_no_preview_no_match(self):
    """Test no preview because there is no important lines."""
    lines = self._make([
        'a', 'b', 'x', 'x', 'x', 'c', 'd', 'e', 'c', 'd', 'e', 'c', 'd', 'e',
        'x', 'x', 'x'
    ])
    self.assertListEqual(show._preview_stacktrace(lines, 11, 5), [])

  def test_preview_middle_and_end(self):
    """Test preview in the middle and in the end."""
    stack = self._make(
        ['a', 'b', 'z', 'x', 'x', 'x', 't-c', 't-d', 't-e', 'x', 'x', 'x', 'z'])
    expected = self._make([
        3,
        'x',
        'x',
        'x',
        't-c',
        't-d',
        't-e',
        'x',
        'x',
        'x',
        1,
    ])
    result = show._preview_stacktrace(stack, 10, 3)
    self.assertListEqual(result, expected)

  def test_preview_two_parts(self):
    """Test preview in 2 parts in the middle."""
    stack = self._make([
        'a', 'b', 'z', 'x', 'x', 'x', 't-c', 't-d', 't-e', 'x', 'x', 'x', 'z',
        'x', 'x', 'x', 't-c', 'x', 'x', 'x', 'x', 'x', 'z'
    ])
    expected = self._make([
        3, 'x', 'x', 'x', 't-c', 't-d', 't-e', 'x', 'x', 'x', 1, 'x', 'x', 'x',
        't-c', 'x', 'x', 'x', 3
    ])
    result = show._preview_stacktrace(stack, 16, 3)
    self.assertListEqual(result, expected)

  def test_preview_two_parts_hit_limit(self):
    """Test preview in 2 parts in the middle and hit limit."""
    stack = self._make([
        'a', 'b', 'z', 'x', 'x', 'x', 't-c', 't-d', 't-e', 'x', 'x', 'x', 'z',
        'x', 'x', 'x', 't-c', 'x', 'x', 'x', 'x', 'x', 'z'
    ])
    expected = self._make([
        3,
        'x',
        'x',
        'x',
        't-c',
        't-d',
        't-e',
        'x',
        13,
    ])
    result = show._preview_stacktrace(stack, 7, 3)
    self.assertListEqual(result, expected)


class HighlightCommonStackFramesTest(unittest.TestCase):
  """Test highlight_common_stack_frames."""

  def test_highlight(self):
    """Ensure it highlights the last 3 lines of the first two crash stacks."""
    stack = '\n'.join([
        'random', '#0 0x3 test0', '#1 0x2 test2', '#2 0x1 test1',
        '#3 0x0 test0', 'random', '#0 0x4 test4', '#1 0x2 test2',
        '#2 0x1 test1', '#3 0x0 test0', 'random', '#0 0x5 test5',
        '#1 0x2 test2', '#2 0x1 test1', '#3 0x0 test0'
    ])
    expected = '\n'.join([
        'random', '#0 0x3 test0', '<b>#1 0x2 test2</b>', '<b>#2 0x1 test1</b>',
        '<b>#3 0x0 test0</b>', 'random', '#0 0x4 test4', '<b>#1 0x2 test2</b>',
        '<b>#2 0x1 test1</b>', '<b>#3 0x0 test0</b>', 'random', '#0 0x5 test5',
        '#1 0x2 test2', '#2 0x1 test1', '#3 0x0 test0'
    ])
    self.assertEqual(show.highlight_common_stack_frames(stack), expected)

  def test_one_stack_frame(self):
    """Ensure it does nothing when there's only one stack frame"""
    stack = '\n'.join([
        'random', '#0 0x3 test0', '#1 0x2 test2', '#2 0x1 test1',
        '#3 0x0 test0', 'random'
    ])
    self.assertEqual(show.highlight_common_stack_frames(stack), stack)


class FilterStacktraceTest(unittest.TestCase):
  """Test filter_stacktrace."""

  def setUp(self):
    test_helpers.patch(self, [
        'handlers.testcase_detail.show.highlight_common_stack_frames',
    ])

    def highlight(stacktrace):
      return stacktrace

    self.mock.highlight_common_stack_frames.side_effect = highlight

  def test_clean(self):
    """Ensure it cleans trace with stack_clean_regex."""
    stack = 'aaaa\nbbbb\ncccc\naaaa\nbbbb\ncccc'
    expected = 'aaaa\ncccc\naaaa\ncccc'
    self.assertEqual(show.filter_stacktrace(stack, 'type', 'bb', {}), expected)

  def test_xss(self):
    """Ensure that we escape untrusted stacktrace."""
    stack = 'aaaa\n<script>alert("XSS")</script>\ncccc'
    expected = 'aaaa\n&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;\ncccc'
    self.assertEqual(show.filter_stacktrace(stack, 'type', '', {}), expected)

  def test_asan_chromium(self):
    """Ensure it linkifies asan trace for chromium."""
    revisions_dict = {
        '/src': {
            'url': 'https://chromium.googlesource.com/chromium/src.git',
            'rev': '1d783bc2a3629b94c963debfa3feaee27092dd92',
        },
        'src/v8': {
            'url': 'https://chromium.googlesource.com/v8/v8.git',
            'rev': '7fb2c3b6db3f889ea95851ca11dcb731b07a7925',
        }
    }
    stack = '\n'.join(
        [r'#1 0xa6760 in Test /build/src/v8/src/api.cc:3', r'random'])

    expected = ('#1 0xa6760 in Test <a href="'
                'https://chromium.googlesource.com/v8/v8/+/'
                '7fb2c3b6db3f889ea95851ca11dcb731b07a7925/src/api.cc#3">'
                'v8/src/api.cc:3'
                '</a>\n'
                'random')
    self.assertEqual(
        show.filter_stacktrace(stack, 'type', '', revisions_dict), expected)

  def test_asan_oss_fuzz(self):
    """Ensure it linkifies asan trace for oss-fuzz."""
    revisions_dict = {
        '/src/libass': {
            'url': 'https://github.com/libass/libass.git',
            'rev': '35dc4dd0e14e3afb4a2c7e319a3f4110e20c7cf2',
            'type': 'git'
        },
        '/src/fribidi': {
            'url': 'https://github.com/behdad/fribidi.git',
            'rev': '881b8d891cc61989ab8811b74d0e721f72bf913b',
            'type': 'git'
        }
    }
    stack = '\n'.join(
        [r'#1 0xa6760 in Test /src/fribidi/lib/common.h:3', r'random'])

    expected = ('#1 0xa6760 in Test <a href="'
                'https://github.com/behdad/fribidi/blob/'
                '881b8d891cc61989ab8811b74d0e721f72bf913b/lib/common.h#L3">'
                'fribidi/lib/common.h:3'
                '</a>\n'
                'random')
    self.assertEqual(
        show.filter_stacktrace(stack, 'type', '', revisions_dict), expected)

  def test_asan_v8(self):
    """Ensure it linkifies v8 win trace for chromium."""
    revisions_dict = {
        '/src': {
            'url': 'https://chromium.googlesource.com/v8/v8.git',
            'rev': '7fb2c3b6db3f889ea95851ca11dcb731b07a7925',
        }
    }
    stack = '\n'.join([(r'v8::internal::RootVisitor::VisitRootPointer '
                        r'[0x011517C5+53] (C:\b\c\b\win_asan_release\src\v8'
                        r'\src\visitors.h:69)'), r'random'])
    expected = ('v8::internal::RootVisitor::VisitRootPointer [0x011517C5+53] '
                '(<a href="https://chromium.googlesource.com/v8/v8/+/'
                '7fb2c3b6db3f889ea95851ca11dcb731b07a7925/v8/src/visitors.h#69"'
                '>v8/src/visitors.h:69</a>)\n'
                'random')

    self.assertEqual(
        show.filter_stacktrace(stack, 'type', '', revisions_dict), expected)

  def test_no_linkify(self):
    """Ensure that we don't linkify a non-stack frame line."""
    revisions_dict = {
        '/src': {
            'url': 'https://chromium.googlesource.com/chromium/src.git',
            'rev': '1d783bc2a3629b94c963debfa3feaee27092dd92',
        },
        'src/v8': {
            'url': 'https://chromium.googlesource.com/v8/v8.git',
            'rev': '7fb2c3b6db3f889ea95851ca11dcb731b07a7925',
        }
    }
    stack = '\n'.join([
        ('../../net/spdy/chromium/spdy_stream.cc:227:21: runtime error: '
         'signed integer overflow:159714659 + 1996488831 cannot be represented '
         'in type \'int\''), 'random'
    ])
    expected = stack

    self.assertEqual(
        show.filter_stacktrace(stack, 'type', '', revisions_dict), expected)


@test_utils.with_cloud_emulators('datastore')
class GetTestcaseTest(unittest.TestCase):
  """Test get_testcase."""

  def setUp(self):
    test_helpers.patch_environ(self)
    test_helpers.patch(self, [
        'metrics.crash_stats.get_last_crash_time',
        'datastore.data_types.Job.get_environment',
        'config.db_config.get',
        'config.db_config.get_value',
        'config.db_config.get_value_for_job',
        'build_management.revisions.get_component_range_list',
        'build_management.revisions.get_component_revisions_dict',
        'datastore.data_handler.get_stacktrace',
        'issue_management.issue_tracker_utils.get_issue_url',
        'libs.access.has_access',
        'libs.helpers.get_user_email',
        'libs.access.can_user_access_testcase',
        'handlers.testcase_detail.show.filter_stacktrace',
        'libs.form.generate_csrf_token',
    ])

    self.mock.has_access.return_value = False
    self.mock.get_user_email.return_value = 'test@test.com'

    self.mock.get_component_range_list.return_value = [{
        'component': 'name',
        'link_text': '0:revision'
    }]

    self.mock.get_component_revisions_dict.return_value = {
        '/src': {
            'name': 'name',
            'rev': 'revision'
        }
    }

    self.make_token().put()
    os.environ['ISSUE_TRACKER'] = 'test-issue-tracker'

  def make_token(self):
    token = data_types.CSRFToken()
    token.user_email = self.mock.get_user_email.return_value
    return token

  def test_no_testcase_id(self):
    """Test no testcase id."""
    with self.assertRaises(helpers.EarlyExitException) as cm:
      show.get_testcase_detail_by_id(None)

    self.assertEqual(cm.exception.status, 404)
    self.assertEqual(cm.exception.message, 'No test case specified!')

  def test_no_testcase(self):
    """Test invalid testcase."""
    with self.assertRaises(helpers.EarlyExitException) as cm:
      show.get_testcase_detail_by_id(1)

    self.assertEqual(cm.exception.status, 404)
    self.assertEqual(cm.exception.message, 'Invalid test case!')

  def test_forbidden(self):
    """Test forbidden testcase."""
    self.mock.can_user_access_testcase.return_value = False
    data_types.Testcase().put()

    with self.assertRaises(helpers.EarlyExitException) as cm:
      show.get_testcase_detail_by_id(2)

    self.assertEqual(cm.exception.status, 403)
    self.assertEqual(cm.exception.message, '')

  def test_reproducible_get(self):
    """Test valid reproducible testcase."""
    testcase = data_types.Testcase()
    testcase.job_type = 'linux_asan_chrome'
    testcase.crash_type = 'crash_type1\ncrash_type2'
    testcase.crash_address = 'crash_address'
    testcase.crash_state = 'crash_state'
    testcase.crash_revision = 123
    testcase.regression = None
    testcase.fixed = None
    testcase.fuzzed_keys = None
    testcase.minimized_keys = None
    testcase.timestamp = datetime.datetime(1970, 1, 1)
    testcase.project_name = 'chromium'
    testcase.one_time_crasher_flag = False
    testcase.put()

    job = data_types.Job()
    job.name = 'linux_asan_chrome'
    job.custom_binary_revision = 1234
    job.put()

    self.mock.can_user_access_testcase.return_value = True
    self.mock.get_issue_url.return_value = 'issue_url'
    self.mock.get_stacktrace.return_value = 'crash_stacktrace'
    self.mock.filter_stacktrace.return_value = 'crash_stacktrace'
    self.mock.get_environment.return_value = ({'HELP_URL': 'help_url'})
    self.mock.generate_csrf_token.return_value = 'csrf'

    result = show.get_testcase_detail_by_id(2)
    expected_subset = {
        'id': 2,
        'crash_type': 'crash_type1 crash_type2',
        'crash_address': 'crash_address',
        'crash_state': 'crash_state',
        'crash_state_lines': ['crash_state'],
        'crash_revision': 123,
        'csrf_token': 'csrf',
        'external_user': True,
        'footer': '',
        'fixed': 'NO',
        'issue_url': 'issue_url',
        'metadata': {},
        'minimized_testcase_size': '',
        'needs_refresh': True,
        'original_testcase_size': '',
        'privileged_user': False,
        'regression': 'Pending',
        'security_severity': None,
        'show_impact': True,
        'show_blame': True,
        'auto_delete_timestamp': None,
        'auto_close_timestamp': None,
        'memory_tool_display_label': 'Sanitizer',
        'memory_tool_display_value': 'address (ASAN)',
        'last_tested': 'name: 0:revision<br />',
        'is_admin_or_not_oss_fuzz': True,
        'has_issue_tracker': True,
        'reproduction_help_url': 'help_url',
    }

    self.maxDiff = None  # pylint: disable=invalid-name
    self.assertDictContainsSubset(expected_subset, result)
    self.assertEqual(result['testcase'].key.id(), testcase.key.id())

    self.assertDictContainsSubset({
        'lines': [show.Line(1, 'crash_stacktrace', False)]
    }, result['crash_stacktrace'])
    self.assertDictContainsSubset({
        'lines': [show.Line(1, 'crash_stacktrace', False)]
    }, result['second_crash_stacktrace'])
    self.assertDictContainsSubset({
        'lines': [show.Line(1, 'crash_stacktrace', False)]
    }, result['last_tested_crash_stacktrace'])

  def test_unreproducible_get(self):
    """Test valid unreproducible testcase."""
    self.mock.get_last_crash_time.return_value = datetime.datetime(2000, 1, 1)

    testcase = data_types.Testcase()
    testcase.job_type = 'windows_asan_chrome'
    testcase.crash_type = 'crash_type1\ncrash_type2'
    testcase.crash_address = 'crash_address'
    testcase.crash_state = 'crash_state'
    testcase.crash_revision = 123
    testcase.regression = None
    testcase.fixed = None
    testcase.fuzzed_keys = None
    testcase.minimized_keys = None
    testcase.timestamp = datetime.datetime(1970, 1, 1)
    testcase.project_name = 'chromium'
    testcase.one_time_crasher_flag = True
    testcase.put()

    job = data_types.Job()
    job.name = 'windows_asan_chrome'
    job.custom_binary_revision = 1234
    job.put()

    self.mock.can_user_access_testcase.return_value = True
    self.mock.get_issue_url.return_value = 'issue_url'
    self.mock.get_stacktrace.return_value = 'crash_stacktrace'
    self.mock.filter_stacktrace.return_value = 'crash_stacktrace'
    self.mock.get_environment.return_value = ({'HELP_URL': 'help_url'})
    self.mock.generate_csrf_token.return_value = 'csrf'

    result = show.get_testcase_detail_by_id(2)
    expected_subset = {
        'id': 2,
        'crash_type': 'crash_type1 crash_type2',
        'crash_address': 'crash_address',
        'crash_state': 'crash_state',
        'crash_state_lines': ['crash_state'],
        'crash_revision': 123,
        'csrf_token': 'csrf',
        'external_user': True,
        'footer': '',
        'fixed': 'NO',
        'issue_url': 'issue_url',
        'metadata': {},
        'minimized_testcase_size': '',
        'needs_refresh': True,
        'original_testcase_size': '',
        'privileged_user': False,
        'regression': 'Pending',
        'security_severity': None,
        'show_impact': False,
        'show_blame': True,
        'auto_delete_timestamp': 947289600.0,
        'auto_close_timestamp': None,
        'memory_tool_display_label': 'Sanitizer',
        'memory_tool_display_value': 'address (ASAN)',
        'last_tested': 'name: 0:revision<br />',
        'is_admin_or_not_oss_fuzz': True,
        'has_issue_tracker': True,
        'reproduction_help_url': 'help_url',
    }

    self.maxDiff = None  # pylint: disable=invalid-name
    self.assertDictContainsSubset(expected_subset, result)
    self.assertEqual(result['testcase'].key.id(), testcase.key.id())

    self.assertDictContainsSubset({
        'lines': [show.Line(1, 'crash_stacktrace', False)]
    }, result['crash_stacktrace'])
    self.assertDictContainsSubset({
        'lines': [show.Line(1, 'crash_stacktrace', False)]
    }, result['second_crash_stacktrace'])
    self.assertDictContainsSubset({
        'lines': [show.Line(1, 'crash_stacktrace', False)]
    }, result['last_tested_crash_stacktrace'])
