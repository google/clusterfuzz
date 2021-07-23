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
"""Tests for blame task."""
# pylint: disable=protected-access

import json
import unittest

from clusterfuzz._internal.bot.tasks import blame_task
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.tests.core.bot.tasks.component_revision_patching_test import \
    ComponentRevisionPatchingTest
from clusterfuzz._internal.tests.test_libs import test_utils


class ExtractUrlAndShaFromDepsEntryTest(unittest.TestCase):
  """Test _extract_url_and_sha_from_deps_entry."""

  def test_entry_with_git(self):
    """Ensure that we correctly break deps entries into URLs and SHAs."""
    entry = {
        'url': 'https://site/project.git',
        'rev': '46c07eef042cf06a07a333b41eb50c7d19686b5c'
    }
    url, sha = blame_task._extract_url_and_sha_from_deps_entry(entry)
    self.assertEqual(url, 'https://site/project')
    self.assertEqual(sha, '46c07eef042cf06a07a333b41eb50c7d19686b5c')

  def test_entry_without_git(self):
    entry = {
        'url': 'https://site/project',
        'rev': '0c3c7b36321ce9ddd56c2756ebc4946b2bb98823'
    }
    url, sha = blame_task._extract_url_and_sha_from_deps_entry(entry)
    self.assertEqual(url, 'https://site/project')
    self.assertEqual(sha, '0c3c7b36321ce9ddd56c2756ebc4946b2bb98823')

  def test_malformed_entry(self):
    with self.assertRaises(AssertionError):
      blame_task._extract_url_and_sha_from_deps_entry('malformed')


class ComputeRollsTest(unittest.TestCase):
  """Test _compute_rolls"""

  def test(self):
    """Test."""
    start_revisions_dict = {
        'src/a': {
            'url': 'https://domain/a',
            'rev': '2439bd08ff93d4dce761dd6b825917938bd35a4f'
        },
        'src/b': {
            'url': 'https://domain/b',
            'rev': '2439bd08ff93d4dce761dd6b825917938bd35a4f'
        },
        'src/c/d': {
            'url': 'https://domain/e',
            'rev': '1edde9d2fe203229c895b648fdec355917200ad6'
        }
    }
    end_revisions_dict = {
        'src/a': {
            'url': 'https://domain/a',
            'rev': '2439bd08ff93d4dce761dd6b825917938bd35a4f'
        },
        'src/b': {
            'url': 'https://domain/b',
            'rev': 'e9d71f5ee7c92d6dc9e92ffdad17b8bd49418f98'
        },
        'src/c/d': {
            'url': 'https://domain/f',
            'rev': '5bf1fd927dfb8679496a2e6cf00cbe50c1c87145'
        },
        'src/new': {
            'url': 'https://domain/new',
            'rev': '984844635245b39e82f7f931568393969acd5d31'
        }
    }

    expected_rolls = [
        {
            'dep_path': 'src/b',
            'repo_url': 'https://domain/b',
            'old_revision': '2439bd08ff93d4dce761dd6b825917938bd35a4f',
            'new_revision': 'e9d71f5ee7c92d6dc9e92ffdad17b8bd49418f98',
        },
        {
            'dep_path': 'src/c/d',
            'repo_url': 'https://domain/f',
            'old_revision': '1edde9d2fe203229c895b648fdec355917200ad6',
            'new_revision': '5bf1fd927dfb8679496a2e6cf00cbe50c1c87145',
        },
        {
            'dep_path': 'src/new',
            'repo_url': 'https://domain/new',
            'new_revision': '984844635245b39e82f7f931568393969acd5d31',
        },
    ]

    # Order is not important, but we must sort for comparison to the reference.
    actual_rolls = blame_task._compute_rolls(start_revisions_dict,
                                             end_revisions_dict)
    actual_rolls = sorted(actual_rolls, key=lambda roll: roll['dep_path'])

    self.assertEqual(actual_rolls, expected_rolls)


class FormatComponentRevisionsForPredator(unittest.TestCase):
  """Test _format_component_revisions_for_predator"""

  def test(self):
    """Test."""
    revisions_dict = {
        'src/a': {
            'url': 'https://domain/a',
            'rev': '2439bd08ff93d4dce761dd6b825917938bd35a4f'
        },
        'src/b': {
            'url': 'https://blah/b.git',
            'rev': '2439bd08ff93d4dce761dd6b825917938bd35a4f'
        },
        'src/c/d': {
            'url': 'https://domain/e',
            'rev': '1edde9d2fe203229c895b648fdec355917200ad6'
        }
    }

    expected_result = [
        {
            'dep_path': 'src/a',
            'repo_url': 'https://domain/a',
            'revision': '2439bd08ff93d4dce761dd6b825917938bd35a4f',
        },
        {
            'dep_path': 'src/b',
            'repo_url': 'https://blah/b',
            'revision': '2439bd08ff93d4dce761dd6b825917938bd35a4f',
        },
        {
            'dep_path': 'src/c/d',
            'repo_url': 'https://domain/e',
            'revision': '1edde9d2fe203229c895b648fdec355917200ad6',
        },
    ]

    # Order is not important, but we must sort for comparison to the reference.
    actual_result = blame_task._format_component_revisions_for_predator(
        revisions_dict)
    actual_result = sorted(actual_result, key=lambda roll: roll['dep_path'])

    self.assertEqual(actual_result, expected_result)


class PreparePredatorRequestBodyTest(ComponentRevisionPatchingTest):
  """Test prepare_predator_message."""

  def test_custom_binary(self):
    """Test custom binary."""
    environment.set_value('CUSTOM_BINARY', True)

    testcase = test_utils.create_generic_testcase()
    expected_result = {
        'result': {
            'error_message': 'Not applicable to custom binaries.',
            'feedback_url': '',
            'found': False,
            'project': '',
            'suspected_components': '',
            'suspected_cls': '',
        }
    }

    self.assertIsNone(blame_task._prepare_predator_message(testcase))

    testcase = data_handler.get_testcase_by_id(testcase.key.id())
    actual_result = testcase.get_metadata('predator_result')
    self.assertEqual(actual_result, expected_result)

    environment.remove_key('CUSTOM_BINARY')

  def test_reproducible_no_regression_range(self):
    """Test reproducible with no regression range."""
    testcase = test_utils.create_generic_testcase()
    testcase.one_time_crasher_flag = False
    testcase.regression = ''
    testcase.put()

    expected_result = {
        'result': {
            'error_message':
                'No regression range, wait for regression task to finish.',
            'feedback_url':
                '',
            'found':
                False,
            'project':
                '',
            'suspected_components':
                '',
            'suspected_cls':
                '',
        }
    }

    self.assertIsNone(blame_task._prepare_predator_message(testcase))

    testcase = data_handler.get_testcase_by_id(testcase.key.id())
    actual_result = testcase.get_metadata('predator_result')
    self.assertEqual(actual_result, expected_result)

  def test_reproducible_invalid_regression_range(self):
    """Test reproducible with invalid regression range."""
    testcase = test_utils.create_generic_testcase()
    testcase.one_time_crasher_flag = False
    testcase.regression = 'BAD'
    testcase.put()

    expected_result = {
        'result': {
            'error_message': 'Invalid regression range BAD.',
            'feedback_url': '',
            'found': False,
            'project': '',
            'suspected_components': '',
            'suspected_cls': '',
        }
    }

    self.assertIsNone(blame_task._prepare_predator_message(testcase))

    testcase = data_handler.get_testcase_by_id(testcase.key.id())
    actual_result = testcase.get_metadata('predator_result')
    self.assertEqual(actual_result, expected_result)

  def test_reproducible_regression_range(self):
    """Test reproducible with regression range."""
    testcase = test_utils.create_generic_testcase()
    testcase.crash_revision = 398287
    testcase.regression = '398287:399171'
    testcase.put()

    expected_message = {
        'stack_trace': 'crashy_function()',
        'customized_data': {
            'crash_address':
                '0xdeadbeef',
            'job_type':
                'test_content_shell_drt',
            'dependencies': [{
                'dep_path': 'src/third_party/bidichecker',
                'repo_url': 'https://chromium.googlesource.com/'
                            'external/bidichecker/lib',
                'revision': '97f2aa645b74c28c57eca56992235c79850fa9e0'
            }, {
                'dep_path': 'src/third_party/pdfium',
                'repo_url': 'https://pdfium.googlesource.com/pdfium',
                'revision': 'f7e108b2d0c2f67a143e99693df084bfff7037ec'
            }, {
                'dep_path': 'src/third_party/skia',
                'repo_url': 'https://skia.googlesource.com/skia',
                'revision': 'ee295645bd91fcbe1714847c5fe5341759037cc5'
            }, {
                'dep_path': 'src/v8',
                'repo_url': 'https://chromium.googlesource.com/v8/v8',
                'revision': 'cba1fdd4d72e7c5b874f9eeb07901792f26c871a'
            }, {
                'dep_path': 'src',
                'repo_url': 'https://chromium.googlesource.com/chromium/src',
                'revision': 'e4eb2a57c8667ab31903237e3c316fcaf4afe718'
            }],
            'dependency_rolls': [{
                'dep_path':
                    'src/third_party/gperf',
                'repo_url':
                    'https://chromium.googlesource.com/chromium/deps/gperf',
                'new_revision':
                    '97f2aa645b74c28c57eca56992235c79850fa9e0'
            }, {
                'dep_path': 'src/third_party/pdfium',
                'repo_url': 'https://pdfium.googlesource.com/pdfium',
                'new_revision': '855665d4889853f8ac71519de8ff004dba8eb056',
                'old_revision': 'f7e108b2d0c2f67a143e99693df084bfff7037ec'
            }, {
                'dep_path': 'src/third_party/skia',
                'repo_url': 'https://skia.googlesource.com/skia',
                'new_revision': '4772bd537d153922cd772020e4ad4820090be51a',
                'old_revision': 'ee295645bd91fcbe1714847c5fe5341759037cc5'
            }, {
                'dep_path': 'src/v8',
                'repo_url': 'https://chromium.googlesource.com/v8/v8',
                'new_revision': '3a590058de9b3640f73741b1e95f815f5c089988',
                'old_revision': 'cba1fdd4d72e7c5b874f9eeb07901792f26c871a'
            }, {
                'dep_path': 'src',
                'repo_url': 'https://chromium.googlesource.com/chromium/src',
                'new_revision': '52523d4e58d99cdb768791bf9ac532c917522460',
                'old_revision': 'e4eb2a57c8667ab31903237e3c316fcaf4afe718'
            }],
            'regression_range': {
                'old_revision': 'e4eb2a57c8667ab31903237e3c316fcaf4afe718',
                'new_revision': '52523d4e58d99cdb768791bf9ac532c917522460',
                'dep_path': 'src',
                'repo_url': 'https://chromium.googlesource.com/chromium/src'
            },
            'security_flag':
                False,
            'testcase_id':
                1,
            'sanitizer':
                'ASAN',
            'crash_type':
                'fake type'
        },
        'crash_revision': 'e4eb2a57c8667ab31903237e3c316fcaf4afe718',
        'platform': 'linux',
        'client_id': 'clusterfuzz',
        'signature': 'crashy_function()'
    }

    actual_message = blame_task._prepare_predator_message(testcase)
    actual_message = json.loads(actual_message.data)
    self.assertDictEqual(actual_message, expected_message)

  def test_reproducible_regression_range_with_zero_start_revision(self):
    """Test reproducible with regression range with 0 start."""
    testcase = test_utils.create_generic_testcase()
    testcase.crash_revision = 399171
    testcase.regression = '0:398287'
    testcase.put()

    expected_message = {
        'stack_trace': 'crashy_function()',
        'customized_data': {
            'crash_address':
                '0xdeadbeef',
            'job_type':
                'test_content_shell_drt',
            'dependencies': [{
                'dep_path':
                    'src/third_party/gperf',
                'repo_url':
                    'https://chromium.googlesource.com/chromium/deps/gperf',
                'revision':
                    '97f2aa645b74c28c57eca56992235c79850fa9e0'
            }, {
                'dep_path': 'src/third_party/pdfium',
                'repo_url': 'https://pdfium.googlesource.com/pdfium',
                'revision': '855665d4889853f8ac71519de8ff004dba8eb056'
            }, {
                'dep_path': 'src/third_party/skia',
                'repo_url': 'https://skia.googlesource.com/skia',
                'revision': '4772bd537d153922cd772020e4ad4820090be51a'
            }, {
                'dep_path': 'src/v8',
                'repo_url': 'https://chromium.googlesource.com/v8/v8',
                'revision': '3a590058de9b3640f73741b1e95f815f5c089988'
            }, {
                'dep_path': 'src',
                'repo_url': 'https://chromium.googlesource.com/chromium/src',
                'revision': '52523d4e58d99cdb768791bf9ac532c917522460'
            }],
            'dependency_rolls': [],
            'regression_range': {
                'old_revision': None,
                'new_revision': 'e4eb2a57c8667ab31903237e3c316fcaf4afe718',
                'dep_path': 'src',
                'repo_url': 'https://chromium.googlesource.com/chromium/src'
            },
            'security_flag':
                False,
            'testcase_id':
                1,
            'sanitizer':
                'ASAN',
            'crash_type':
                'fake type'
        },
        'crash_revision': '52523d4e58d99cdb768791bf9ac532c917522460',
        'platform': 'linux',
        'client_id': 'clusterfuzz',
        'signature': 'crashy_function()'
    }

    actual_message = blame_task._prepare_predator_message(testcase)
    actual_message = json.loads(actual_message.data)
    self.assertDictEqual(actual_message, expected_message)

  def test_unreproducible(self):
    """Test unreproducible."""
    testcase = test_utils.create_generic_testcase()
    testcase.one_time_crasher_flag = True
    testcase.crash_revision = 399171
    testcase.regression = 'NA'
    testcase.put()

    expected_message = {
        'stack_trace': 'crashy_function()',
        'customized_data': {
            'crash_address':
                '0xdeadbeef',
            'job_type':
                'test_content_shell_drt',
            'dependencies': [{
                'dep_path':
                    'src/third_party/gperf',
                'repo_url':
                    'https://chromium.googlesource.com/chromium/deps/gperf',
                'revision':
                    '97f2aa645b74c28c57eca56992235c79850fa9e0'
            }, {
                'dep_path': 'src/third_party/pdfium',
                'repo_url': 'https://pdfium.googlesource.com/pdfium',
                'revision': '855665d4889853f8ac71519de8ff004dba8eb056'
            }, {
                'dep_path': 'src/third_party/skia',
                'repo_url': 'https://skia.googlesource.com/skia',
                'revision': '4772bd537d153922cd772020e4ad4820090be51a'
            }, {
                'dep_path': 'src/v8',
                'repo_url': 'https://chromium.googlesource.com/v8/v8',
                'revision': '3a590058de9b3640f73741b1e95f815f5c089988'
            }, {
                'dep_path': 'src',
                'repo_url': 'https://chromium.googlesource.com/chromium/src',
                'revision': '52523d4e58d99cdb768791bf9ac532c917522460'
            }],
            'dependency_rolls': [],
            'regression_range': {
                'old_revision': None,
                'new_revision': None,
                'dep_path': 'src',
                'repo_url': 'https://chromium.googlesource.com/chromium/src'
            },
            'security_flag':
                False,
            'testcase_id':
                1,
            'sanitizer':
                'ASAN',
            'crash_type':
                'fake type'
        },
        'crash_revision': '52523d4e58d99cdb768791bf9ac532c917522460',
        'platform': 'linux',
        'client_id': 'clusterfuzz',
        'signature': 'crashy_function()'
    }

    actual_message = blame_task._prepare_predator_message(testcase)
    actual_message = json.loads(actual_message.data)
    self.assertDictEqual(actual_message, expected_message)


class FilterStacktraceTest(unittest.TestCase):
  """Tests for the _filter_stacktrace helper function."""

  def test_filter_uninteresting_lines(self):
    """Ensure that uninteresting lines are filtered."""
    stacktrace = (
        '[19622:19622:1006/184548.701693:VERBOSE1:bluez_dbus_manager.cc(172)] '
        'Bluetooth not supported.\n'
        '[19622:19622:1006/184548.717837:WARNING:browser_main_loop.cc(294)] '
        '<unknown>: atk-bridge: get_device_events_reply: unknown signature\n'
        'Interesting line 1\n'
        'Interesting line 2\n'
        'Interesting line 3')
    expected_filtered_stacktrace = ('Interesting line 1\n'
                                    'Interesting line 2\n'
                                    'Interesting line 3')
    actual_filtered_stacktrace = blame_task._filter_stacktrace(stacktrace)
    self.assertEqual(expected_filtered_stacktrace, actual_filtered_stacktrace)

  def test_filter_lengthy_stacktrace(self):
    """Ensure that we use the last few lines from a lengthy stacktrace."""
    stacktrace = 'A\n' * 500000
    expected_filtered_stacktrace = 'A\n' * 449999 + 'A'
    actual_filtered_stacktrace = blame_task._filter_stacktrace(stacktrace)
    self.assertEqual(expected_filtered_stacktrace, actual_filtered_stacktrace)
