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
"""Tests for jobs."""
import unittest

import flask
import webtest

from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from clusterfuzz._internal.tests.test_libs import test_utils
from handlers import crash_query

TEST_STACKTRACE_OVERFLOW = '''
=================================================================
==14479==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x615000000c80 at pc 0x000000c43002 bp 0x7ffc7ba6fae0 sp 0x7ffc7ba6fad8
WRITE of size 4 at 0x615000000c80 thread T0
SCARINESS: 36 (4-byte-write-heap-buffer-overflow)
    #0 0xc48001 in Foo foo.c:36:4
    #1 0x3d912f in Bar bar.c:2:6
    #2 0x41e77e in Main main.c:47:13
    #3 0x3f0778 in LLVMFuzzerTestOneInput fuzzer.cpp:12:1
    #4 0x4f216b in main
    #5 0x7f371939782f in __libc_start_main /build/glibc-LK5gWL/glibc-2.23/csu/libc-start.c:291
    #6 0x441bb8 in _start
SUMMARY: AddressSanitizer: heap-buffer-overflow ()
==14479==ABORTING
'''

TEST_STACKTRACE_OOM = '''
==1== ERROR: libFuzzer: out-of-memory (used: 2590Mb; limit: 2560Mb)
   To change the out-of-memory limit use -rss_limit_mb=<N>
SUMMARY: libFuzzer: out-of-memory
'''


@test_utils.with_cloud_emulators('datastore')
class CrashQueryTest(unittest.TestCase):
  """Jobs tests."""

  def setUp(self):
    test_helpers.patch(self, [
        'libs.auth.get_current_user',
    ])
    flaskapp = flask.Flask('testflask')
    flaskapp.add_url_rule('/', view_func=crash_query.Handler.as_view('/'))
    self.app = webtest.TestApp(flaskapp)

  def test_new(self):
    """Test new."""
    response = self.app.post_json(
        '/', {
            'project': 'project',
            'fuzz_target': 'target',
            'stacktrace': TEST_STACKTRACE_OVERFLOW,
        })

    self.assertEqual({
        'result': 'new',
        'type': 'Heap-buffer-overflow\nWRITE 4',
        'state': 'Foo\nBar\nMain\n',
        'security': True,
    }, response.json)

  def test_duplicate(self):
    """Test duplicate."""
    expected_crash_state = 'Foo\nBar\nMain\n'
    t = data_types.Testcase(
        open=True,
        status='Processed',
        crash_state=expected_crash_state,
        crash_type='Heap-buffer-overflow\nWRITE 4',
        project_name='project',
        security_flag=True)
    t.put()

    response = self.app.post_json(
        '/', {
            'project': 'project',
            'fuzz_target': 'target',
            'stacktrace': TEST_STACKTRACE_OVERFLOW,
        })
    self.assertEqual({
        'result': 'duplicate',
        'duplicate_id': 1,
        'type': 'Heap-buffer-overflow\nWRITE 4',
        'state': expected_crash_state,
        'security': True,
    }, response.json)

    t.group_bug_information = 123
    t.put()
    response = self.app.post_json(
        '/', {
            'project': 'project',
            'fuzz_target': 'target',
            'stacktrace': TEST_STACKTRACE_OVERFLOW,
        })
    self.assertEqual({
        'result': 'duplicate',
        'duplicate_id': 1,
        'bug_id': '123',
        'type': 'Heap-buffer-overflow\nWRITE 4',
        'state': expected_crash_state,
        'security': True,
    }, response.json)

    t.bug_information = '1337'
    t.put()
    response = self.app.post_json(
        '/', {
            'project': 'project',
            'fuzz_target': 'target',
            'stacktrace': TEST_STACKTRACE_OVERFLOW,
        })
    self.assertEqual({
        'result': 'duplicate',
        'duplicate_id': 1,
        'bug_id': '1337',
        'type': 'Heap-buffer-overflow\nWRITE 4',
        'state': expected_crash_state,
        'security': True,
    }, response.json)

  def test_oom(self):
    """Test OOM parsing."""
    response = self.app.post_json(
        '/', {
            'project': 'project',
            'fuzz_target': 'target',
            'stacktrace': TEST_STACKTRACE_OOM,
        })
    self.assertEqual({
        'result': 'new',
        'type': 'Out-of-memory',
        'state': 'target\n',
        'security': False,
    }, response.json)
