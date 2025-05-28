# Copyright 2025 Google LLC
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
"""Events handler tests."""
import datetime
import os
import platform
import unittest

from clusterfuzz._internal.metrics import events
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils


@test_utils.with_cloud_emulators('datastore')
class EventsDataTest(unittest.TestCase):
  """Test event dataclasses."""

  def setUp(self):
    helpers.patch(self, ['clusterfuzz._internal.base.utils.get_instance_name'])
    self.original_env = dict(os.environ)
    os.environ['OS_OVERRIDE'] = 'linux'
    # Override reading the manifest file for the source version.
    os.environ['SOURCE_VERSION_OVERRIDE'] = ('20250402153042-utc-40773ac0-user'
                                             '-cad6977-prod')
    self.mock.get_instance_name.return_value = 'linux-bot'
    os.environ['CF_TASK_ID'] = 'f61826c3-ca9a-4b97-9c1e-9e6f4e4f8868'

    # Common metadata used for every event.
    self.common_metadata = {
        'clusterfuzz_version': '40773ac0',
        'clusterfuzz_config_version': 'cad6977',
        'instance_id': 'linux-bot',
        'operating_system': 'LINUX',
        'os_version': platform.release()
    }
    return super().setUp()

  def tearDown(self):
    os.environ.clear()
    os.environ.update(self.original_env)
    return super().tearDown()

  def _assert_event_common_fields(self, event, event_type, source):
    """Asserts for common event fields."""
    self.assertEqual(event.event_type, event_type)
    self.assertEqual(event.source, source)
    self.assertIsInstance(event.timestamp, datetime.datetime)
    for key, val in self.common_metadata.items():
      self.assertEqual(getattr(event, key, None), val)

  def _assert_testcase_fields(self, event, testcase):
    """Asserts for testcase-related event fields."""
    self.assertEqual(event.testcase_id, testcase.key.id())
    self.assertEqual(event.fuzzer, testcase.fuzzer_name)
    self.assertEqual(event.job, testcase.job_type)
    self.assertEqual(event.crash_revision, testcase.crash_revision)

  def test_generic_event(self):
    """Test base event class."""
    event_type = 'generic_event'
    source = 'events_test'
    event = events.Event(event_type=event_type, source=source)
    self._assert_event_common_fields(event, event_type, source)

  def test_testcase_event(self):
    """Test testcase event base class. """
    event_type = 'testcase_event'
    source = 'events_test'
    testcase = test_utils.create_generic_testcase()

    event = events.TestcaseEvent(
        event_type=event_type, source=source, testcase=testcase)
    self._assert_event_common_fields(event, event_type, source)
    self._assert_testcase_fields(event, testcase)

  def test_task_event(self):
    """Test task-related event base class."""
    event_type = 'testcase_event'
    source = 'events_test'

    event = events.TaskEvent(event_type=event_type, source=source)
    self.assertEqual(event.task_id, 'f61826c3-ca9a-4b97-9c1e-9e6f4e4f8868')
    self._assert_event_common_fields(event, event_type, source)

  def test_testcase_creation_events(self):
    """Test testcase creation event class."""
    source = 'events_test'
    testcase = test_utils.create_generic_testcase()

    event_creation_manual = events.TestcaseCreationEvent(
        source=source,
        testcase=testcase,
        origin='manual_upload',
        uploader='test@gmail.com')
    self._assert_event_common_fields(event_creation_manual, 'testcase_creation',
                                     source)
    self.assertEqual(event_creation_manual.origin, 'manual_upload')
    self.assertEqual(event_creation_manual.uploader, 'test@gmail.com')

    event_creation_fuzz = events.TestcaseCreationEvent(
        source=source, testcase=testcase, origin='fuzz_task')
    self._assert_event_common_fields(event_creation_fuzz, 'testcase_creation',
                                     source)
    self.assertEqual(event_creation_fuzz.origin, 'fuzz_task')
    self.assertIsNone(event_creation_fuzz.uploader)

  def test_testcase_rejection_event(self):
    """Test testcase rejection event class."""
    source = 'events_test'
    testcase = test_utils.create_generic_testcase()

    event_rejection = events.TestcaseRejectionEvent(
        source=source, testcase=testcase, reason='triage_duplicate_testcase')
    self.assertEqual(event_rejection.reason, 'triage_duplicate_testcase')
