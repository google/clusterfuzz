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
import time
import unittest

from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
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

    self.assertEqual(event.clusterfuzz_version, '40773ac0')
    self.assertEqual(event.clusterfuzz_config_version, 'cad6977')
    self.assertEqual(event.instance_id, 'linux-bot')
    self.assertEqual(event.operating_system, 'LINUX')
    self.assertEqual(event.os_version, platform.release())

  def _assert_testcase_fields(self, event, testcase):
    """Asserts for testcase-related event fields."""
    self.assertEqual(event.testcase_id, testcase.key.id())
    # Values based on `test_utils.create_generic_testcase`.
    self.assertEqual(event.fuzzer, 'fuzzer1')
    self.assertEqual(event.job, 'test_content_shell_drt')
    self.assertEqual(event.crash_revision, 1)

  def test_generic_event(self):
    """Test base event class."""
    event_type = 'generic_event'
    source = 'events_test'
    event = events.Event(event_type=event_type, source=source)
    self._assert_event_common_fields(event, event_type, source)

  def test_event_timestamp(self):
    """Test event creation timestamp."""
    event_type = 'generic_event'
    early_event = events.Event(event_type=event_type)
    time.sleep(1)
    late_event = events.Event(event_type=event_type)
    self.assertGreater(late_event.timestamp, early_event.timestamp)

  def test_testcase_event(self):
    """Test testcase event base class. """
    event_type = 'testcase_event'
    source = 'events_test'
    testcase = test_utils.create_generic_testcase()

    event = events.BaseTestcaseEvent(
        event_type=event_type, source=source, testcase=testcase)
    self._assert_event_common_fields(event, event_type, source)
    self._assert_testcase_fields(event, testcase)

  def test_task_event(self):
    """Test task-related event base class."""
    event_type = 'testcase_event'
    source = 'events_test'

    event = events.BaseTaskEvent(event_type=event_type, source=source)
    self.assertEqual(event.task_id, 'f61826c3-ca9a-4b97-9c1e-9e6f4e4f8868')
    self._assert_event_common_fields(event, event_type, source)

  def test_testcase_creation_events(self):
    """Test testcase creation event class."""
    event_type = events.EventTypes.TESTCASE_CREATION.value
    source = 'events_test'
    testcase = test_utils.create_generic_testcase()

    event_creation_manual = events.TestcaseCreationEvent(
        source=source,
        testcase=testcase,
        origin='manual_upload',
        uploader='test@gmail.com')
    self._assert_event_common_fields(event_creation_manual, event_type, source)
    self.assertEqual(event_creation_manual.origin, 'manual_upload')
    self.assertEqual(event_creation_manual.uploader, 'test@gmail.com')

    event_creation_fuzz = events.TestcaseCreationEvent(
        source=source, testcase=testcase, origin='fuzz_task')
    self._assert_event_common_fields(event_creation_fuzz, event_type, source)
    self.assertEqual(event_creation_fuzz.origin, 'fuzz_task')
    self.assertIsNone(event_creation_fuzz.uploader)

  def test_mapping_event_classes(self):
    """Assert that all defined event types are in the classes map."""
    event_types = [e.value for e in events.EventTypes]
    event_types_classes = list(events._EVENT_TYPE_CLASSES.keys())  # pylint: disable=protected-access
    self.assertCountEqual(event_types, event_types_classes)


@test_utils.with_cloud_emulators('datastore')
class DatastoreEventsTest(unittest.TestCase):
  """Test event handling and emission with datastore repository."""

  def setUp(self):
    helpers.patch(self, ['clusterfuzz._internal.base.utils.get_instance_name'])
    self.original_env = dict(os.environ)

    self.repository = events.NDBEventRepository()

    # Set common metadata used by events.
    os.environ['OS_OVERRIDE'] = 'linux'
    # Override reading the manifest file for the source version.
    os.environ['SOURCE_VERSION_OVERRIDE'] = ('20250402153042-utc-40773ac0-user'
                                             '-cad6977-prod')
    self.mock.get_instance_name.return_value = 'linux-bot'
    os.environ['CF_TASK_ID'] = 'f61826c3-ca9a-4b97-9c1e-9e6f4e4f8868'
    return super().setUp()

  def tearDown(self):
    os.environ.clear()
    os.environ.update(self.original_env)
    return super().tearDown()

  def _set_common_event_fields(self, entity):
    """Set the common event fields to a datastore entity."""
    entity.clusterfuzz_version = '40773ac0'
    entity.clusterfuzz_config_version = 'cad6977'
    entity.instance_id = 'linux-bot'
    entity.operating_system = 'LINUX'
    entity.os_version = platform.release()

  def _assert_common_event_fields(self, event):
    """Assert common fields from an event."""
    self.assertEqual(event.clusterfuzz_version, '40773ac0')
    self.assertEqual(event.clusterfuzz_config_version, 'cad6977')
    self.assertEqual(event.instance_id, 'linux-bot')
    self.assertEqual(event.operating_system, 'LINUX')
    self.assertEqual(event.os_version, platform.release())

  def test_serialize_generic_event(self):
    """Test serializing a generic event into a datastore entity."""
    event_type = 'generic_event'
    source = 'events_test'
    event_gen = events.Event(event_type=event_type, source=source)
    event_entity = self.repository._serialize_event(event_gen)  # pylint: disable=protected-access

    self.assertIsNotNone(event_entity)
    # Currently, only the TestcaseLifecycleEvent data model is used.
    self.assertIsInstance(event_entity, data_types.TestcaseLifecycleEvent)

    self.assertEqual(event_entity.event_type, event_type)
    self.assertEqual(event_entity.source, source)
    self.assertEqual(event_entity.timestamp, event_gen.timestamp)
    self._assert_common_event_fields(event_entity)

  def test_serialize_testcase_specific_event(self):
    """Test serializing a testcase specific event into a datastore entity."""
    testcase = test_utils.create_generic_testcase()
    source = 'events_test'
    # Using testcase creation event for testing should be enough to test any
    # event type as long as it is mapped in the events module.
    event_tc_creation = events.TestcaseCreationEvent(
        source=source, testcase=testcase, origin='fuzz_task')
    event_type = event_tc_creation.event_type

    event_entity = self.repository._serialize_event(event_tc_creation)  # pylint: disable=protected-access
    self.assertIsNotNone(event_entity)
    self.assertIsInstance(event_entity, data_types.TestcaseLifecycleEvent)
    self.assertEqual(event_entity.event_type, event_type)
    self.assertEqual(event_entity.source, source)
    self.assertEqual(event_entity.timestamp, event_tc_creation.timestamp)
    self._assert_common_event_fields(event_entity)

    self.assertEqual(event_entity.origin, 'fuzz_task')
    self.assertIsNone(event_entity.uploader)

  def test_deserialize_generic_event(self):
    """Test deserializing a datastore event entity into an event class."""
    event_entity = data_types.TestcaseLifecycleEvent(event_type='generic_event')
    date_now = datetime.datetime.now()
    event_entity.timestamp = date_now
    event_entity.source = 'events_test'
    self._set_common_event_fields(event_entity)
    event_entity.put()

    event = self.repository._deserialize_event(event_entity)  # pylint: disable=protected-access
    self.assertIsNotNone(event)
    self.assertIsInstance(event, events.Event)
    self.assertEqual(event.event_type, 'generic_event')
    self.assertEqual(event.source, 'events_test')
    self.assertEqual(event.timestamp, date_now)
    self._assert_common_event_fields(event)

  def test_deserialize_testcase_event(self):
    """Test deserializing a datastore event entity into an specific event."""
    event_type = events.EventTypes.TESTCASE_CREATION.value
    date_now = datetime.datetime.now()

    event_entity = data_types.TestcaseLifecycleEvent(event_type=event_type)
    event_entity.timestamp = date_now
    event_entity.source = 'events_test'
    self._set_common_event_fields(event_entity)
    event_entity.task_id = 'f61826c3-ca9a-4b97-9c1e-9e6f4e4f8868'
    event_entity.testcase_id = 1
    event_entity.fuzzer = 'fuzzer1'
    event_entity.job = 'test_job'
    event_entity.crash_revision = 2
    event_entity.origin = 'manual_upload'
    event_entity.uploader = 'test@gmail.com'
    event_entity.put()

    event = self.repository._deserialize_event(event_entity)  # pylint: disable=protected-access
    self.assertIsNotNone(event)
    self.assertIsInstance(event, events.TestcaseCreationEvent)
    self.assertEqual(event.event_type, event_type)
    self.assertEqual(event.source, 'events_test')
    self.assertEqual(event.timestamp, date_now)
    self._assert_common_event_fields(event)
    self.assertEqual(event.task_id, 'f61826c3-ca9a-4b97-9c1e-9e6f4e4f8868')
    self.assertEqual(event.testcase_id, 1)
    self.assertEqual(event.fuzzer, 'fuzzer1')
    self.assertEqual(event.job, 'test_job')
    self.assertEqual(event.crash_revision, 2)
    self.assertEqual(event.origin, 'manual_upload')
    self.assertEqual(event.uploader, 'test@gmail.com')

  def test_store_event(self):
    """Test storing an event into datastore."""
    testcase = test_utils.create_generic_testcase()
    source = 'events_test'

    event_tc_creation = events.TestcaseCreationEvent(
        source=source, testcase=testcase, origin='fuzz_task')
    event_type = event_tc_creation.event_type
    eid = self.repository.store_event(event_tc_creation)
    self.assertIsNotNone(eid)

    event_entity = data_handler.get_entity_by_type_and_id(
        data_types.TestcaseLifecycleEvent, eid)
    self.assertIsNotNone(event_entity)
    self.assertEqual(event_entity.event_type, event_type)

  def test_get_event(self):
    """Test retrieving an event from datastore."""
    event_entity = data_types.TestcaseLifecycleEvent(
        event_type='generic_event_test')
    date_now = datetime.datetime.now()
    event_entity.timestamp = date_now
    event_entity.source = 'events_test'
    self._set_common_event_fields(event_entity)
    event_entity.put()
    event_id = event_entity.key.id()

    event = self.repository.get_event(event_id)
    self.assertIsNotNone(event)
    self.assertEqual(event.event_type, 'generic_event_test')
    self.assertIsInstance(event, events.Event)
