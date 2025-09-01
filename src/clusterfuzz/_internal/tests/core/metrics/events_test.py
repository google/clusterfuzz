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
from typing import Generator
import unittest

from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.metrics import events
from clusterfuzz._internal.protos import uworker_msg_pb2
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils


@test_utils.with_cloud_emulators('datastore')
class EventsDataTest(unittest.TestCase):
  """Test event dataclasses."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.base.utils.get_instance_name',
        'clusterfuzz._internal.metrics.events._get_datetime_now'
    ])
    self.original_env = dict(os.environ)
    os.environ['OS_OVERRIDE'] = 'linux'
    # Override reading the manifest file for the source version.
    os.environ['SOURCE_VERSION_OVERRIDE'] = ('20250402153042-utc-40773ac0-user'
                                             '-cad6977-prod')
    self.mock.get_instance_name.return_value = 'linux-bot'

    os.environ['CF_TASK_ID'] = 'f61826c3-ca9a-4b97-9c1e-9e6f4e4f8868'
    os.environ['CF_TASK_NAME'] = 'fuzz'

    self.date_now = datetime.datetime(2025, 1, 1, 10, 30, 15)
    self.mock._get_datetime_now.return_value = self.date_now  # pylint: disable=protected-access
    return super().setUp()

  def tearDown(self):
    os.environ.clear()
    os.environ.update(self.original_env)
    return super().tearDown()

  def _assert_event_common_fields(self, event, event_type, source):
    """Asserts for common event fields."""
    self.assertEqual(event.event_type, event_type)
    self.assertEqual(event.source, source)
    self.assertEqual(event.timestamp, self.date_now)

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

  def _assert_task_fields(self, event):
    """Asserts task-related event fields."""
    self.assertEqual(event.task_id, 'f61826c3-ca9a-4b97-9c1e-9e6f4e4f8868')
    self.assertEqual(event.task_name, 'fuzz')

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
    self.assertEqual(event.task_name, 'fuzz')
    self._assert_event_common_fields(event, event_type, source)

  def test_testcase_creation_events(self):
    """Test testcase creation event class."""
    event_type = events.EventTypes.TESTCASE_CREATION
    source = 'events_test'
    testcase = test_utils.create_generic_testcase()

    event_creation_manual = events.TestcaseCreationEvent(
        source=source,
        testcase=testcase,
        creation_origin=events.TestcaseOrigin.MANUAL_UPLOAD,
        uploader='test@gmail.com')
    self._assert_event_common_fields(event_creation_manual, event_type, source)
    self._assert_testcase_fields(event_creation_manual, testcase)
    self._assert_task_fields(event_creation_manual)
    self.assertEqual(event_creation_manual.creation_origin,
                     events.TestcaseOrigin.MANUAL_UPLOAD)
    self.assertEqual(event_creation_manual.uploader, 'test@gmail.com')

    event_creation_fuzz = events.TestcaseCreationEvent(
        source=source,
        testcase=testcase,
        creation_origin=events.TestcaseOrigin.FUZZ_TASK)
    self._assert_event_common_fields(event_creation_fuzz, event_type, source)
    self._assert_testcase_fields(event_creation_fuzz, testcase)
    self._assert_task_fields(event_creation_fuzz)
    self.assertEqual(event_creation_fuzz.creation_origin,
                     events.TestcaseOrigin.FUZZ_TASK)
    self.assertIsNone(event_creation_fuzz.uploader)

  def test_testcase_rejection_event(self):
    """Test testcase rejection event class."""
    event_type = events.EventTypes.TESTCASE_REJECTION
    source = 'events_test'
    testcase = test_utils.create_generic_testcase()

    event_rejection = events.TestcaseRejectionEvent(
        source=source,
        testcase=testcase,
        rejection_reason=events.RejectionReason.ANALYZE_NO_REPRO)
    self._assert_event_common_fields(event_rejection, event_type, source)
    self._assert_testcase_fields(event_rejection, testcase)
    self._assert_task_fields(event_rejection)
    self.assertEqual(event_rejection.rejection_reason,
                     events.RejectionReason.ANALYZE_NO_REPRO)

  def test_testcase_fixed_event(self):
    """Test testcase fixed event class."""
    event_type = events.EventTypes.TESTCASE_FIXED
    source = 'events_test'
    testcase = test_utils.create_generic_testcase()

    event_fixed = events.TestcaseFixedEvent(
        source=source, testcase=testcase, fixed_revision='1:2')

    self._assert_event_common_fields(event_fixed, event_type, source)
    self._assert_testcase_fields(event_fixed, testcase)
    self._assert_task_fields(event_fixed)
    self.assertEqual(event_fixed.fixed_revision, '1:2')

  def test_issue_filing_event(self):
    """Test issue filing event class."""
    event_type = events.EventTypes.ISSUE_FILING
    source = 'events_test'
    testcase = test_utils.create_generic_testcase()

    event_filing = events.IssueFilingEvent(
        source=source,
        testcase=testcase,
        issue_tracker_project='oss-fuzz',
        issue_id='12345',
        issue_created=True)
    self._assert_event_common_fields(event_filing, event_type, source)
    self._assert_testcase_fields(event_filing, testcase)
    self._assert_task_fields(event_filing)
    self.assertEqual(event_filing.issue_tracker_project, 'oss-fuzz')
    self.assertEqual(event_filing.issue_id, '12345')
    self.assertTrue(event_filing.issue_created)

  def test_issue_closing_event(self):
    """Test issue closing event class."""
    event_type = events.EventTypes.ISSUE_CLOSING
    source = 'events_test'
    testcase = test_utils.create_generic_testcase()

    event_closing = events.IssueClosingEvent(
        source=source,
        testcase=testcase,
        issue_tracker_project='oss-fuzz',
        issue_id='12345',
        closing_reason=events.ClosingReason.TESTCASE_FIXED)
    self._assert_event_common_fields(event_closing, event_type, source)
    self._assert_testcase_fields(event_closing, testcase)
    self._assert_task_fields(event_closing)
    self.assertEqual(event_closing.issue_tracker_project, 'oss-fuzz')
    self.assertEqual(event_closing.issue_id, '12345')
    self.assertEqual(event_closing.closing_reason,
                     events.ClosingReason.TESTCASE_FIXED)

  def test_testcase_grouping_event(self):
    """Test testcase grouping event class."""
    event_type = events.EventTypes.TESTCASE_GROUPING
    source = 'events_test'
    testcase = test_utils.create_generic_testcase()
    similar_testcase_id = 2

    # Testcase is similar to another one.
    event_grouping = events.TestcaseGroupingEvent(
        source=source,
        testcase=testcase,
        group_id=10,
        previous_group_id=0,
        similar_testcase_id=similar_testcase_id,
        grouping_reason=events.GroupingReason.SIMILAR_CRASH)
    self._assert_event_common_fields(event_grouping, event_type, source)
    self._assert_testcase_fields(event_grouping, testcase)
    self._assert_task_fields(event_grouping)
    self.assertEqual(event_grouping.group_id, 10)
    self.assertEqual(event_grouping.previous_group_id, 0)
    self.assertEqual(event_grouping.similar_testcase_id, similar_testcase_id)
    self.assertEqual(event_grouping.grouping_reason,
                     events.GroupingReason.SIMILAR_CRASH)
    self.assertEqual(event_grouping.group_merge_reason, None)

    # Testcase's group is being merged.
    event_grouping = events.TestcaseGroupingEvent(
        source=source,
        testcase=testcase,
        group_id=10,
        previous_group_id=5,
        similar_testcase_id=similar_testcase_id,
        grouping_reason=events.GroupingReason.GROUP_MERGE,
        group_merge_reason=events.GroupingReason.SAME_ISSUE)
    self._assert_event_common_fields(event_grouping, event_type, source)
    self._assert_testcase_fields(event_grouping, testcase)
    self._assert_task_fields(event_grouping)
    self.assertEqual(event_grouping.group_id, 10)
    self.assertEqual(event_grouping.previous_group_id, 5)
    self.assertEqual(event_grouping.similar_testcase_id, similar_testcase_id)
    self.assertEqual(event_grouping.grouping_reason,
                     events.GroupingReason.GROUP_MERGE)
    self.assertEqual(event_grouping.group_merge_reason,
                     events.GroupingReason.SAME_ISSUE)

  def test_task_execution_event(self):
    """Test task execution events."""
    job_type = 'job_test'
    fuzzer_name = 'fuzzer_test'
    testcase_id = 1
    event_type = events.EventTypes.TASK_EXECUTION
    source = 'events_test'

    event_task_exec_pre = events.TaskExecutionEvent(
        source=source,
        testcase_id=testcase_id,
        task_job=job_type,
        task_fuzzer=fuzzer_name,
        task_stage=events.TaskStage.PREPROCESS,
        task_status=events.TaskStatus.STARTED)
    self._assert_event_common_fields(event_task_exec_pre, event_type, source)
    self._assert_task_fields(event_task_exec_pre)
    self.assertEqual(event_task_exec_pre.task_stage,
                     events.TaskStage.PREPROCESS)
    self.assertEqual(event_task_exec_pre.task_status, events.TaskStatus.STARTED)
    self.assertIsNone(event_task_exec_pre.task_outcome)
    self.assertEqual(event_task_exec_pre.task_job, job_type)
    self.assertEqual(event_task_exec_pre.task_fuzzer, fuzzer_name)
    self.assertEqual(event_task_exec_pre.testcase_id, testcase_id)

    task_outcome = uworker_msg_pb2.ErrorType.Name(
        uworker_msg_pb2.ErrorType.MINIMIZE_UNREPRODUCIBLE_CRASH)
    event_task_exec_post_finish = events.TaskExecutionEvent(
        source=source,
        testcase_id=testcase_id,
        task_job=job_type,
        task_fuzzer=fuzzer_name,
        task_stage=events.TaskStage.POSTPROCESS,
        task_status=events.TaskStatus.POST_COMPLETED,
        task_outcome=task_outcome)
    self._assert_event_common_fields(event_task_exec_post_finish, event_type,
                                     source)
    self._assert_task_fields(event_task_exec_post_finish)
    self.assertEqual(event_task_exec_post_finish.task_stage,
                     events.TaskStage.POSTPROCESS)
    self.assertEqual(event_task_exec_post_finish.task_status,
                     events.TaskStatus.POST_COMPLETED)
    self.assertEqual(event_task_exec_post_finish.task_outcome, task_outcome)
    self.assertEqual(event_task_exec_post_finish.task_job, job_type)
    self.assertEqual(event_task_exec_post_finish.task_fuzzer, fuzzer_name)
    self.assertEqual(event_task_exec_post_finish.testcase_id, testcase_id)

  def test_mapping_event_classes(self):
    """Assert that all defined event types are in the classes map."""
    # Retrieve all event types defined by EventTypes class.
    event_types = [
        v for k, v in vars(events.EventTypes).items() if not k.startswith('__')
    ]
    event_types_classes = list(events._EVENT_TYPE_CLASSES.keys())  # pylint: disable=protected-access
    self.assertCountEqual(event_types, event_types_classes)


@test_utils.with_cloud_emulators('datastore')
class DatastoreEventsTest(unittest.TestCase):
  """Test event handling and persistence with datastore repository."""

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
    os.environ['CF_TASK_NAME'] = 'fuzz'

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

  def _assert_testcase_fields(self, event, testcase_id):
    """Asserts for testcase-related event fields."""
    self.assertEqual(event.testcase_id, testcase_id)
    # Values based on `test_utils.create_generic_testcase`.
    self.assertEqual(event.fuzzer, 'fuzzer1')
    self.assertEqual(event.job, 'test_content_shell_drt')
    self.assertEqual(event.crash_revision, 1)

  def _assert_task_fields(self, event):
    """Asserts task-related event fields."""
    self.assertEqual(event.task_id, 'f61826c3-ca9a-4b97-9c1e-9e6f4e4f8868')
    self.assertEqual(event.task_name, 'fuzz')

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

  def test_serialize_testcase_creation_event(self):
    """Test serializing a testcase creation event into a datastore entity."""
    testcase = test_utils.create_generic_testcase()
    source = 'events_test'

    event_tc_creation = events.TestcaseCreationEvent(
        source=source,
        testcase=testcase,
        creation_origin=events.TestcaseOrigin.FUZZ_TASK)
    event_type = event_tc_creation.event_type
    timestamp = event_tc_creation.timestamp

    event_entity = self.repository._serialize_event(event_tc_creation)  # pylint: disable=protected-access

    # BaseTestcaseEvent and BaseTaskEvent general assertions.
    self.assertIsNotNone(event_entity)
    self.assertIsInstance(event_entity, data_types.TestcaseLifecycleEvent)
    self.assertEqual(event_entity.event_type, event_type)
    self.assertEqual(event_entity.source, source)
    self.assertEqual(event_entity.timestamp, timestamp)
    self._assert_common_event_fields(event_entity)
    self._assert_testcase_fields(event_entity, testcase.key.id())
    self._assert_task_fields(event_entity)

    # TestcaseCreationEvent specific assertions.
    self.assertEqual(event_entity.creation_origin,
                     events.TestcaseOrigin.FUZZ_TASK)
    self.assertIsNone(event_entity.uploader)

  def test_serialize_testcase_rejection_event(self):
    """Test serializing a testcase rejection event."""
    testcase = test_utils.create_generic_testcase()
    event = events.TestcaseRejectionEvent(
        source='events_test',
        testcase=testcase,
        rejection_reason=events.RejectionReason.ANALYZE_FLAKE_ON_FIRST_ATTEMPT)
    event_type = event.event_type
    timestamp = event.timestamp

    event_entity = self.repository._serialize_event(event)  # pylint: disable=protected-access

    # BaseTestcaseEvent and BaseTaskEvent general assertions
    self.assertIsNotNone(event_entity)
    self.assertIsInstance(event_entity, data_types.TestcaseLifecycleEvent)
    self.assertEqual(event_entity.event_type, event_type)
    self.assertEqual(event_entity.timestamp, timestamp)
    self._assert_common_event_fields(event_entity)
    self._assert_testcase_fields(event_entity, testcase.key.id())
    self._assert_task_fields(event_entity)

    # TestcaseRejectionEvent specific assertions
    self.assertEqual(event_entity.rejection_reason,
                     events.RejectionReason.ANALYZE_FLAKE_ON_FIRST_ATTEMPT)

  def test_serialize_testcase_fixed_event(self):
    """Test serializing a testcase fixed event."""
    testcase = test_utils.create_generic_testcase()
    event = events.TestcaseFixedEvent(
        source='events_test', testcase=testcase, fixed_revision='1:2')
    event_type = event.event_type
    timestamp = event.timestamp

    event_entity = self.repository._serialize_event(event)  # pylint: disable=protected-access

    # BaseTestcaseEvent and BaseTaskEvent general assertions
    self.assertIsNotNone(event_entity)
    self.assertIsInstance(event_entity, data_types.TestcaseLifecycleEvent)
    self.assertEqual(event_entity.event_type, event_type)
    self.assertEqual(event_entity.timestamp, timestamp)
    self._assert_common_event_fields(event_entity)
    self._assert_testcase_fields(event_entity, testcase.key.id())
    self._assert_task_fields(event_entity)

    # TestcaseFixedEvent specific assertions
    self.assertEqual(event_entity.fixed_revision, '1:2')

  def test_serialize_issue_filing_event(self):
    """Test serializing an issue filing event."""
    testcase = test_utils.create_generic_testcase()
    event = events.IssueFilingEvent(
        source='events_test',
        testcase=testcase,
        issue_tracker_project='oss-fuzz',
        issue_id='67890',
        issue_created=False)
    event_type = event.event_type
    timestamp = event.timestamp

    event_entity = self.repository._serialize_event(event)  # pylint: disable=protected-access

    # BaseTestcaseEvent and BaseTaskEvent general assertions
    self.assertIsNotNone(event_entity)
    self.assertIsInstance(event_entity, data_types.TestcaseLifecycleEvent)
    self.assertEqual(event_entity.event_type, event_type)
    self.assertEqual(event_entity.timestamp, timestamp)
    self._assert_common_event_fields(event_entity)
    self._assert_testcase_fields(event_entity, testcase.key.id())
    self._assert_task_fields(event_entity)

    # IssueFilingEvent specific assertions
    self.assertEqual(event_entity.issue_tracker_project, 'oss-fuzz')
    self.assertEqual(event_entity.issue_id, '67890')
    self.assertFalse(event_entity.issue_created)

  def test_serialize_issue_closing_event(self):
    """Test serializing an issue closing event."""
    testcase = test_utils.create_generic_testcase()
    event = events.IssueClosingEvent(
        source='events_test',
        testcase=testcase,
        issue_tracker_project='oss-fuzz',
        issue_id='67890',
        closing_reason=events.ClosingReason.TESTCASE_FIXED)
    event_type = event.event_type
    timestamp = event.timestamp

    event_entity = self.repository._serialize_event(event)  # pylint: disable=protected-access

    # BaseTestcaseEvent and BaseTaskEvent general assertions.
    self.assertIsNotNone(event_entity)
    self.assertIsInstance(event_entity, data_types.TestcaseLifecycleEvent)
    self.assertEqual(event_entity.event_type, event_type)
    self.assertEqual(event_entity.timestamp, timestamp)
    self._assert_common_event_fields(event_entity)
    self._assert_testcase_fields(event_entity, testcase.key.id())
    self._assert_task_fields(event_entity)

    # IssueClosingEvent specific assertions.
    self.assertEqual(event_entity.issue_tracker_project, 'oss-fuzz')
    self.assertEqual(event_entity.issue_id, '67890')
    self.assertEqual(event_entity.closing_reason,
                     events.ClosingReason.TESTCASE_FIXED)

  def test_serialize_testcase_grouping_event(self):
    """Test serializing a testcase grouping event."""
    testcase = test_utils.create_generic_testcase()
    event = events.TestcaseGroupingEvent(
        source='events_test',
        testcase=testcase,
        group_id=10,
        previous_group_id=5,
        similar_testcase_id=2,
        grouping_reason=events.GroupingReason.GROUP_MERGE,
        group_merge_reason=events.GroupingReason.IDENTICAL_VARIANT)
    event_type = event.event_type
    timestamp = event.timestamp

    event_entity = self.repository._serialize_event(event)  # pylint: disable=protected-access

    # BaseTestcaseEvent and BaseTaskEvent general assertions
    self.assertIsNotNone(event_entity)
    self.assertIsInstance(event_entity, data_types.TestcaseLifecycleEvent)
    self.assertEqual(event_entity.event_type, event_type)
    self.assertEqual(event_entity.timestamp, timestamp)
    self._assert_common_event_fields(event_entity)
    self._assert_testcase_fields(event_entity, testcase.key.id())
    self._assert_task_fields(event_entity)

    # TestcaseGroupingEvent specific assertions
    self.assertEqual(event_entity.group_id, 10)
    self.assertEqual(event_entity.previous_group_id, 5)
    self.assertEqual(event_entity.similar_testcase_id, 2)
    self.assertEqual(event_entity.grouping_reason,
                     events.GroupingReason.GROUP_MERGE)
    self.assertEqual(event_entity.group_merge_reason,
                     events.GroupingReason.IDENTICAL_VARIANT)

  def test_serialize_task_execution_event(self):
    """Test serializing a task execution event into a datastore entity."""
    source = 'events_test'
    job_type = 'job_test'
    fuzzer_name = 'fuzzer_test'
    testcase_id = 1
    task_outcome = uworker_msg_pb2.ErrorType.Name(
        uworker_msg_pb2.ErrorType.ANALYZE_NO_CRASH)
    event_task_exec = events.TaskExecutionEvent(
        source=source,
        testcase_id=testcase_id,
        task_fuzzer=fuzzer_name,
        task_job=job_type,
        task_stage=events.TaskStage.POSTPROCESS,
        task_status=events.TaskStatus.POST_COMPLETED,
        task_outcome=task_outcome)
    event_type = event_task_exec.event_type
    timestamp = event_task_exec.timestamp

    event_entity = self.repository._serialize_event(event_task_exec)  # pylint: disable=protected-access

    # BaseTestcaseEvent and BaseTaskEvent general assertions.
    self.assertIsNotNone(event_entity)
    self.assertIsInstance(event_entity, data_types.TestcaseLifecycleEvent)
    self.assertEqual(event_entity.event_type, event_type)
    self.assertEqual(event_entity.source, source)
    self.assertEqual(event_entity.timestamp, timestamp)
    self._assert_common_event_fields(event_entity)
    self._assert_task_fields(event_entity)

    # TaskExecutionEvent specific assertions.
    self.assertEqual(event_entity.task_stage, events.TaskStage.POSTPROCESS)
    self.assertEqual(event_entity.task_status, events.TaskStatus.POST_COMPLETED)
    self.assertEqual(event_entity.task_outcome, task_outcome)
    self.assertEqual(event_entity.testcase_id, testcase_id)
    self.assertEqual(event_entity.task_job, job_type)
    self.assertEqual(event_entity.task_fuzzer, fuzzer_name)

  def test_deserialize_generic_event(self):
    """Test deserializing a datastore event entity into an event class."""
    event_entity = data_types.TestcaseLifecycleEvent(event_type='generic_event')
    date_now = datetime.datetime(2025, 1, 1, 10, 30, 15)
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

  def test_deserialize_testcase_creation_event(self):
    """Test deserializing a datastore event into a testcase creation event."""
    event_type = events.EventTypes.TESTCASE_CREATION
    date_now = datetime.datetime(2025, 1, 1, 10, 30, 15)

    event_entity = data_types.TestcaseLifecycleEvent(event_type=event_type)
    event_entity.timestamp = date_now
    event_entity.source = 'events_test'
    self._set_common_event_fields(event_entity)
    event_entity.task_id = 'f61826c3-ca9a-4b97-9c1e-9e6f4e4f8868'
    event_entity.task_name = 'fuzz'
    event_entity.testcase_id = 1
    event_entity.fuzzer = 'fuzzer1'
    event_entity.job = 'test_job'
    event_entity.crash_revision = 2
    event_entity.creation_origin = events.TestcaseOrigin.MANUAL_UPLOAD
    event_entity.uploader = 'test@gmail.com'
    event_entity.put()

    event = self.repository._deserialize_event(event_entity)  # pylint: disable=protected-access
    self.assertIsNotNone(event)
    self.assertIsInstance(event, events.TestcaseCreationEvent)

    # BaseTestcaseEvent and BaseTaskEvent general assertions
    self.assertEqual(event.event_type, event_type)
    self.assertEqual(event.source, 'events_test')
    self.assertEqual(event.timestamp, date_now)
    self._assert_common_event_fields(event)
    self.assertEqual(event.task_id, 'f61826c3-ca9a-4b97-9c1e-9e6f4e4f8868')
    self.assertEqual(event.task_name, 'fuzz')
    self.assertEqual(event.testcase_id, 1)
    self.assertEqual(event.fuzzer, 'fuzzer1')
    self.assertEqual(event.job, 'test_job')
    self.assertEqual(event.crash_revision, 2)

    # TestcaseCreationEvent specific assertions
    self.assertEqual(event.creation_origin, events.TestcaseOrigin.MANUAL_UPLOAD)
    self.assertEqual(event.uploader, 'test@gmail.com')

  def test_deserialize_testcase_rejection_event(self):
    """Test deserializing a testcase rejection event."""
    event_type = events.EventTypes.TESTCASE_REJECTION
    date_now = datetime.datetime(2025, 1, 1, 10, 30, 15)

    event_entity = data_types.TestcaseLifecycleEvent(event_type=event_type)
    event_entity.timestamp = date_now
    event_entity.source = 'events_test'
    self._set_common_event_fields(event_entity)
    event_entity.task_id = 'f61826c3-ca9a-4b97-9c1e-9e6f4e4f8868'
    event_entity.task_name = 'fuzz'
    event_entity.testcase_id = 1
    event_entity.fuzzer = 'fuzzer1'
    event_entity.job = 'test_job'
    event_entity.crash_revision = 2
    event_entity.rejection_reason = events.RejectionReason.ANALYZE_FLAKE_ON_FIRST_ATTEMPT
    event_entity.put()

    event = self.repository._deserialize_event(event_entity)  # pylint: disable=protected-access
    self.assertIsNotNone(event)
    self.assertIsInstance(event, events.TestcaseRejectionEvent)

    # BaseTestcaseEvent and BaseTaskEvent general assertions
    self.assertEqual(event.event_type, event_type)
    self.assertEqual(event.source, 'events_test')
    self.assertEqual(event.timestamp, date_now)
    self._assert_common_event_fields(event)
    self.assertEqual(event.task_id, 'f61826c3-ca9a-4b97-9c1e-9e6f4e4f8868')
    self.assertEqual(event.task_name, 'fuzz')
    self.assertEqual(event.testcase_id, 1)
    self.assertEqual(event.fuzzer, 'fuzzer1')
    self.assertEqual(event.job, 'test_job')
    self.assertEqual(event.crash_revision, 2)

    # TestcaseRejectionEvent specific assertions
    self.assertEqual(event.rejection_reason,
                     events.RejectionReason.ANALYZE_FLAKE_ON_FIRST_ATTEMPT)

  def test_deserialize_testcase_fixed_event(self):
    """Test deserializing a testcase fixed event."""
    event_type = events.EventTypes.TESTCASE_FIXED
    date_now = datetime.datetime(2025, 1, 1, 10, 30, 15)

    event_entity = data_types.TestcaseLifecycleEvent(event_type=event_type)
    event_entity.timestamp = date_now
    event_entity.source = 'events_test'
    self._set_common_event_fields(event_entity)
    event_entity.task_id = 'f61826c3-ca9a-4b97-9c1e-9e6f4e4f8868'
    event_entity.task_name = 'progression'
    event_entity.testcase_id = 1
    event_entity.fuzzer = 'fuzzer1'
    event_entity.job = 'test_job'
    event_entity.crash_revision = 2
    event_entity.fixed_revision = '3:4'
    event_entity.put()

    event = self.repository._deserialize_event(event_entity)  # pylint: disable=protected-access
    self.assertIsNotNone(event)
    self.assertIsInstance(event, events.TestcaseFixedEvent)

    # BaseTestcaseEvent and BaseTaskEvent general assertions.
    self.assertEqual(event.event_type, event_type)
    self.assertEqual(event.source, 'events_test')
    self.assertEqual(event.timestamp, date_now)
    self._assert_common_event_fields(event)
    self.assertEqual(event.task_id, 'f61826c3-ca9a-4b97-9c1e-9e6f4e4f8868')
    self.assertEqual(event.task_name, 'progression')
    self.assertEqual(event.testcase_id, 1)
    self.assertEqual(event.fuzzer, 'fuzzer1')
    self.assertEqual(event.job, 'test_job')
    self.assertEqual(event.crash_revision, 2)

    # TestcaseFixedEvent specific assertions.
    self.assertEqual(event.fixed_revision, '3:4')

  def test_deserialize_issue_filing_event(self):
    """Test deserializing an issue filing event."""
    event_type = events.EventTypes.ISSUE_FILING
    date_now = datetime.datetime(2025, 1, 1, 10, 30, 15)

    event_entity = data_types.TestcaseLifecycleEvent(event_type=event_type)
    event_entity.timestamp = date_now
    event_entity.source = 'events_test'
    self._set_common_event_fields(event_entity)
    event_entity.task_id = 'f61826c3-ca9a-4b97-9c1e-9e6f4e4f8868'
    event_entity.testcase_id = 1
    event_entity.fuzzer = 'fuzzer1'
    event_entity.job = 'test_job'
    event_entity.crash_revision = 2
    event_entity.issue_tracker_project = 'oss-fuzz'
    event_entity.issue_id = '13579'
    event_entity.issue_created = True
    event_entity.put()

    event = self.repository._deserialize_event(event_entity)  # pylint: disable=protected-access
    self.assertIsNotNone(event)
    self.assertIsInstance(event, events.IssueFilingEvent)

    # BaseTestcaseEvent and BaseTaskEvent general assertions
    self.assertEqual(event.event_type, event_type)
    self.assertEqual(event.source, 'events_test')
    self.assertEqual(event.timestamp, date_now)
    self._assert_common_event_fields(event)
    self.assertEqual(event.task_id, 'f61826c3-ca9a-4b97-9c1e-9e6f4e4f8868')
    self.assertEqual(event.testcase_id, 1)
    self.assertEqual(event.fuzzer, 'fuzzer1')
    self.assertEqual(event.job, 'test_job')
    self.assertEqual(event.crash_revision, 2)

    # IssueFilingEvent specific assertions
    self.assertEqual(event.issue_tracker_project, 'oss-fuzz')
    self.assertEqual(event.issue_id, '13579')
    self.assertTrue(event.issue_created)

  def test_deserialize_issue_closing_event(self):
    """Test deserializing an issue closing event."""
    event_type = events.EventTypes.ISSUE_CLOSING
    date_now = datetime.datetime(2025, 1, 1, 10, 30, 15)

    event_entity = data_types.TestcaseLifecycleEvent(event_type=event_type)
    event_entity.timestamp = date_now
    event_entity.source = 'events_test'
    self._set_common_event_fields(event_entity)
    event_entity.task_id = 'f61826c3-ca9a-4b97-9c1e-9e6f4e4f8868'
    event_entity.testcase_id = 1
    event_entity.fuzzer = 'fuzzer1'
    event_entity.job = 'test_job'
    event_entity.crash_revision = 2
    event_entity.issue_tracker_project = 'oss-fuzz'
    event_entity.issue_id = '13579'
    event_entity.closing_reason = events.ClosingReason.TESTCASE_FIXED
    event_entity.put()

    event = self.repository._deserialize_event(event_entity)  # pylint: disable=protected-access
    self.assertIsNotNone(event)
    self.assertIsInstance(event, events.IssueClosingEvent)

    # BaseTestcaseEvent and BaseTaskEvent general assertions.
    self.assertEqual(event.event_type, event_type)
    self.assertEqual(event.source, 'events_test')
    self.assertEqual(event.timestamp, date_now)
    self._assert_common_event_fields(event)
    self.assertEqual(event.task_id, 'f61826c3-ca9a-4b97-9c1e-9e6f4e4f8868')
    self.assertEqual(event.testcase_id, 1)
    self.assertEqual(event.fuzzer, 'fuzzer1')
    self.assertEqual(event.job, 'test_job')
    self.assertEqual(event.crash_revision, 2)

    # IssueClosingEvent specific assertions.
    self.assertEqual(event.issue_tracker_project, 'oss-fuzz')
    self.assertEqual(event.issue_id, '13579')
    self.assertEqual(event.closing_reason, events.ClosingReason.TESTCASE_FIXED)

  def test_deserialize_testcase_grouping_event(self):
    """Test deserializing a testcase grouping event."""
    event_type = events.EventTypes.TESTCASE_GROUPING
    date_now = datetime.datetime(2025, 1, 1, 10, 30, 15)

    event_entity = data_types.TestcaseLifecycleEvent(event_type=event_type)
    event_entity.timestamp = date_now
    event_entity.source = 'events_test'
    self._set_common_event_fields(event_entity)
    event_entity.task_id = 'f61826c3-ca9a-4b97-9c1e-9e6f4e4f8868'
    event_entity.task_name = 'triage'
    event_entity.testcase_id = 1
    event_entity.fuzzer = 'fuzzer1'
    event_entity.job = 'test_job'
    event_entity.crash_revision = 2
    event_entity.group_id = 10
    event_entity.previous_group_id = 5
    event_entity.similar_testcase_id = 2
    event_entity.grouping_reason = events.GroupingReason.GROUP_MERGE
    event_entity.group_merge_reason = events.GroupingReason.SIMILAR_CRASH
    event_entity.put()

    event = self.repository._deserialize_event(event_entity)  # pylint: disable=protected-access
    self.assertIsNotNone(event)
    self.assertIsInstance(event, events.TestcaseGroupingEvent)

    # BaseTestcaseEvent and BaseTaskEvent general assertions.
    self.assertEqual(event.event_type, event_type)
    self.assertEqual(event.source, 'events_test')
    self.assertEqual(event.timestamp, date_now)
    self._assert_common_event_fields(event)
    self.assertEqual(event.task_id, 'f61826c3-ca9a-4b97-9c1e-9e6f4e4f8868')
    self.assertEqual(event.task_name, 'triage')
    self.assertEqual(event.testcase_id, 1)
    self.assertEqual(event.fuzzer, 'fuzzer1')
    self.assertEqual(event.job, 'test_job')
    self.assertEqual(event.crash_revision, 2)

    # TestcaseGroupingEvent specific assertions
    self.assertEqual(event.group_id, 10)
    self.assertEqual(event.previous_group_id, 5)
    self.assertEqual(event.similar_testcase_id, 2)
    self.assertEqual(event.grouping_reason, events.GroupingReason.GROUP_MERGE)
    self.assertEqual(event.group_merge_reason,
                     events.GroupingReason.SIMILAR_CRASH)

  def test_deserialize_task_execution_event(self):
    """Test deserializing a datastore event into a task execution event."""
    event_type = events.EventTypes.TASK_EXECUTION
    date_now = datetime.datetime(2025, 1, 1, 10, 30, 15)

    event_entity = data_types.TestcaseLifecycleEvent(event_type=event_type)
    event_entity.timestamp = date_now
    event_entity.source = 'events_test'
    self._set_common_event_fields(event_entity)
    event_entity.task_id = 'f61826c3-ca9a-4b97-9c1e-9e6f4e4f8868'
    event_entity.task_name = 'regression'
    event_entity.testcase_id = 1
    event_entity.task_fuzzer = 'fuzzer1'
    event_entity.task_job = 'test_job'
    event_entity.task_stage = events.TaskStage.POSTPROCESS
    event_entity.task_status = events.TaskStatus.EXCEPTION
    event_entity.task_outcome = 'REGRESSION_BAD_BUILD_ERROR'
    event_entity.put()

    event = self.repository._deserialize_event(event_entity)  # pylint: disable=protected-access
    self.assertIsNotNone(event)
    self.assertIsInstance(event, events.TaskExecutionEvent)

    # BaseTestcaseEvent and BaseTaskEvent general assertions
    self.assertEqual(event.event_type, event_type)
    self.assertEqual(event.source, 'events_test')
    self.assertEqual(event.timestamp, date_now)
    self._assert_common_event_fields(event)
    self.assertEqual(event.task_id, 'f61826c3-ca9a-4b97-9c1e-9e6f4e4f8868')
    self.assertEqual(event.task_name, 'regression')

    # TaskExecutionEvent specific assertions
    self.assertEqual(event.task_stage, events.TaskStage.POSTPROCESS)
    self.assertEqual(event.task_status, events.TaskStatus.EXCEPTION)
    self.assertEqual(event.task_outcome, 'REGRESSION_BAD_BUILD_ERROR')
    self.assertEqual(event.testcase_id, 1)
    self.assertEqual(event.task_fuzzer, 'fuzzer1')
    self.assertEqual(event.task_job, 'test_job')

  def test_store_event(self):
    """Test storing an event into datastore."""
    testcase = test_utils.create_generic_testcase()

    event_tc_creation = events.TestcaseCreationEvent(
        source='events_test',
        testcase=testcase,
        creation_origin=events.TestcaseOrigin.FUZZ_TASK)
    event_type = event_tc_creation.event_type
    timestamp = event_tc_creation.timestamp
    eid = self.repository.store_event(event_tc_creation)
    self.assertIsNotNone(eid)

    # Assert correctness of the stored event entity.
    event_entity = data_handler.get_entity_by_type_and_id(
        data_types.TestcaseLifecycleEvent, eid)
    self.assertIsNotNone(event_entity)
    self.assertEqual(event_entity.event_type, event_type)
    self.assertEqual(event_entity.source, 'events_test')
    self.assertEqual(event_entity.timestamp, timestamp)
    self._assert_common_event_fields(event_entity)
    self._assert_testcase_fields(event_entity, testcase.key.id())
    self._assert_task_fields(event_entity)
    self.assertEqual(event_entity.creation_origin,
                     events.TestcaseOrigin.FUZZ_TASK)
    self.assertIsNone(event_entity.uploader)

  def test_get_event(self):
    """Test retrieving an event from datastore."""
    event_entity = data_types.TestcaseLifecycleEvent(
        event_type='generic_event_test')
    date_now = datetime.datetime(2025, 1, 1, 10, 30, 15)
    event_entity.timestamp = date_now
    event_entity.source = 'events_test'
    self._set_common_event_fields(event_entity)
    event_entity.put()
    event_id = event_entity.key.id()

    event = self.repository.get_event(event_id)
    self.assertIsNotNone(event)
    self.assertEqual(event.event_type, 'generic_event_test')
    self.assertIsInstance(event, events.Event)
    self.assertEqual(event.source, 'events_test')
    self.assertEqual(event.timestamp, date_now)
    self._assert_common_event_fields(event)


@test_utils.with_cloud_emulators('datastore')
class EventsNotificationsTest(unittest.TestCase):
  """Test issue notifications for events."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.base.utils.get_instance_name',
        'clusterfuzz._internal.metrics.events._get_datetime_now',
        'clusterfuzz._internal.issue_management.issue_tracker_utils.get_issue_for_testcase'
    ])
    self.original_env = dict(os.environ)
    os.environ['OS_OVERRIDE'] = 'linux'
    # Override reading the manifest file for the source version.
    os.environ['SOURCE_VERSION_OVERRIDE'] = ('20250402153042-utc-40773ac0-user'
                                             '-cad6977-prod')
    self.mock.get_instance_name.return_value = 'linux-bot'

    os.environ['CF_TASK_ID'] = 'f61826c3-ca9a-4b97-9c1e-9e6f4e4f8868'
    os.environ['CF_TASK_NAME'] = 'fuzz'

    self.date_now = datetime.datetime(2025, 1, 1, 10, 30, 15)
    self.mock._get_datetime_now.return_value = self.date_now  # pylint: disable=protected-access
    return super().setUp()

  def tearDown(self):
    os.environ.clear()
    os.environ.update(self.original_env)
    return super().tearDown()

  def test_check_disabled_without_config(self):
    """Test events are enabled to notify if no disabled config is used."""
    notifier = events.EventIssueNotification(disabled_events=None)
    event1 = events.Event(event_type='generic_event', source='events_test')
    event2 = events.Event(
        event_type=events.EventTypes.TESTCASE_CREATION, source='events_test')
    self.assertFalse(notifier._check_disabled(event1))  # pylint: disable=protected-access
    self.assertFalse(notifier._check_disabled(event2))  # pylint: disable=protected-access

  def test_check_disabled_config(self):
    """Test disabling events from notifying using the disabled config."""
    testcase = test_utils.create_generic_testcase()
    disabled_events = {
        events.EventTypes.TESTCASE_CREATION: True,
        events.EventTypes.TESTCASE_REJECTION: ['analyze']
    }
    notifier = events.EventIssueNotification(disabled_events)

    # Test enabled event type.
    event = events.Event(event_type='generic_event', source='events_test')
    self.assertFalse(notifier._check_disabled(event))  # pylint: disable=protected-access

    # Test disabled event type for any task.
    os.environ['CF_TASK_NAME'] = 'fuzz'
    event_creation_fuzz = events.TestcaseCreationEvent(
        testcase=testcase, creation_origin=events.TestcaseOrigin.FUZZ_TASK)
    self.assertTrue(notifier._check_disabled(event_creation_fuzz))  # pylint: disable=protected-access

    os.environ['CF_TASK_NAME'] = 'analyze'
    event_creation_manual = events.TestcaseCreationEvent(
        testcase=testcase,
        creation_origin=events.TestcaseOrigin.MANUAL_UPLOAD,
        uploader='@test')
    self.assertTrue(notifier._check_disabled(event_creation_manual))  # pylint: disable=protected-access

    # Test disabled event type for specific task.
    os.environ['CF_TASK_NAME'] = 'triage'
    event_rejection_triage = events.TestcaseRejectionEvent(
        testcase=testcase,
        rejection_reason=events.RejectionReason.ANALYZE_NO_REPRO)
    self.assertFalse(notifier._check_disabled(event_rejection_triage))  # pylint: disable=protected-access

    os.environ['CF_TASK_NAME'] = 'analyze'
    event_rejection_triage = events.TestcaseRejectionEvent(
        testcase=testcase,
        rejection_reason=events.RejectionReason.ANALYZE_NO_REPRO)
    self.assertTrue(notifier._check_disabled(event_rejection_triage))  # pylint: disable=protected-access

  def test_emit_fail_due_to_config(self):
    """Test that emit returns early due to disabled events config."""
    disabled_events = {events.EventTypes.TESTCASE_CREATION: True}
    notifier = events.EventIssueNotification(disabled_events)

    testcase = test_utils.create_generic_testcase()
    # Add bug id to assert that it only fails to emit due to config.
    testcase.bug_information = '1'
    testcase.put()
    event_creation_fuzz = events.TestcaseCreationEvent(
        testcase=testcase, creation_origin=events.TestcaseOrigin.FUZZ_TASK)
    self.assertIsNone(notifier.emit(event_creation_fuzz))
    self.mock.get_issue_for_testcase.assert_not_called()

  def test_emit_fail_missing_testcase_id(self):
    """Test that emit returns early due to missing testcase in event data."""
    notifier = events.EventIssueNotification()
    generic_event = events.Event(event_type='event', source='events_test')
    self.assertIsNone(notifier.emit(generic_event))

    # Test for event type that is expected to have a testcase_id field.
    event_testcase_missing = events.TestcaseCreationEvent(testcase=None)
    self.assertIsNone(notifier.emit(event_testcase_missing))

    event_testcase_error = events.TestcaseCreationEvent(testcase=None)
    # Testcase ID present, but not uploaded to datastore.
    event_testcase_error.testcase_id = 10
    self.assertIsNone(notifier.emit(event_testcase_error))

  def test_emit_fail_testcase_without_bug(self):
    """Test that emit returns early due to testcase without assigned bug."""
    notifier = events.EventIssueNotification()
    testcase = test_utils.create_generic_testcase()
    # Assert that there is no bug associated with the testcase.
    self.assertIsNone(testcase.bug_information)

    event = events.TestcaseCreationEvent(testcase=testcase)
    self.assertIsNone(notifier.emit(event))
    # Assert it does not reach the get issue method, since the return from it
    # is expected to not be None and logged as error if so.
    self.mock.get_issue_for_testcase.assert_not_called()

  def test_emit_issue_notification(self):
    """Test a successful emit execution."""
    # Use a generic mock for issue, since we should only assert that
    # `issue.save()` was called once with the correct args.
    issue = unittest.mock.MagicMock()
    issue.id = 1
    self.mock.get_issue_for_testcase.return_value = issue

    testcase = test_utils.create_generic_testcase()
    testcase.bug_information = '1'
    testcase.put()

    notifier = events.EventIssueNotification()
    event = events.TestcaseCreationEvent(
        testcase=testcase, creation_origin=events.TestcaseOrigin.FUZZ_TASK)
    comment = event.create_notification()
    self.assertEqual(issue.id, notifier.emit(event))
    self.mock.get_issue_for_testcase.assert_called_once_with(testcase=testcase)
    issue.save.assert_called_once_with(new_comment=comment, notify=True)


@test_utils.with_cloud_emulators('datastore')
class EmitEventTest(unittest.TestCase):
  """Test event emission and handler config."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.config.local_config.ProjectConfig',
        'clusterfuzz._internal.metrics.events._get_datetime_now'
    ])
    self.date_now = datetime.datetime(2025, 1, 1, 10, 30, 15)
    self.mock._get_datetime_now.return_value = self.date_now  # pylint: disable=protected-access
    self.project_config = {}
    self.mock.ProjectConfig.return_value = self.project_config
    # Reset handlers, since it is only configured in the first events emit.
    events._handlers = None  # pylint: disable=protected-access

  def tearDown(self):
    self.project_config = {}

  def test_get_datastore_repository(self):
    """Test retrieving datastore event repository based on project config."""
    self.project_config['events.storage'] = 'datastore'
    repository = events.get_repository()
    self.assertIsInstance(repository, events.NDBEventRepository)

  def test_not_implemented_repository(self):
    """Test not implemented event repository based on project config."""
    self.project_config['events.storage'] = 'test'
    repository = events.get_repository()
    self.assertIsNone(repository)

  def test_get_notifier(self):
    """Test retrieving issue notification handler with all events enabled."""
    self.project_config['events.notification.enabled'] = True
    notifier = events.get_notifier()
    self.assertIsInstance(notifier, events.EventIssueNotification)
    self.assertFalse(notifier.disabled_events)

  def test_get_notifier_disabled(self):
    """Test retrieving disabled events notification handler."""
    notifier = events.get_notifier()
    self.assertIsNone(notifier)
    # Either enabled is missing or set to False.
    self.project_config['events.notification.enabled'] = False
    notifier = events.get_notifier()
    self.assertIsNone(notifier)

  def test_get_notifier_with_specific_config(self):
    """Test setting issue notification handler with disabled events config."""
    self.project_config['events.notification.enabled'] = True
    self.project_config['events.notification.disabled_events'] = {
        'testcase_creation': True,
        'testcase_rejection': ['analyze']
    }
    notifier = events.get_notifier()
    self.assertIsInstance(notifier, events.EventIssueNotification)
    self.assertEqual(notifier.disabled_events, {
        'testcase_creation': True,
        'testcase_rejection': ['analyze']
    })

  def test_emit_datastore_event(self):
    """Test emit event with datastore repository."""
    self.project_config['events.storage'] = 'datastore'
    os.environ['CF_TASK_ID'] = 'f61826c3-ca9a-4b97-9c1e-9e6f4e4f8868'
    os.environ['CF_TASK_NAME'] = 'fuzz'

    testcase = test_utils.create_generic_testcase()
    # Using testcase creation event for testing should be enough to test any
    # event type as long as it is mapped in the events module.
    events.emit(
        events.TestcaseCreationEvent(
            source='events_test',
            testcase=testcase,
            creation_origin=events.TestcaseOrigin.FUZZ_TASK))

    # Assert that the event was stored in datastore.
    all_events = data_types.TestcaseLifecycleEvent.query().fetch()
    self.assertEqual(len(all_events), 1)
    event_entity = all_events[0]

    self.assertEqual(event_entity.event_type,
                     events.EventTypes.TESTCASE_CREATION)
    self.assertIsNotNone(event_entity.timestamp)
    self.assertEqual(event_entity.timestamp, self.date_now)
    self.assertEqual(event_entity.source, 'events_test')
    self.assertEqual(event_entity.creation_origin,
                     events.TestcaseOrigin.FUZZ_TASK)
    self.assertEqual(event_entity.task_id,
                     'f61826c3-ca9a-4b97-9c1e-9e6f4e4f8868')
    self.assertEqual(event_entity.task_name, 'fuzz')
    self.assertEqual(event_entity.testcase_id, testcase.key.id())
    self.assertEqual(event_entity.fuzzer, 'fuzzer1')
    self.assertEqual(event_entity.job, 'test_content_shell_drt')
    self.assertEqual(event_entity.crash_revision, 1)


class RetrievingEventsTest(unittest.TestCase):
  """Test retrieving events."""

  def setUp(self):
    self.event1 = data_types.TestcaseLifecycleEvent(
        event_type='type_A',
        testcase_id=1,
        timestamp=datetime.datetime(2025, 1, 1, 8, 0))
    self.event1.put()
    self.event2 = data_types.TestcaseLifecycleEvent(
        event_type='type_B',
        testcase_id=1,
        timestamp=datetime.datetime(2025, 1, 1, 9, 0))
    self.event2.put()
    self.event3 = data_types.TestcaseLifecycleEvent(
        event_type='type_A',
        task_name='analyze',
        testcase_id=2,
        timestamp=datetime.datetime(2025, 1, 1, 10, 0))
    self.event3.put()
    self.event4 = data_types.TestcaseLifecycleEvent(
        event_type='type_A',
        task_name='impact',
        testcase_id=2,
        timestamp=datetime.datetime(2025, 1, 1, 11, 0))
    self.event4.put()
    self.event5 = data_types.TestcaseLifecycleEvent(
        event_type='task_execution',
        testcase_id=3,
        timestamp=datetime.datetime(2025, 1, 1, 12, 0))
    self.event5.put()

  def _assert_events_equal(self, result_events, entities):
    """Asserts that each event match the associated entity"""
    self.assertEqual(len(result_events), len(entities))
    for event, entity in zip(result_events, entities):
      self.assertEqual(event.event_type, entity.event_type)
      self.assertEqual(event.timestamp, entity.timestamp)


@test_utils.with_cloud_emulators('datastore')
class GetEventsFromDatastoreTest(RetrievingEventsTest):
  """Test get_events from datastore repository."""

  def setUp(self):
    self.repository = events.NDBEventRepository()
    return super().setUp()

  def test_get_all_events(self):
    """Verify that all events are yielded when no filters are applied."""
    result = list(self.repository.get_events())
    result.sort(key=lambda e: e.timestamp)
    expected_entities = [
        self.event1, self.event2, self.event3, self.event4, self.event5
    ]
    self._assert_events_equal(result, expected_entities)

  def test_get_events_return_type(self):
    """Verify that get_events returns a Generator."""
    result = self.repository.get_events()
    self.assertIsInstance(result, Generator)

  def test_retrieve_specific_event_type(self):
    """Verify if a retrieved event is correctly deserialized to the correspondent event class"""
    equality_filters = {'event_type': 'task_execution'}
    result = list(self.repository.get_events(equality_filters=equality_filters))
    self._assert_events_equal(result, [self.event5])
    self.assertIsInstance(result[0], events.TaskExecutionEvent)

  def test_get_events_with_equality_filters(self):
    """Verify that only events matching the equality filters are yielded."""
    result = list(
        self.repository.get_events(equality_filters={'event_type': 'type_A'}))
    result.sort(key=lambda e: e.timestamp)
    self._assert_events_equal(result, [self.event1, self.event3, self.event4])

    equality_filters = {'event_type': 'type_A', 'testcase_id': 1}
    result = list(self.repository.get_events(equality_filters=equality_filters))
    result.sort(key=lambda e: e.timestamp)
    self._assert_events_equal(result, [self.event1])

  def test_get_events_with_ordering(self):
    """Verify that events are yielded in the specified order."""
    result = list(self.repository.get_events(order_by=['-timestamp']))
    expected_entities = [
        self.event5, self.event4, self.event3, self.event2, self.event1
    ]
    self._assert_events_equal(result, expected_entities)

  def test_get_events_with_filter_and_ordering(self):
    """Verify that filtering and ordering can be combined."""
    result = list(
        self.repository.get_events(
            equality_filters={'event_type': 'type_A'}, order_by=['-timestamp']))
    self._assert_events_equal(result, [self.event4, self.event3, self.event1])

  def test_get_events_empty(self):
    """Verify that an empty generator is yielded when no events match."""
    result = self.repository.get_events(
        equality_filters={'event_type': 'non_existent'})
    self.assertIsInstance(result, Generator)
    self.assertCountEqual(result, [])


@test_utils.with_cloud_emulators('datastore')
class GetEventsTest(RetrievingEventsTest):
  """Test retrieving events using events module helper functions."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.config.local_config.ProjectConfig',
    ])
    self.project_config = {'events.storage': 'datastore'}
    self.mock.ProjectConfig.return_value.get.side_effect = (
        self.project_config.get)
    return super().setUp()

  def test_get_all_events(self):
    """Verify that get_events correctly retrieve events with filters and ordering."""
    equality_filters = {'event_type': 'type_A'}
    order_by = ['-timestamp']
    result = list(
        events.get_events(equality_filters=equality_filters, order_by=order_by))
    self._assert_events_equal(result, [self.event4, self.event3, self.event1])

  def test_get_events_empty(self):
    """Verify that get_events yields an empty generator when no events are found."""
    result = events.get_events(equality_filters={'event_type': 'non_existent'})
    self.assertCountEqual(result, [])

  def test_get_events_with_no_repository(self):
    """Verify that get_events yields an empty generator when no repository is configured."""
    self.project_config['events.storage'] = 'invalid'
    result = events.get_events()
    self.assertCountEqual(result, [])

  def test_get_events_from_testcase_with_no_filters(self):
    """Verify that get_events_from_testcase can retrieve events with no extra filters."""
    testcase_id = 1
    result = list(events.get_events_from_testcase(testcase_id))
    # Default is to sort by descending order.
    self._assert_events_equal(result, [self.event2, self.event1])

  def test_get_events_from_testcase_with_all_filters(self):
    """Verify that get_events_from_testcase can retrieve events with multiple filters."""
    testcase_id = 1
    event_type = 'type_A'
    result = list(
        events.get_events_from_testcase(testcase_id, event_type=event_type))
    self._assert_events_equal(result, [self.event1])

    testcase_id = 2
    event_type = 'type_A'
    task_name = 'analyze'
    result = list(
        events.get_events_from_testcase(
            testcase_id, event_type=event_type, task_name=task_name))
    self._assert_events_equal(result, [self.event3])

  def test_get_events_from_testcase_without_timestamp_ordering(self):
    """Verify that get_events_from_testcase can retrieve events with latest_first=False."""
    testcase_id = 3
    result = list(
        events.get_events_from_testcase(testcase_id, latest_first=False))
    self._assert_events_equal(result, [self.event5])

  def test_get_events_from_testcase_empty(self):
    """Verify that get_events_from_testcase returns an empty generator when no events are found."""
    testcase_id = 0
    result = events.get_events_from_testcase(testcase_id)
    self.assertIsInstance(result, Generator)
    self.assertCountEqual(result, [])
