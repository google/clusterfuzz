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
"""Tests for analyze task."""

import json
import os
import tempfile
import unittest

from clusterfuzz._internal.bot.tasks.utasks import analyze_task
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils
from clusterfuzz._internal.tests.test_libs import utask_helpers


@test_utils.with_cloud_emulators('datastore')
class AddDefaultIssueMetadataTest(unittest.TestCase):
  """Test _add_default_issue_metadata."""

  def setUp(self):
    helpers.patch(
        self,
        [
            # Disable logging.
            'clusterfuzz._internal.datastore.data_types.Testcase._post_put_hook',
            'clusterfuzz._internal.metrics.logs.info',
        ])

  def test_union(self):
    """Test union of current testcase metadata and default issue metadata."""
    issue_metadata = {
        'issue_owners': 'dev1@example1.com, dev2@example2.com',
        'issue_components': 'component1',
        'issue_labels': 'label1, label2 ,label3',
        'issue_metadata': json.dumps({
            "assignee": "dev3@example3.com"
        })
    }

    testcase = test_utils.create_generic_testcase()
    testcase.set_metadata('issue_owners', 'dev3@example3.com,dev2@example2.com')
    testcase.set_metadata('issue_components', 'component2')
    testcase.set_metadata('issue_labels', 'label4,label5, label2,')
    testcase.set_metadata(
        'issue_metadata',
        {"additional_fields": {
            'Acknowledgements': 'dev4@example4.com'
        }})

    analyze_task._add_default_issue_metadata(testcase, issue_metadata)  # pylint: disable=protected-access
    self.assertEqual('dev1@example1.com,dev2@example2.com,dev3@example3.com',
                     testcase.get_metadata('issue_owners'))
    self.assertEqual('component1,component2',
                     testcase.get_metadata('issue_components'))
    self.assertEqual('label1,label2,label3,label4,label5',
                     testcase.get_metadata('issue_labels'))
    self.assertEqual({
        "additional_fields": {
            'Acknowledgements': 'dev4@example4.com'
        }
    }, testcase.get_metadata('issue_metadata'))
    self.assertEqual(3, self.mock.info.call_count)

  def test_no_testcase_metadata(self):
    """Test when we only have testcase metadata and no default issue
    metadata."""
    issue_metadata = {}

    testcase = test_utils.create_generic_testcase()
    testcase.set_metadata('issue_owners', 'dev1@example1.com,dev2@example2.com')
    testcase.set_metadata('issue_components', 'component1')
    testcase.set_metadata('issue_labels', 'label1,label2,label3')

    analyze_task._add_default_issue_metadata(testcase, issue_metadata)  # pylint: disable=protected-access
    self.assertEqual('dev1@example1.com,dev2@example2.com',
                     testcase.get_metadata('issue_owners'))
    self.assertEqual('component1', testcase.get_metadata('issue_components'))
    self.assertEqual('label1,label2,label3',
                     testcase.get_metadata('issue_labels'))
    self.assertEqual(0, self.mock.info.call_count)

  def test_no_default_issue_metadata(self):
    """Test when we only have default issue metadata and no testcase
    metadata."""
    issue_metadata = {
        'issue_owners': 'dev1@example1.com,dev2@example2.com',
        'issue_components': 'component1',
        'issue_labels': 'label1,label2,label3',
        'issue_metadata': json.dumps({
            "assignee": "dev3@example3.com"
        })
    }

    testcase = test_utils.create_generic_testcase()

    analyze_task._add_default_issue_metadata(testcase, issue_metadata)  # pylint: disable=protected-access
    self.assertEqual('dev1@example1.com,dev2@example2.com',
                     testcase.get_metadata('issue_owners'))
    self.assertEqual('component1', testcase.get_metadata('issue_components'))
    self.assertEqual('label1,label2,label3',
                     testcase.get_metadata('issue_labels'))
    self.assertEqual({
        "assignee": "dev3@example3.com"
    }, testcase.get_metadata('issue_metadata'))
    self.assertEqual(4, self.mock.info.call_count)

  def test_same_testcase_and_default_issue_metadata(self):
    """Test when we have same testcase metadata and default issue metadata."""
    issue_metadata = {
        'issue_owners': 'dev1@example1.com,dev2@example2.com',
        'issue_components': 'component1',
        'issue_labels': 'label1,label2,label3'
    }

    testcase = test_utils.create_generic_testcase()
    testcase.set_metadata('issue_owners', 'dev1@example1.com,dev2@example2.com')
    testcase.set_metadata('issue_components', 'component1')
    testcase.set_metadata('issue_labels', 'label1,label2,label3')

    analyze_task._add_default_issue_metadata(testcase, issue_metadata)  # pylint: disable=protected-access
    self.assertEqual('dev1@example1.com,dev2@example2.com',
                     testcase.get_metadata('issue_owners'))
    self.assertEqual('component1', testcase.get_metadata('issue_components'))
    self.assertEqual('label1,label2,label3',
                     testcase.get_metadata('issue_labels'))
    self.assertEqual(0, self.mock.info.call_count)


@test_utils.with_cloud_emulators('datastore')
class SetupTestcaseAndBuildTest(unittest.TestCase):
  """Tests for setup_testcase_and_build."""

  def setUp(self):
    """Do setup for tests."""
    helpers.patch(self, [
        'clusterfuzz._internal.bot.tasks.setup.setup_testcase',
        'clusterfuzz._internal.bot.tasks.utasks.analyze_task.setup_build',
    ])
    helpers.patch_environ(self)
    self.testcase_path = '/fake-testcase-path'
    self.build_url = 'https://build.zip'
    self.mock.setup_testcase.return_value = (None, self.testcase_path, None)
    self.gn_args = ('is_asan = true\n'
                    'use_goma = true\n'
                    'v8_enable_verify_heap = true')

    def setup_build(*args, **kwargs):  # pylint: disable=useless-return
      del args
      del kwargs
      os.environ['BUILD_URL'] = self.build_url
      return None

    self.mock.setup_build.side_effect = setup_build

  @unittest.skip('Metadata isn\'t set properly in tests.')
  def test_field_setting(self):
    """Tests that the correct fields are set after setting up the build.
    Especially testcase.metadata."""
    testcase = data_types.Testcase()
    testcase.put()
    with tempfile.NamedTemporaryFile() as gn_args_path:
      os.environ['GN_ARGS_PATH'] = gn_args_path.name
      gn_args_path.write(bytes(self.gn_args, 'utf-8'))
      gn_args_path.seek(0)
      result = analyze_task.setup_testcase_and_build(testcase, 'job', None, [])
      metadata = json.loads(testcase.additional_metadata)
      self.assertEqual(metadata['gn_args'], self.gn_args)
    self.assertEqual(result, (self.testcase_path, None))
    self.assertEqual(testcase.absolute_path, self.testcase_path)
    self.assertEqual(metadata['build_url'], self.build_url)
    self.assertEqual(testcase.platform, 'linux')


@test_utils.with_cloud_emulators('datastore')
class AnalyzeTaskIntegrationTest(utask_helpers.UtaskIntegrationTest):
  """Integration tests for analyze_task."""

  def setUp(self):
    super().setUp()
    helpers.patch(self, [
        'clusterfuzz._internal.base.tasks.add_task',
    ])
    self.uworker_env['TASK_NAME'] = 'analyze'
    self.uworker_env['JOB_NAME'] = 'libfuzzer_chrome_asan'

  def test_analyze_reproducible(self):
    """Tests that analyze_task handles reproducible testcases properly."""
    self.execute(analyze_task, str(self.testcase.key.id()), self.job_type,
                 self.uworker_env)
    # TODO(metzman): Figure out why this test doesn't crash in CI. The reenable the checks.
    # For now, it's good to check that (de)serialization doesn't exception.
    # testcase = self.testcase.key.get(use_cache=False, use_memcache=False)
    # self.assertTrue(testcase.status, 'Processed')
    # self.assertIn('SCARINESS', testcase.crash_stacktrace)
