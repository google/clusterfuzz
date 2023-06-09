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

# import json
import os
import tempfile
import unittest

from clusterfuzz._internal.bot.tasks.utasks import analyze_task
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils


@test_utils.with_cloud_emulators('datastore')
class AddDefaultIssueMetadataTest(unittest.TestCase):
  """Test _add_default_issue_metadata."""

  def setUp(self):
    helpers.patch(
        self,
        [
            'clusterfuzz._internal.bot.fuzzers.engine_common.'
            'get_all_issue_metadata_for_testcase',
            # Disable logging.
            'clusterfuzz._internal.datastore.data_types.Testcase._post_put_hook',
            'clusterfuzz._internal.metrics.logs.log',
        ])

  def test_union(self):
    """Test union of current testcase metadata and default issue metadata."""
    self.mock.get_all_issue_metadata_for_testcase.return_value = {
        'issue_owners': 'dev1@example1.com, dev2@example2.com',
        'issue_components': 'component1',
        'issue_labels': 'label1, label2 ,label3'
    }

    testcase = test_utils.create_generic_testcase()
    testcase.set_metadata('issue_owners', 'dev3@example3.com,dev2@example2.com')
    testcase.set_metadata('issue_components', 'component2')
    testcase.set_metadata('issue_labels', 'label4,label5, label2,')

    analyze_task._add_default_issue_metadata(testcase)  # pylint: disable=protected-access
    self.assertEqual('dev1@example1.com,dev2@example2.com,dev3@example3.com',
                     testcase.get_metadata('issue_owners'))
    self.assertEqual('component1,component2',
                     testcase.get_metadata('issue_components'))
    self.assertEqual('label1,label2,label3,label4,label5',
                     testcase.get_metadata('issue_labels'))
    self.assertEqual(3, self.mock.log.call_count)

  def test_no_testcase_metadata(self):
    """Test when we only have default issue metadata and no testcase
    metadata."""
    self.mock.get_all_issue_metadata_for_testcase.return_value = None

    testcase = test_utils.create_generic_testcase()
    testcase.set_metadata('issue_owners', 'dev1@example1.com,dev2@example2.com')
    testcase.set_metadata('issue_components', 'component1')
    testcase.set_metadata('issue_labels', 'label1,label2,label3')

    analyze_task._add_default_issue_metadata(testcase)  # pylint: disable=protected-access
    self.assertEqual('dev1@example1.com,dev2@example2.com',
                     testcase.get_metadata('issue_owners'))
    self.assertEqual('component1', testcase.get_metadata('issue_components'))
    self.assertEqual('label1,label2,label3',
                     testcase.get_metadata('issue_labels'))
    self.assertEqual(0, self.mock.log.call_count)

  def test_no_default_issue_metadata(self):
    """Test when we only have testcase metadata and no default issue
    metadata."""
    self.mock.get_all_issue_metadata_for_testcase.return_value = {
        'issue_owners': 'dev1@example1.com,dev2@example2.com',
        'issue_components': 'component1',
        'issue_labels': 'label1,label2,label3'
    }

    testcase = test_utils.create_generic_testcase()

    analyze_task._add_default_issue_metadata(testcase)  # pylint: disable=protected-access
    self.assertEqual('dev1@example1.com,dev2@example2.com',
                     testcase.get_metadata('issue_owners'))
    self.assertEqual('component1', testcase.get_metadata('issue_components'))
    self.assertEqual('label1,label2,label3',
                     testcase.get_metadata('issue_labels'))
    self.assertEqual(3, self.mock.log.call_count)

  def test_same_testcase_and_default_issue_metadata(self):
    """Test when we have same testcase metadata and default issue metadata."""
    self.mock.get_all_issue_metadata_for_testcase.return_value = {
        'issue_owners': 'dev1@example1.com,dev2@example2.com',
        'issue_components': 'component1',
        'issue_labels': 'label1,label2,label3'
    }

    testcase = test_utils.create_generic_testcase()
    testcase.set_metadata('issue_owners', 'dev1@example1.com,dev2@example2.com')
    testcase.set_metadata('issue_components', 'component1')
    testcase.set_metadata('issue_labels', 'label1,label2,label3')

    analyze_task._add_default_issue_metadata(testcase)  # pylint: disable=protected-access
    self.assertEqual('dev1@example1.com,dev2@example2.com',
                     testcase.get_metadata('issue_owners'))
    self.assertEqual('component1', testcase.get_metadata('issue_components'))
    self.assertEqual('label1,label2,label3',
                     testcase.get_metadata('issue_labels'))
    self.assertEqual(0, self.mock.log.call_count)


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

  def test_field_setting(self):
    """Tests that the correct fields are set after setting up the build.
    Especially testcase.metadata."""
    testcase = data_types.Testcase()
    testcase.put()
    with tempfile.NamedTemporaryFile() as gn_args_path:
      os.environ['GN_ARGS_PATH'] = gn_args_path.name
      gn_args_path.write(bytes(self.gn_args, 'utf-8'))
      gn_args_path.seek(0)
      result = analyze_task.setup_testcase_and_build(testcase, None, 'job',
                                                     'https://fake-url')
      self.assertTrue(False)  # pylint: disable=redundant-unittest-assert
      metadata = json.loads(testcase.additional_metadata)
      self.assertEqual(metadata['gn_args'], self.gn_args)
    self.assertEqual(result, (self.testcase_path, None))
    self.assertEqual(testcase.absolute_path, self.testcase_path)
    self.assertEqual(metadata['build_url'], self.build_url)
    self.assertEqual(testcase.platform, 'linux')
