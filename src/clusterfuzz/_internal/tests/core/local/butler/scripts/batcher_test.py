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
"""batcher tests."""
import datetime
import unittest

from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.tests.test_libs import test_utils
from local.butler.scripts import batcher


@test_utils.with_cloud_emulators('datastore')
class BatcherTest(unittest.TestCase):
  """Test batcher."""

  def setUp(self):
    self.testcase_ids = []
    for i in range(100):
      testcase = data_types.Testcase()
      testcase.timestamp = datetime.datetime.fromtimestamp(i)
      testcase.put()
      self.testcase_ids.append(testcase.key.id())

  def _test(self, batch_size, expected_batch_count, expected_count):
    """Test when the limit is too large."""
    query = data_types.Testcase.query().order(data_types.Testcase.timestamp)
    list_of_testcases = list(batcher.iterate(query, batch_size=batch_size))

    self.assertEqual(expected_batch_count, len(list_of_testcases))
    count = 0
    for testcases in list_of_testcases:
      for testcase in testcases:
        self.assertEqual(self.testcase_ids[count], testcase.key.id())
        count += 1
    self.assertEqual(expected_count, count)

  def test_batch(self):
    """Test batching."""
    self._test(2, 50, 100)

  def test_batch_non_multiple(self):
    """Test when the batch size is not a multiple."""
    self._test(7, 15, 100)

  def test_too_large_batch(self):
    """Test when the batch is too large."""
    self._test(105, 1, 100)

  def test_exact_batch(self):
    """Test when the batch is exactly the number of items."""
    self._test(100, 1, 100)
