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
"""Tests for batch_fuzzer_jobs."""

import unittest

from google.cloud import ndb

from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.tests.test_libs import test_utils
from handlers.cron import batch_fuzzer_jobs


@test_utils.with_cloud_emulators('datastore')
class TestBatchingFuzzerJobs(unittest.TestCase):
  """Test batching FuzzerJob entitites."""

  def setUp(self):
    self.total_fuzzer_jobs = 7000
    self.platforms = ['LINUX', 'WINDOWS']
    fuzzer_jobs = []
    for platform in self.platforms:
      for i in range(self.total_fuzzer_jobs):
        fuzzer_job = data_types.FuzzerJob(
            fuzzer='libFuzzer',
            job='libfuzzer_asan_{}_{:06d}'.format(platform, i),
            platform=platform)
        fuzzer_jobs.append(fuzzer_job)

    ndb.put_multi(fuzzer_jobs)

    # Should be removed.
    data_types.FuzzerJobs(id='LINUX-2', platform='LINUX').put()

    # Should be overwritten and not removed.
    data_types.FuzzerJobs(id='LINUX-0', platform='LINUX').put()

  def test_batch(self):
    """Test batching."""
    batch_fuzzer_jobs.batch_fuzzer_jobs()
    for platform in self.platforms:
      all_fuzzer_jobs = []
      for i in range(2):
        key = ndb.Key(data_types.FuzzerJobs, platform + '-' + str(i))
        fuzzer_jobs = key.get()
        all_fuzzer_jobs.extend(fuzzer_jobs.fuzzer_jobs)

      self.assertEqual(self.total_fuzzer_jobs, len(all_fuzzer_jobs))
      for i in range(self.total_fuzzer_jobs):
        self.assertEqual('libfuzzer_asan_{}_{:06d}'.format(platform, i),
                         all_fuzzer_jobs[i].job)

    self.assertIsNone(ndb.Key(data_types.FuzzerJobs, 'LINUX-2').get())
