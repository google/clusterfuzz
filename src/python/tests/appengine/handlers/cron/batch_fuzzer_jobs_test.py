# Lint as: python3
"""Tests for batch_fuzzer_jobs."""

import unittest

from google.cloud import ndb

from datastore import data_types
from handlers.cron import batch_fuzzer_jobs
from tests.test_libs import helpers as test_helpers
from tests.test_libs import test_utils


@test_utils.with_cloud_emulators('datastore')
class TestBatchingFuzzerJobs(unittest.TestCase):
  """Test batching FuzzerJob entitites."""

  def setUp(self):
    self.total_fuzzer_jobs = 12000
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
        self.assertEqual('libfuzzer_asan_{}_{:06d}'.format(platform, i), all_fuzzer_jobs[i].job)
