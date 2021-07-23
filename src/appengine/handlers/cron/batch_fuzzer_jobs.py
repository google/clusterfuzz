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
"""A cron handler that batches FuzzerJobs."""

from google.cloud import ndb

from clusterfuzz._internal.datastore import data_types
from handlers import base_handler
from libs import handler

FUZZER_JOB_BATCH_SIZE = 4000


def batch_fuzzer_jobs():
  """Batch FuzzerJobs for reduced Datastore read ops by bots."""
  platforms = [
      item.platform for item in data_types.FuzzerJob.query(
          projection=[data_types.FuzzerJob.platform], distinct=True)
  ]

  for platform in platforms:
    fuzzer_jobs = list(
        data_types.FuzzerJob.query(data_types.FuzzerJob.platform == platform))
    fuzzer_jobs.sort(key=lambda item: item.job)

    batches_to_remove = set(
        b.key for b in data_types.FuzzerJobs.query(
            data_types.FuzzerJobs.platform == platform))

    batch_count = 0
    for i in range(0, len(fuzzer_jobs), FUZZER_JOB_BATCH_SIZE):
      key_id = platform + '-' + str(batch_count)
      end = min(i + FUZZER_JOB_BATCH_SIZE, len(fuzzer_jobs))

      batched = data_types.FuzzerJobs(id=key_id, platform=platform)
      batched.platform = platform
      batched.fuzzer_jobs = fuzzer_jobs[i:end]
      batched.put()
      batch_count += 1

      batches_to_remove.discard(batched.key)

    # Remove additional batches if number reduced.
    if batches_to_remove:
      ndb.delete_multi(batches_to_remove)


class Handler(base_handler.Handler):
  """Handler for building data_types.CrashsStats2."""

  @handler.cron()
  def get(self):
    """Process a GET request from a cronjob."""
    batch_fuzzer_jobs()
