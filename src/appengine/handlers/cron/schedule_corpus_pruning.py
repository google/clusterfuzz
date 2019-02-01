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
"""Schedule corpus pruning tasks."""

from base import tasks
from base import utils
from build_management import build_manager
from datastore import data_types
from datastore import fuzz_target_utils
from handlers import base_handler
from libs import handler
from metrics import logs


def _get_latest_job_revision(job):
  """Return the latest release revision for a job."""
  job_environment = job.get_environment()
  release_build_bucket_path = job_environment.get('RELEASE_BUILD_BUCKET_PATH')
  if not release_build_bucket_path:
    logs.log_error('Failed to get release build url pattern for %s.' % job.name)
    return None

  revisions = build_manager.get_revisions_list(release_build_bucket_path)

  if not revisions:
    logs.log_error('Failed to get revisions list for %s.' % job.name)
    return None

  logs.log('Latest revision for %s is %d.' % (job.name, revisions[-1]))
  return revisions[-1]


class Handler(base_handler.Handler):
  """Schedule corpus pruning tasks.."""

  @handler.check_cron()
  def get(self):
    """Schedule the corpus pruning tasks."""
    for job in data_types.Job.query():
      if not utils.string_is_true(job.get_environment().get('CORPUS_PRUNE')):
        continue

      latest_revision = _get_latest_job_revision(job)
      if not latest_revision:
        continue

      queue = tasks.queue_for_job(job.name)
      for target_job in fuzz_target_utils.get_fuzz_target_jobs(job=job.name):
        tasks.add_task(
            'corpus_pruning',
            '%s@%s' % (target_job.fuzz_target_name, latest_revision),
            job.name,
            queue=queue)
