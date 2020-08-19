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
"""Handler that schedules ML train jobs."""

from base import tasks
from base import utils
from datastore import data_types
from datastore import fuzz_target_utils
from handlers import base_handler_flask
from libs import handler_flask


class Handler(base_handler_flask.Handler):
  """Schedule ML train tasks."""

  @handler_flask.cron()
  def get(self):
    """Handle a GET request."""
    for job in data_types.Job.query():
      if not utils.string_is_true(
          job.get_environment().get('USE_CORPUS_FOR_ML')):
        continue

      target_jobs = list(fuzz_target_utils.get_fuzz_target_jobs(job=job.name))
      fuzz_targets = fuzz_target_utils.get_fuzz_targets_for_target_jobs(
          target_jobs)

      for target in fuzz_targets:
        tasks.add_task(
            'ml_train',
            target.project_qualified_name(),
            job.name,
            queue=tasks.ML_JOBS_TASKQUEUE)
