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

from clusterfuzz._internal.base import tasks
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import fuzz_target_utils
from clusterfuzz._internal.metrics import logs
from handlers import base_handler
from libs import handler

MODEL_NAME_TO_TASK = {
    'rnn_generator': 'train_rnn_generator',
}


class Handler(base_handler.Handler):
  """Schedule ML train tasks."""

  @handler.cron()
  def get(self):
    """Handle a GET request."""
    for job in data_types.Job.query():

      models = job.get_environment().get('ML_MODELS_TO_USE')
      if not models:
        continue

      task_list = []
      for model_name in models.split(','):
        try:
          task_list.append(MODEL_NAME_TO_TASK[model_name.strip()])
        except KeyError:
          logs.log_error(f'Invalid ML model {model_name} for job {job.name}.')

      if not task_list:
        continue

      target_jobs = list(fuzz_target_utils.get_fuzz_target_jobs(job=job.name))
      fuzz_targets = fuzz_target_utils.get_fuzz_targets_for_target_jobs(
          target_jobs)

      for task_name in task_list:
        for target in fuzz_targets:
          tasks.add_task(
              task_name,
              target.fully_qualified_name(),
              job.name,
              queue=tasks.ML_JOBS_TASKQUEUE)
