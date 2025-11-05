# Copyright 2024 Google LLC
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
"""Run a task locally."""
import os

from clusterfuzz._internal.bot.tasks import commands
from clusterfuzz._internal.build_management import build_manager
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment


def execute(args):
  """Add build url and gn args to testcase metadata."""

  del args
  environment.set_bot_environment()
  environment.set_local_log_only()
  logs.configure('run_bot')
  dry_run = False
  print(f'Starting - DRY RUN = {dry_run}')
  print()
  n_missing = 0
  n_limit = 300
  updated_testcases = []
  # [6162924968017920, 5115444050460672, 6100880994533376, 5113383019806720, 5468644226039808, 4974258308448256]

  for testcase_id in data_handler.get_open_testcase_id_iterator():
    if n_limit > 0 and n_missing >= n_limit:
      break
    try:
      testcase = data_handler.get_testcase_by_id(testcase_id)
      if testcase.get_metadata('build_url') or testcase.get_metadata('build_key'):
        continue
      print(f'Missing BUILD_URL/BUILD_KEY - Testcase_id: {testcase_id}')
      n_missing += 1

      if not dry_run:
        job = data_types.Job.query(data_types.Job.name == testcase.job_type).get()
        if not job:
          continue

        os.environ.pop('BUILD_URL', None)
        os.environ.pop('BUILD_KEY', None)
        os.environ.pop('GN_ARGS_PATH', None)
        environment.set_value('JOB_NAME', job.name)
        commands.update_environment_for_job(job.get_environment_string())

        fuzz_target = testcase.get_fuzz_target()
        fuzz_target_bin = fuzz_target.binary if fuzz_target else None

        _ = build_manager.setup_build(testcase.crash_revision, fuzz_target_bin)
        data_handler.set_build_metadata_to_testcase(testcase, update=True)
        updated_testcases.append(testcase_id)
    except:
      continue

  print(f'Total missing: {n_missing}')
  with open('missing_build_testcases.txt', 'w') as f:
    for testcase_id in updated_testcases:
      f.write(f'{testcase_id}\n')
