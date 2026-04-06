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
"""Script to inject a fuzz task directly into the tworker PREPROCESS_QUEUE."""

from clusterfuzz._internal.base import tasks


def execute(args):
  """Inject a task directly into the PREPROCESS_QUEUE."""

  if args.script_args is None or len(args.script_args) < 2:
    print(
        'Usage:   butler.py run -c <CONFIG_DIR> schedule_tworker_fuzz --script_args FUZZER_NAME JOB_NAME'
    )
    print(
        'Example: butler.py run -c ~/configs/chrome-dev/ schedule_tworker_fuzz --script_args libFuzzer libfuzzer_asan_linux'
    )
    print(
        'Note:    Pass the --non-dry-run flag before the script name to actually schedule the task.'
    )
    return

  fuzzer_name = args.script_args[0]
  job_name = args.script_args[1]
  command = 'fuzz'

  if not args.non_dry_run:
    print('Running in dry-run mode. Task will NOT be added to the queue.')
    print('Re-run with --non-dry-run to actually schedule the task.')

  print(f'Attempting to add task: {command} {fuzzer_name} {job_name}')
  print(f'Target Queue: {tasks.PREPROCESS_QUEUE}')

  if args.non_dry_run:
    tasks.add_task(
        command=command,
        argument=fuzzer_name,
        job_type=job_name,
        queue=tasks.PREPROCESS_QUEUE,
        wait_time=0)
    print(f"Successfully scheduled '{command}' task!")
