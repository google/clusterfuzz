# Copyright 2025 Google LLC
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
"""Reproduces a testcase locally"""

import os
import json

from clusterfuzz._internal.config import local_config

from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import ndb_init
from clusterfuzz._internal.datastore.data_types import Testcase, Job
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.bot import testcase_manager
from clusterfuzz._internal.bot.tasks.commands import update_environment_for_job 

def _execute(args) -> None:
    """Reproduce a testcase locally."""
    testcase : Testcase = data_handler.get_testcase_by_id(args.testcase_id) # TODO: check if testcase-id exists

    print("Testcase: ")
    print(f'Testcase id: {testcase.key.id()}')
    print(f'Status: {testcase.status}')
    print(f'Crash revsion: {testcase.crash_revision}')
    print(f'Job type: {testcase.job_type}')
    print(f'Archive filename: {testcase.archive_filename}')
    print(f'Path: {testcase.absolute_path}')
    print(f'Fuzzer name: {testcase.actual_fuzzer_name()}')
    print(f'Fuzz target: {testcase.get_fuzz_target()}')

    # print(json.dumps(testcase.to_dict(), indent=4, default=str))
    
    job : Job = data_types.Job.query(data_types.Job.name == testcase.job_type).get()
    update_environment_for_job(job.get_environment_string())

    print()
    print("Job: ")
    print(json.dumps(job.to_dict(), indent=4, default=str))
    
    # if input('Do you want to try to reproduce the testcase? (y/N): ').lower() != 'y':
    #     print('Exiting.')
    #     return
    testcase_manager.get_command_line_for_application(testcase.absolute_path, needs_http=False)
    # testcase_manager.test_for_crash_with_retries(
    #     testcase.get_fuzz_target(),
    #     testcase,
    #     testcase.absolute_path,
    #     test_timeout=10,
    #     crash_retries=2
    # )

def execute(args) -> None:
    os.environ['CONFIG_DIR_OVERRIDE'] = os.path.abspath(args.config_dir) # Do I really need this?
    local_config.ProjectConfig().set_environment()

    """Reproduce a testcase locally."""
    with ndb_init.context():
        _execute(args)
