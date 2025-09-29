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
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.build_management import build_manager
from clusterfuzz._internal.bot.fuzzers import init
from clusterfuzz._internal.protos import uworker_msg_pb2
from clusterfuzz._internal.bot.tasks import setup


def _execute(args) -> None:
    """Reproduce a testcase locally."""
    testcase : Testcase = data_handler.get_testcase_by_id(args.testcase_id) 
    
    job : Job = data_types.Job.query(data_types.Job.name == testcase.job_type).get()
    environment.set_value('JOB_NAME', job.name)
    update_environment_for_job(job.get_environment_string())

    # setup.setup_testcase(testcase, job.name, None) this is used in progression task.
    # probably I'm going to need to write my own setup_testcase.

    if(testcase.get_fuzz_target()):
        build_manager.setup_build(revision=testcase.crash_revision, fuzz_target=testcase.get_fuzz_target().binary)
    else:
        build_manager.setup_build(revision=testcase.crash_revision)

    bad_build_result : uworker_msg_pb2.BuildData = testcase_manager.check_for_bad_build(job.name, testcase.crash_revision) # TODO: check the return type
    
    if(bad_build_result.is_bad_build):
        print('Bad build detected, exiting.')
        return
    
    reproduces = testcase_manager.test_for_reproducibility(
        fuzz_target=testcase.get_fuzz_target(),
        testcase_path=testcase.absolute_path, # this is wrong. it doesn't gets the path for the local testcase
        crash_type=testcase.crash_type,
        expected_state=None,
        expected_security_flag=None,
        test_timeout=20,
        http_flag=testcase.http_flag,
        gestures=testcase.gestures,
        arguments=None
    )

    print(reproduces)

def execute(args) -> None:
    os.environ['CONFIG_DIR_OVERRIDE'] = os.path.abspath(args.config_dir) # Do I really need this?
    local_config.ProjectConfig().set_environment() # this is alredy done in set_bot_environment()
    environment.set_bot_environment()
    os.environ['LOG_TO_CONSOLE'] = 'True'
    os.environ['LOCAL_DEVELOPMENT'] = 'True'
    os.environ['LOG_TO_GCP'] = ''
    logs.configure('run_bot')
    init.run()

    """Reproduce a testcase locally."""
    with ndb_init.context():
        _execute(args)
