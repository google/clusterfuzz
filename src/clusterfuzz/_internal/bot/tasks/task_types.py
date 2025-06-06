# Copyright 2023 Google LLC
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
"""Types of tasks. This needs to be seperate from commands.py because
base/tasks.py depends on this module and many things commands.py imports depend
on base/tasks.py (i.e. avoiding circular imports)."""
from clusterfuzz._internal import swarming
from clusterfuzz._internal.base import tasks
from clusterfuzz._internal.base.tasks import task_utils
from clusterfuzz._internal.bot.tasks import utasks
from clusterfuzz._internal.google_cloud_utils import batch
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment


class BaseTask:
  """Base module for tasks."""

  @staticmethod
  def is_execution_remote(command=None):
    del command
    return False

  def __init__(self, module):
    self.module = module

  def execute(self, task_argument, job_type, uworker_env):
    """Executes a task."""
    raise NotImplementedError('Child class must implement.')


class TrustedTask(BaseTask):
  """Implementation of a task that is run on a single machine. These tasks were
  the original ones in ClusterFuzz."""

  @logs.task_stage_context(logs.Stage.NA)
  def execute(self, task_argument, job_type, uworker_env):
    # Simple tasks can just use the environment they don't need the uworker env.
    del uworker_env
    assert not environment.is_tworker()
    self.module.execute_task(task_argument, job_type)


class BaseUTask(BaseTask):
  """Base class representing an untrusted task. Children must decide to execute
  locally or remotely."""

  def execute(self, task_argument, job_type, uworker_env):
    """Executes a task."""
    raise NotImplementedError('Child class must implement.')

  def execute_locally(self, task_argument, job_type, uworker_env):
    """Executes the utask locally (on this machine, not on batch)."""
    assert not environment.is_tworker()
    uworker_input = utasks.tworker_preprocess_no_io(self.module, task_argument,
                                                    job_type, uworker_env)
    if uworker_input is None:
      return
    uworker_output = utasks.uworker_main_no_io(self.module, uworker_input)
    if uworker_output is None:
      return
    utasks.tworker_postprocess_no_io(self.module, uworker_output, uworker_input)
    logs.info('Utask local: done.')

  def preprocess(self, task_argument, job_type, uworker_env):
    """Executes preprocessing."""
    raise NotImplementedError('Child class must implement.')


def is_no_privilege_workload(command, job):
  if not COMMAND_TYPES[command].is_execution_remote(command):
    return False
  return batch.is_no_privilege_workload(command, job)


def is_remote_utask(command, job):
  if not COMMAND_TYPES[command].is_execution_remote(command):
    return False

  if environment.is_uworker():
    # Return True even if we can't query the db.
    return True

  return batch.is_remote_task(command, job) or swarming.is_swarming_task(
      command, job)


def task_main_runs_on_uworker():
  """This returns True if the uworker_main portion of this task is
  unprivileged."""
  command = environment.get_value('TASK_NAME')
  job = environment.get_value('JOB_NAME')
  return is_remote_utask(command, job)


class UTaskLocalExecutor(BaseUTask):
  """Represents an untrusted task. Executes it entirely locally and in
  memory."""

  def execute(self, task_argument, job_type, uworker_env):
    """Executes a utask locally in-memory."""
    self.execute_locally(task_argument, job_type, uworker_env)

  def preprocess(self, task_argument, job_type, uworker_env):
    """Executes preprocessing."""
    raise NotImplementedError('Only needed for utasks.')


class UTask(BaseUTask):
  """Represents an untrusted task. Executes preprocess on this machine, main on
  an untrusted machine, and postprocess on another trusted machine if
  opted-in. Otherwise executes locally."""

  @staticmethod
  def is_execution_remote(command=None):
    return task_utils.is_remotely_executing_utasks()

  def execute(self, task_argument, job_type, uworker_env):
    """Executes a utask."""
    logs.info('Executing utask.')
    command = task_utils.get_command_from_module(self.module.__name__)
    # TODO(metzman): This is really complicated because of the need to test
    # remote execution. This is no longer a need, so simplify this.
    if not (environment.is_tworker() or is_remote_utask(command, job_type)):
      self.execute_locally(task_argument, job_type, uworker_env)
      return

    logs.info('Preprocessing utask.')
    download_url = self.preprocess(task_argument, job_type, uworker_env)
    if download_url is None:
      return

    logs.info('Queueing utask for remote execution.', download_url=download_url)
    if batch.is_remote_task(command, job_type):
      tasks.add_utask_main(command, download_url, job_type)
    else:
      assert swarming.is_swarming_task(command, job_type)
      swarming.push_swarming_task(command, download_url, job_type)

  @logs.task_stage_context(logs.Stage.PREPROCESS)
  def preprocess(self, task_argument, job_type, uworker_env):
    result = utasks.tworker_preprocess(self.module, task_argument, job_type,
                                       uworker_env)
    if not result:
      return None

    download_url, _ = result
    if not download_url:
      logs.error('No download_url returned from preprocess.')
      return None
    logs.info('Utask: done with preprocess.')
    return download_url


class PostprocessTask(BaseTask):
  """Represents postprocessing of an untrusted task."""

  def __init__(self, module):
    del module
    # We don't need a module, postprocess isn't a real task, it's one part of
    # many different tasks.
    super().__init__('none')

  @logs.task_stage_context(logs.Stage.POSTPROCESS)
  def execute(self, task_argument, job_type, uworker_env):
    """Executes postprocessing of a utask."""
    # These values are None for now.
    del job_type
    del uworker_env
    input_path = task_argument
    utasks.tworker_postprocess(input_path)


class UworkerMainTask(BaseTask):
  """Represents uworker main of an untrusted task. This should only be used for
  tasks that cannot use Google Cloud batch (e.g. Mac)."""

  # TODO(metzman): Merge with PostprocessTask.
  def __init__(self, module):
    # We don't need a module, uworker_main isn't a real task, it's one part of
    # many different tasks.
    del module
    super().__init__('none')

  @logs.task_stage_context(logs.Stage.MAIN)
  def execute(self, task_argument, job_type, uworker_env):
    """Executes uworker_main of a utask."""
    # These values are None for now.
    del job_type
    del uworker_env
    input_path = task_argument
    utasks.uworker_main(input_path)


COMMAND_TYPES = {
    'analyze': UTask,
    'blame': TrustedTask,
    'corpus_pruning': UTask,
    'fuzz': UTaskLocalExecutor,
    'impact': TrustedTask,
    'minimize': UTask,
    'progression': UTask,
    'regression': UTask,
    'symbolize': UTask,
    'unpack': TrustedTask,
    'postprocess': PostprocessTask,
    'uworker_main': UworkerMainTask,
    'variant': UTask,
}
