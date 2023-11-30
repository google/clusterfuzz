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
from clusterfuzz._internal.bot.tasks import utasks
from clusterfuzz._internal.google_cloud_utils import batch
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment


class BaseTask:
  """Base module for tasks."""

  def __init__(self, module):
    self.module = module

  def execute(self, task_argument, job_type, uworker_env):
    """Executes a task."""
    raise NotImplementedError('Child class must implement.')

  @classmethod
  def is_execution_remote(self):
    return False


class TrustedTask(BaseTask):
  """Implementation of a task that is run on a single machine. These tasks were
  the original ones in ClusterFuzz."""

  def execute(self, task_argument, job_type, uworker_env):
    # Simple tasks can just use the environment they don't need the uworker env.
    del uworker_env
    self.module.execute_task(task_argument, job_type)


def is_production():
  return not (environment.is_local_development() or
              environment.get_value('UNTRUSTED_RUNNER_TESTS') or
              environment.get_value('LOCAL_DEVELOPMENT') or
              environment.get_value('UTASK_TESTS'))


class BaseUTask(BaseTask):
  """Base class representing an untrusted task. Children must decide to execute
  locally or remotely."""

  def execute(self, task_argument, job_type, uworker_env):
    """Executes a task."""
    raise NotImplementedError('Child class must implement.')

  def execute_locally(self, task_argument, job_type, uworker_env):
    uworker_input = utasks.tworker_preprocess_no_io(self.module, task_argument,
                                                    job_type, uworker_env)
    if uworker_input is None:
      return
    uworker_output = utasks.uworker_main_no_io(self.module, uworker_input)
    if uworker_output is None:
      return
    utasks.tworker_postprocess_no_io(self.module, uworker_output, uworker_input)
    logs.log('Utask local: done.')


class UTaskLocalExecutor(BaseUTask):
  """Represents an untrusted task. Executes it entirely locally and in
  memory."""

  def execute(self, task_argument, job_type, uworker_env):
    """Executes a utask locally in-memory."""
    self.execute_locally(task_argument, job_type, uworker_env)


def is_remotely_executing_utasks():
  return (is_production() and
          environment.get_value('REMOTE_UTASK_EXECUTION') and
          environment.platform() == 'LINUX')


class UTask(BaseUTask):
  """Represents an untrusted task. Executes preprocess on this machine, main on
  an untrusted machine, and postprocess on another trusted machine if
  opted-in. Otherwise executes locally."""

  def execute_preprocess(self, task_argument, job_type, uworker_env):
    return utasks.tworker_preprocess(self.module, task_argument,
                                     job_type, uworker_env)[0]

  @classmethod
  def is_execution_remote(self):
    return is_remotely_executing_utasks()

  def execute(self, task_argument, job_type, uworker_env):
    """Executes a utask locally."""
    if not self.is_execution_remote():
      self.execute_locally(task_argument, job_type, uworker_env)
      return

    download_url = self.execute_preprocess(task_argument, job_type, uworker_env)

    if not download_url:
      logs.log_error('No download_url returned from preprocess.')
      return

    logs.log('Utask: done with preprocess.')
    batch.create_uworker_main_batch_job(self.module.__name__, job_type,
                                        download_url)
    logs.log('Utask: done creating main.')


class PostprocessTask(BaseTask):
  """Represents postprocessing of an untrusted task."""

  def __init__(self, module):
    del module
    # We don't need a module, postprocess isn't a real task, it's one part of
    # many different tasks.
    super().__init__('none')

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

  def execute(self, task_argument, job_type, uworker_env):
    """Executes uworker_main of a utask."""
    # These values are None for now.
    del job_type
    del uworker_env
    input_path = task_argument
    utasks.uworker_main(input_path)


COMMAND_TYPES = {
    'analyze': UTaskLocalExecutor,
    'blame': TrustedTask,
    'corpus_pruning': UTaskLocalExecutor,
    'fuzz': UTaskLocalExecutor,
    'impact': TrustedTask,
    'minimize': UTaskLocalExecutor,
    'progression': UTaskLocalExecutor,
    'regression': UTaskLocalExecutor,
    'symbolize': UTaskLocalExecutor,
    'unpack': TrustedTask,
    'postprocess': PostprocessTask,
    'uworker_main': UworkerMainTask,
    'variant': UTaskLocalExecutor,
}


def is_remote_utask(command):
  return COMMAND_TYPES[command].is_execution_remote()


def get_combinable_commands():
  return [command for command in COMMAND_TYPES
          if is_command_combinable(command)]


def is_trusted_portion_of_utask(command_name):
  """Returns true if |command_name| is asking the bot to execute the
  trusted-portion of a utask (preprocess and postprocess). The workflow for
  executing a task is as follows:
  1. A command such as analyze is given to a bot.
  2. The bot executes preprocess and schedules uworker_main.
  3. The uworker_main command is given to the uworker which executes the
  uworker_main function of the specified task.
  4. Postprocessing runs (the postprocess task is triggered by GCS when
  uworker_main writes its output.
  Therefore, the commands to execute utasks and the "postprocess" command can be
  executed on Linux bots even if the utask is supposed to run on Windows. This
  function returns commands that denote these portions.
  """
  task_type = COMMAND_TYPES[command_name]
  # Postprocess and preprocess tasks are executed on tworkers, while utask_mains
  # are executed on uworkers. Note that the uworker_main command will be used to
  # execute uworker_main, while the name of the task itself will be used to
  # request execution of the preprocess step.
  return task_type in (PostprocessTask, UTask)


def get_utask_trusted_portions():
  return [
      command_name for command_name in COMMAND_TYPES
      if is_trusted_portion_of_utask(command_name)
  ]
