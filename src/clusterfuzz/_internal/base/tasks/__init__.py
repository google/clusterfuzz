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
"""Task queue functions."""

import contextlib
import datetime
import functools
import json
import random
import threading
import time
from typing import List
from typing import Optional

from clusterfuzz._internal.base import external_tasks
from clusterfuzz._internal.base import persistent_cache
from clusterfuzz._internal.base import utils
from clusterfuzz._internal.base.tasks import task_utils
from clusterfuzz._internal.config import local_config
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import ndb_utils
from clusterfuzz._internal.fuzzing import fuzzer_selection
from clusterfuzz._internal.google_cloud_utils import pubsub
from clusterfuzz._internal.google_cloud_utils import storage
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment

# Task queue prefixes for various job types.
JOBS_PREFIX = 'jobs'
HIGH_END_JOBS_PREFIX = 'high-end-jobs'

# Default task queue names for various job types. These will be different for
# different platforms with the platform name added as suffix later.
JOBS_TASKQUEUE = JOBS_PREFIX
HIGH_END_JOBS_TASKQUEUE = HIGH_END_JOBS_PREFIX

# Limits on number of tasks leased at once and in total.
MAX_LEASED_TASKS_LIMIT = 1000
MAX_TASKS_LIMIT = 100000

# The stated limit is 1000, but in reality meassages do not get delivered
# around this limit. We should probably switch to the real client library.
MAX_PUBSUB_MESSAGES_PER_REQ = 250

# Various variables for task leasing and completion times (in seconds).
TASK_COMPLETION_BUFFER = 90 * 60
TASK_CREATION_WAIT_INTERVAL = 2 * 60
TASK_EXCEPTION_WAIT_INTERVAL = 5 * 60
TASK_LEASE_SECONDS = 6 * 60 * 60  # Can be overridden via environment variable.
TASK_LEASE_SECONDS_BY_COMMAND = {
    'corpus_pruning': 24 * 60 * 60,
    'regression': 24 * 60 * 60,
}

TASK_QUEUE_DISPLAY_NAMES = {
    'LINUX': 'Linux',
    'LINUX_WITH_GPU': 'Linux (with GPU)',
    'LINUX_UNTRUSTED': 'Linux (untrusted)',
    'ANDROID': 'Android',
    'ANDROID_AUTO': 'Android Auto',
    'ANDROID_X86': 'Android (x86)',
    'ANDROID_EMULATOR': 'Android (Emulated)',
    'CHROMEOS': 'Chrome OS',
    'FUCHSIA': 'Fuchsia OS',
    'MAC': 'Mac',
    'WINDOWS': 'Windows',
    'WINDOWS_WITH_GPU': 'Windows (with GPU)',
}

VALID_REDO_TASKS = ['minimize', 'regression', 'progression', 'impact', 'blame']

LEASE_FAIL_WAIT = 10
LEASE_RETRIES = 5

TASK_PAYLOAD_KEY = 'task_payload'
TASK_END_TIME_KEY = 'task_end_time'

POSTPROCESS_QUEUE = 'postprocess'
UTASK_MAIN_QUEUE = 'utask_main'
PREPROCESS_QUEUE = 'preprocess'

# See https://github.com/google/clusterfuzz/issues/3347 for usage
SUBQUEUE_IDENTIFIER = ':'

UTASK_QUEUE_PULL_SECONDS = 150

# The maximum number of utasks we will collect from the utask queue before
# scheduling on batch.
MAX_UTASKS = 3000


class Error(Exception):
  """Base exception class."""


class InvalidRedoTask(Error):

  def __init__(self, task):
    super().__init__("The task '%s' is invalid." % task)


def queue_suffix_for_platform(platform):
  """Get the queue suffix for a platform."""
  # Handle the case where a subqueue is used.
  platform = platform.lower().replace(SUBQUEUE_IDENTIFIER, '-')
  return '-' + platform.lower().replace('_', '-')


def default_queue_suffix():
  """Get the queue suffix for the current platform."""
  queue_override = environment.get_value('QUEUE_OVERRIDE')
  logs.info(f'QUEUE_OVERRIDE is [{queue_override}]. '
            f'Platform is {environment.platform()}')
  if queue_override:
    return queue_suffix_for_platform(queue_override)

  return queue_suffix_for_platform(environment.platform())


def regular_queue(prefix=JOBS_PREFIX):
  """Get the regular jobs queue."""
  if full_utask_task_model():
    return PREPROCESS_QUEUE
  return prefix + default_queue_suffix()


def high_end_queue():
  """Get the high end jobs queue."""
  return regular_queue(prefix=HIGH_END_JOBS_PREFIX)


def default_queue():
  """Get the default jobs queue."""
  thread_multiplier = environment.get_value('THREAD_MULTIPLIER')
  if thread_multiplier and thread_multiplier > 1:
    return high_end_queue()

  return regular_queue()


def default_android_queue():
  """Get the generic 'android' queue that is not tied to a specific device."""
  # Note: environment.platform() is not used as it could return different
  # values based on the devices.
  # E.g: Pixel 8 it is 'ANDROID_MTE' for Pixel 5 it is 'ANDROID_DEP'
  # TODO: Update this when b/347727208 is fixed
  return JOBS_PREFIX + queue_suffix_for_platform('ANDROID')


def get_command_override():
  """Get command override task."""
  command_override = environment.get_value('COMMAND_OVERRIDE', '').strip()
  if not command_override:
    return None

  parts = command_override.split()
  if len(parts) != 3:
    raise ValueError('Command override should have 3 components.')

  return Task(*parts, is_command_override=True)


def get_fuzz_task():
  """Try to get a fuzz task."""
  argument, job = fuzzer_selection.get_fuzz_task_payload()
  if not argument:
    return None

  return Task('fuzz', argument, job)


def get_high_end_task():
  """Get a high end task."""
  task = get_regular_task(queue=high_end_queue())
  if not task:
    return None

  task.high_end = True
  return task


def get_regular_task(queue=None):
  """Get a regular task."""
  if not queue:
    queue = regular_queue()

  pubsub_puller = PubSubPuller(queue)

  while True:
    messages = pubsub_puller.get_messages(max_messages=1)
    if not messages:
      return None

    task = get_task_from_message(messages[0], queue)
    if task:
      return task


def get_machine_template_for_queue(queue_name):
  """Gets the machine template for the instance used to execute a task from
  |queue_name|. This will be used by tworkers to schedule the appropriate
  machine using batch to execute the utask_main part of a utask."""
  initial_queue_name = queue_name

  # Handle it being high-end (preemptible) or not.
  if queue_name.startswith(JOBS_PREFIX):
    is_high_end = False
    prefix = JOBS_PREFIX
  else:
    assert queue_name.startswith(HIGH_END_JOBS_PREFIX)
    is_high_end = True
    prefix = HIGH_END_JOBS_PREFIX
  # Add 1 for hyphen.
  queue_name = queue_name[len(prefix) + 1:]

  template_name = f'clusterfuzz-{queue_name}'
  if not is_high_end:
    template_name = f'{template_name}-pre'

  templates = get_machine_templates()
  for template in templates:
    if template['name'] == template_name:
      logs.info(
          f'Found machine template for {initial_queue_name}',
          machine_template=template)
      return template
  return None


def get_machine_templates():
  """Returns machine templates."""
  # TODO(metzman): Cache this.
  clusters_config = local_config.Config(local_config.GCE_CLUSTERS_PATH).get()
  project = utils.get_application_id()
  conf = clusters_config[project]
  return conf['instance_templates']


class PubSubPuller:
  """PubSub client providing convenience methods for pulling."""

  def __init__(self, queue):
    self.client = pubsub.PubSubClient()
    self.application_id = utils.get_application_id()
    self.queue = queue

  def get_messages(self, max_messages=1):
    """Pulls a list of messages up to |max_messages| from self.queue using
    pubsub."""
    return self.client.pull_from_subscription(
        pubsub.subscription_name(self.application_id, self.queue), max_messages)

  def get_messages_time_limited(self, max_messages, time_limit_secs):
    """Returns up to |max_messages|. Waits up until |time_limit_secs| to get to
    |max_messages|."""
    start_time = time.time()
    messages = []

    def is_done_collecting_messages():
      curr_time = time.time()
      if curr_time - start_time >= time_limit_secs:
        logs.info('Timed out collecting messages.')
        return True

      if len(messages) >= max_messages:
        return True

      return False

    while not is_done_collecting_messages():
      new_messages = self.get_messages(max_messages - len(messages))
      if new_messages:
        messages.extend(new_messages)

    return messages


def get_postprocess_task():
  """Gets a postprocess task if one exists."""
  # This should only be run on non-preemptible bots.
  if not task_utils.is_remotely_executing_utasks():
    return None
  # Postprocess is platform-agnostic, so we run all such tasks on our
  # most generic and plentiful bots only. In other words, we avoid
  # wasting our precious non-linux bots on generic postprocess tasks.
  if not environment.platform().lower() == 'linux':
    return None
  pubsub_puller = PubSubPuller(POSTPROCESS_QUEUE)
  logs.info('Pulling from postprocess queue')
  messages = pubsub_puller.get_messages(max_messages=1)
  if not messages:
    return None
  task = get_task_from_message(messages[0], POSTPROCESS_QUEUE)
  if task:
    logs.info('Pulled from postprocess queue.')
  return task


def allow_all_tasks():
  return not environment.get_value('PREEMPTIBLE')


def get_preprocess_task():
  pubsub_puller = PubSubPuller(PREPROCESS_QUEUE)
  messages = pubsub_puller.get_messages(max_messages=1)
  if not messages:
    return None
  task = get_task_from_message(
      messages[0], PREPROCESS_QUEUE, task_cls=PubSubTTask)
  if task:
    logs.info('Pulled from preprocess queue.')
  return task


def tworker_get_task():
  """Gets a task for a tworker to do."""
  assert environment.is_tworker()
  # TODO(metzman): Pulling tasks is relatively expensive compared to
  # preprocessing. It's too expensive to pull twice (once from the postproces
  # queue that is probably empty) to do a single preprocess. Investigate
  # combining preprocess and postprocess queues and allowing pulling of
  # multiple messages.
  if random.random() < .5:
    # Pick either one with equal probability so we don't hurt the
    # throughput of one compared to the other.
    # TODO(metzman): We may want to combine these queues to save time reading
    # from queues.
    return get_postprocess_task()
  return get_preprocess_task()


def get_task():
  """Returns an ordinary (non-utask_main) task that is pulled from a ClusterFuzz
  task queue."""
  task = get_command_override()
  if task:
    return task

  if allow_all_tasks():
    # Postprocess tasks need to be executed on a non-preemptible otherwise we
    # can lose the output of a task.
    # Postprocess tasks get priority because they are so quick. They typically
    # only involve a few DB writes and never run user code.
    task = get_postprocess_task()
    if task:
      return task

    # Check the high-end jobs queue for bots with multiplier greater than 1.
    thread_multiplier = environment.get_value('THREAD_MULTIPLIER')
    if thread_multiplier and thread_multiplier > 1:
      task = get_high_end_task()
      if task:
        return task

    task = get_regular_task()
    if task:
      # Log the task details for debug purposes.
      logs.info(f'Got task with cmd {task.command} args {task.argument} '
                f'job {task.job} from {regular_queue()} queue.')
      return task

    if environment.is_android():
      logs.info(f'Could not get task from {regular_queue()}. Trying from'
                f'default android queue {default_android_queue()}.')
      task = get_regular_task(default_android_queue())
      if task:
        # Log the task details for debug purposes.
        logs.info(f'Got task with cmd {task.command} args {task.argument} '
                  f'job {task.job} from {default_android_queue()} queue.')
        return task

  logs.info(f'Could not get task from {regular_queue()}. Fuzzing.')

  task = get_fuzz_task()
  if not task:
    logs.error('Failed to get any fuzzing tasks. This should not happen.')
    time.sleep(TASK_EXCEPTION_WAIT_INTERVAL)

  return task


def construct_payload(command, argument, job, queue=None):
  """Constructs payload for task, a standard description of tasks."""
  return ' '.join([command, str(argument), str(job), str(queue)])


class Task:
  """Represents a task."""

  def __init__(self,
               command,
               argument,
               job,
               eta=None,
               is_command_override=False,
               high_end=False,
               extra_info=None,
               queue=None):
    self.command = command
    self.argument = argument
    self.job = job
    self.eta = eta
    self.is_command_override = is_command_override
    self.high_end = high_end
    self.extra_info = extra_info
    self.queue = queue

  def __repr__(self):
    return f'Task: {self.command} {self.argument} {self.job} {self.queue}'

  def attribute(self, _):
    return None

  def payload(self):
    """Get the payload."""
    return construct_payload(self.command, self.argument, self.job, self.queue)

  def to_pubsub_message(self):
    """Convert the task to a pubsub message."""
    attributes = {
        'command': self.command,
        'argument': str(self.argument),
        'job': self.job,
    }
    if self.extra_info is not None:
      for attribute, value in self.extra_info.items():
        if attribute in attributes:
          raise ValueError(f'Cannot set {attribute} using extra_info.')
        attributes[attribute] = value

    if self.eta:
      attributes['eta'] = str(utils.utc_datetime_to_timestamp(self.eta))

    return pubsub.Message(attributes=attributes)

  @contextlib.contextmanager
  def lease(self):
    """Maintain a lease for the task. Track only start and end by default."""
    # Assume default time for non-pubsub tasks.
    track_task_start(self, TASK_LEASE_SECONDS)
    yield
    track_task_end()

  def set_queue(self, queue):
    self.queue = queue
    return self


class PubSubTask(Task):
  """A Pub/Sub task."""

  def __init__(self, pubsub_message):
    self._pubsub_message = pubsub_message
    super().__init__(
        self.attribute('command'), self.attribute('argument'),
        self.attribute('job'))

    self.extra_info = {
        key: value
        for key, value in self._pubsub_message.attributes.items()
        if key not in {'command', 'argument', 'job', 'eta'}
    }

    self.eta = datetime.datetime.utcfromtimestamp(float(self.attribute('eta')))

  def attribute(self, key):
    """Return attribute value."""
    try:
      return self._pubsub_message.attributes[key]
    except KeyError:
      logs.error((f'KeyError: Missing key {key} in message: '
                  f'{self._pubsub_message.attributes}'))
      raise

  def defer(self):
    """Defer a task until its ETA. Returns whether or not we deferred."""
    if self.eta is None:
      return False
    now = utils.utcnow()
    if now >= self.eta:
      return False

    # Extend the deadline until the ETA, or MAX_ACK_DEADLINE.
    time_until_eta = int((self.eta - now).total_seconds())
    logs.info('Deferring task "%s".' % self.payload())
    self._pubsub_message.modify_ack_deadline(
        min(pubsub.MAX_ACK_DEADLINE, time_until_eta))
    return True

  @contextlib.contextmanager
  def lease(self, _event=None):  # pylint: disable=arguments-differ
    """Maintain a lease for the task."""
    task_lease_timeout = TASK_LEASE_SECONDS_BY_COMMAND.get(
        self.command, get_task_lease_timeout())

    environment.set_value('TASK_LEASE_SECONDS', task_lease_timeout)
    track_task_start(self, task_lease_timeout)

    if _event is None:
      _event = threading.Event()

    leaser_thread = _PubSubLeaserThread(self._pubsub_message, _event,
                                        task_lease_timeout)
    leaser_thread.start()
    try:
      yield leaser_thread
    finally:
      _event.set()
      leaser_thread.join()

    # If we get here the task succeeded in running. Acknowledge the message.
    self._pubsub_message.ack()
    track_task_end()

  def dont_retry(self):
    self._pubsub_message.ack()


class PubSubTTask(PubSubTask):
  """TTask from pubsub."""
  TTASK_TIMEOUT = 30 * 60

  @contextlib.contextmanager
  def lease(self, _event=None):  # pylint: disable=arguments-differ
    """Maintain a lease for the task."""
    task_lease_timeout = TASK_LEASE_SECONDS_BY_COMMAND.get(
        self.command, get_task_lease_timeout())

    environment.set_value('TASK_LEASE_SECONDS', task_lease_timeout)
    track_task_start(self, task_lease_timeout)
    if _event is None:
      _event = threading.Event()
    # We won't repeat fuzz task if we timeout, there's nothing
    # important about any particular fuzz task.
    if self.command != 'fuzz':
      leaser_thread = _PubSubLeaserThread(self._pubsub_message, _event,
                                          task_lease_timeout)
    else:
      leaser_thread = _PubSubLeaserThread(
          self._pubsub_message, _event, self.TTASK_TIMEOUT, ack_on_timeout=True)
    leaser_thread.start()
    try:
      yield leaser_thread
    finally:
      _event.set()
      leaser_thread.join()

    # If we get here the task succeeded in running. Acknowledge the message.
    self._pubsub_message.ack()
    track_task_end()


def get_task_from_message(message, queue=None, can_defer=True,
                          task_cls=None) -> Optional[PubSubTask]:
  """Returns a task constructed from the first of |messages| if possible."""
  if message is None:
    return None
  try:
    task = initialize_task(message, task_cls=task_cls)
    if task is None:
      return None
  except KeyError:
    logs.error('Received an invalid task, discarding...')
    message.ack()
    return None

  task = task.set_queue(queue)
  # Check that this task should be run now (past the ETA). Otherwise we defer
  # its execution.
  if can_defer and task.defer():
    return None

  return task


def get_utask_mains() -> List[PubSubTask]:
  """Returns a list of tasks for preprocessing many utasks on this bot and then
  running the uworker_mains in the same batch job."""
  pubsub_puller = PubSubPuller(UTASK_MAIN_QUEUE)
  messages = pubsub_puller.get_messages_time_limited(MAX_UTASKS,
                                                     UTASK_QUEUE_PULL_SECONDS)
  return handle_multiple_utask_main_messages(messages, UTASK_MAIN_QUEUE)


def handle_multiple_utask_main_messages(messages, queue) -> List[PubSubTask]:
  """Merges tasks specified in |messages| into a list for processing on this
  bot."""
  tasks = []
  for message in messages:
    # We shouldn't defer as that was done for the preprocess part of this ttask.
    task = get_task_from_message(message, queue, can_defer=False)
    if task is None:
      continue
    tasks.append(task)

  logs.info(
      'Got utask_mains.',
      tasks_extras_info=[task.extra_info for task in tasks if task])
  return tasks


def initialize_task(message, task_cls=None) -> PubSubTask:
  """Creates a task from |messages|."""
  if task_cls is None:
    task_cls = PubSubTask

  if message.attributes.get('eventType') not in {
      'OBJECT_FINALIZE', 'OBJECT_DELETE'
  }:
    return task_cls(message)

  # Handle postprocess task.
  # The GCS API for pub/sub notifications uses the data field unlike
  # ClusterFuzz which uses attributes more.
  data = json.loads(message.data)
  name = data['name']
  bucket = data['bucket']
  output_url_argument = storage.get_cloud_storage_file_path(bucket, name)
  task = PostprocessPubSubTask(output_url_argument, message)
  if message.attributes.get('eventType') == 'OBJECT_DELETE':
    # These may be from maintainer action to reduce the size of the buckets,
    # just ignore these.
    task.ack()
    return None
  return task


class PostprocessPubSubTask(PubSubTask):
  """A postprocess task received over pub/sub."""

  def __init__(self,
               output_url_argument,
               pubsub_message,
               is_command_override=False):
    command = 'postprocess'
    job_type = 'none'
    eta = None
    high_end = False
    grandparent_class = super(PubSubTask, self)
    grandparent_class.__init__(command, output_url_argument, job_type, eta,
                               is_command_override, high_end)
    self._pubsub_message = pubsub_message

  def ack(self):
    self._pubsub_message.ack()


class _PubSubLeaserThread(threading.Thread):
  """Thread that continuously renews the lease for a message."""

  EXTENSION_TIME_SECONDS = 10 * 60  # 10 minutes.

  def __init__(self,
               message,
               done_event,
               max_lease_seconds,
               ack_on_timeout=False):
    super().__init__()

    self.daemon = True
    self._message = message
    self._done_event = done_event
    self._max_lease_seconds = max_lease_seconds
    self._ack_on_timeout = ack_on_timeout

  def run(self):
    """Run the leaser thread."""
    latest_end_time = time.time() + self._max_lease_seconds

    while True:
      try:
        time_left = latest_end_time - time.time()
        if time_left <= 0:
          logs.info('Lease reached maximum lease time of {} seconds, '
                    'stopping renewal.'.format(self._max_lease_seconds))
          if self._ack_on_timeout:
            logs.info('Acking on timeout')
            self._message.ack()
          break

        extension_seconds = min(self.EXTENSION_TIME_SECONDS, time_left)

        logs.info(
            'Renewing lease for task by {} seconds.'.format(extension_seconds))
        self._message.modify_ack_deadline(extension_seconds)

        # Schedule renewals earlier than the extension to avoid race conditions
        # and performing the next extension too late.
        wait_seconds = min(time_left, self.EXTENSION_TIME_SECONDS // 2)

        # Wait until the next scheduled renewal, or if the task is complete.
        if self._done_event.wait(wait_seconds):
          logs.info('Task complete, stopping renewal.')
          break
      except Exception:
        logs.error('Leaser thread failed.')


def add_utask_main(command, input_url, job_type, wait_time=None):
  """Adds the utask_main portion of a utask to the utasks queue for scheduling
  on batch. This should only be done after preprocessing."""
  initial_command = environment.get_value('TASK_PAYLOAD')
  add_task(
      command,
      input_url,
      job_type,
      queue=UTASK_MAIN_QUEUE,
      wait_time=wait_time,
      extra_info={'initial_command': initial_command})


def bulk_add_tasks(tasks, queue=None, eta_now=False):
  """Adds |tasks| in bulk to |queue|."""
  # Old testcases may pass in queue=None explicitly, so we must check this here.
  if queue is None:
    queue = default_queue()

  # If callers want delays, they must do it themselves, because this function is
  # meant to be used for batch tasks which don't need this.
  # Use an ETA of right now for batch because we don't need extra delay, there
  # is natural delay added by batch, waiting for utask_main_scheduler,
  # postprocess etc.
  if eta_now:
    now = utils.utcnow()
    for task in tasks:
      task.eta = now

  pubsub_client = pubsub.PubSubClient()
  pubsub_messages = [task.to_pubsub_message() for task in tasks]
  topic_name = pubsub.topic_name(utils.get_application_id(), queue)
  for batch in utils.batched(pubsub_messages, MAX_PUBSUB_MESSAGES_PER_REQ):
    pubsub_client.publish(topic_name, batch)


def add_task(command,
             argument,
             job_type,
             queue=None,
             wait_time=None,
             extra_info=None):
  """Add a new task to the job queue."""
  if wait_time is None:
    wait_time = random.randint(1, TASK_CREATION_WAIT_INTERVAL)

  if job_type != 'none':
    job = data_types.Job.query(data_types.Job.name == job_type).get()
    if not job:
      raise Error(f'Job {job_type} not found.')

    if job.is_external():
      external_tasks.add_external_task(command, argument, job)
      return

  # Add the task.
  eta = utils.utcnow() + datetime.timedelta(seconds=wait_time)
  task = Task(command, argument, job_type, eta=eta, extra_info=extra_info)

  bulk_add_tasks([task], queue=queue)


def get_task_lease_timeout():
  """Return the task lease timeout."""
  return environment.get_value('TASK_LEASE_SECONDS', TASK_LEASE_SECONDS)


def get_task_completion_deadline():
  """Return task completion deadline. This gives an additional buffer over the
  task lease deadline."""
  start_time = time.time()
  task_lease_timeout = get_task_lease_timeout()
  return start_time + task_lease_timeout - TASK_COMPLETION_BUFFER


@functools.lru_cache
def full_utask_task_model() -> bool:
  return local_config.ProjectConfig().get('full_utask_model.enabled', False)


def queue_for_platform(platform, is_high_end=False):
  """Return the queue for the platform."""
  if full_utask_task_model():
    return PREPROCESS_QUEUE
  prefix = HIGH_END_JOBS_PREFIX if is_high_end else JOBS_PREFIX
  return prefix + queue_suffix_for_platform(platform)


def queue_for_testcase(testcase):
  """Return the right queue for the testcase."""
  is_high_end = (
      testcase.queue and testcase.queue.startswith(HIGH_END_JOBS_PREFIX))
  return queue_for_job(testcase.job_type, is_high_end=is_high_end)


def queue_for_job(job_name, is_high_end=False):
  """Queue for job."""
  job = data_types.Job.query(data_types.Job.name == job_name).get()
  if not job:
    raise Error('Job {} not found.'.format(job_name))

  return queue_for_platform(job.platform, is_high_end)


def redo_testcase(testcase, tasks, user_email):
  """Redo specific tasks for a testcase. This is requested by the user from the
  web interface."""
  for task in tasks:
    if task not in VALID_REDO_TASKS:
      raise InvalidRedoTask(task)

  minimize = 'minimize' in tasks
  regression = 'regression' in tasks
  progression = 'progression' in tasks
  impact = 'impact' in tasks
  blame = 'blame' in tasks

  task_list = []
  testcase_id = testcase.key.id()

  # Metadata keys to clear based on which redo tasks were selected.
  metadata_keys_to_clear = ['potentially_flaky']

  if minimize:
    task_list.append('minimize')
    testcase.minimized_keys = ''
    testcase.set_metadata('redo_minimize', True, update_testcase=False)
    metadata_keys_to_clear += [
        'env', 'current_minimization_phase_attempts', 'minimization_phase'
    ]

    # If this testcase was archived during minimization, update the state.
    testcase.archive_state &= ~data_types.ArchiveStatus.MINIMIZED

  if regression:
    task_list.append('regression')
    testcase.regression = ''
    metadata_keys_to_clear += ['last_regression_min', 'last_regression_max']

  if progression:
    task_list.append('progression')
    testcase.fixed = ''
    testcase.open = True
    testcase.last_tested_crash_stacktrace = None
    testcase.triaged = False
    testcase.set_metadata('progression_pending', True, update_testcase=False)
    metadata_keys_to_clear += [
        'last_progression_min', 'last_progression_max', 'last_tested_revision'
    ]

  if impact:
    task_list.append('impact')
    testcase.is_impact_set_flag = False

  if blame:
    task_list.append('blame')
    testcase.set_metadata('blame_pending', True, update_testcase=False)
    testcase.set_metadata('predator_result', None, update_testcase=False)

  for key in metadata_keys_to_clear:
    testcase.delete_metadata(key, update_testcase=False)

  testcase.comments += '[%s] %s: Redo task(s): %s\n' % (
      utils.current_date_time(), user_email, ', '.join(sorted(task_list)))
  testcase.one_time_crasher_flag = False
  testcase.put()

  # Log the task's queue for debug purposes.
  logs.info(
      f'{utils.current_date_time()} : Adding testcase id {testcase_id} '
      f'to queue {queue_for_testcase(testcase)} with job {testcase.job_type} '
      f'for tasks {sorted(task_list)}.')

  # Allow new notifications to be sent for this testcase.
  notifications = ndb_utils.get_all_from_query(
      data_types.Notification.query(
          data_types.Notification.testcase_id == testcase.key.id()),
      keys_only=True)
  ndb_utils.delete_multi(notifications)

  # Use wait_time=0 to execute the task ASAP, since it is user-facing.
  wait_time = 0

  # If we are re-doing minimization, other tasks will be done automatically
  # after minimization completes. So, don't add those tasks.
  if minimize:
    add_task(
        'minimize',
        testcase_id,
        testcase.job_type,
        queue_for_testcase(testcase),
        wait_time=wait_time)
    return

  if regression:
    add_task(
        'regression',
        testcase_id,
        testcase.job_type,
        queue_for_testcase(testcase),
        wait_time=wait_time)

  if progression:
    add_task(
        'progression',
        testcase_id,
        testcase.job_type,
        queue_for_testcase(testcase),
        wait_time=wait_time)

  if impact:
    add_task(
        'impact',
        testcase_id,
        testcase.job_type,
        queue_for_testcase(testcase),
        wait_time=wait_time)

  if blame:
    add_task(
        'blame',
        testcase_id,
        testcase.job_type,
        queue_for_testcase(testcase),
        wait_time=wait_time)


def get_task_payload():
  """Return current task payload."""
  return persistent_cache.get_value(TASK_PAYLOAD_KEY)


def get_task_end_time():
  """Return current task end time."""
  return persistent_cache.get_value(
      TASK_END_TIME_KEY, constructor=datetime.datetime.utcfromtimestamp)


def track_task_start(task, task_duration):
  """Cache task information."""
  persistent_cache.set_value(TASK_PAYLOAD_KEY, task.payload())
  persistent_cache.set_value(TASK_END_TIME_KEY, time.time() + task_duration)

  # Don't wait on |run_heartbeat|, update task information as soon as it starts.
  from clusterfuzz._internal.datastore import data_handler
  data_handler.update_heartbeat(force_update=True)


def track_task_end():
  """Remove cached task information."""
  persistent_cache.delete_value(TASK_PAYLOAD_KEY)
  persistent_cache.delete_value(TASK_END_TIME_KEY)

  # Don't wait on |run_heartbeat|, remove task information as soon as it ends.
  from clusterfuzz._internal.datastore import data_handler
  data_handler.update_heartbeat(force_update=True)
