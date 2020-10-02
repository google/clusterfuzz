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
import random
import threading
import time

from base import persistent_cache
from base import utils
from datastore import data_types
from datastore import ndb_utils
from fuzzing import fuzzer_selection
from google_cloud_utils import pubsub
from metrics import logs
from system import environment

# Task queue prefixes for various job types.
JOBS_PREFIX = 'jobs'
HIGH_END_JOBS_PREFIX = 'high-end-jobs'

# Default task queue names for various job types. These will be different for
# different platforms with the platform name added as suffix later.
JOBS_TASKQUEUE = JOBS_PREFIX
HIGH_END_JOBS_TASKQUEUE = HIGH_END_JOBS_PREFIX

# ML job is currently supported on Linux only.
ML_JOBS_TASKQUEUE = 'ml-jobs-linux'

# Limits on number of tasks leased at once and in total.
MAX_LEASED_TASKS_LIMIT = 1000
MAX_TASKS_LIMIT = 100000

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
    'ANDROID_KERNEL': 'Android Kernel',
    'ANDROID_AUTO': 'Android Auto',
    'ANDROID_X86': 'Android (x86)',
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


class Error(Exception):
  """Base exception class."""


class InvalidRedoTask(Error):

  def __init__(self, task):
    super(InvalidRedoTask, self).__init__("The task '%s' is invalid." % task)


def queue_suffix_for_platform(platform):
  """Get the queue suffix for a platform."""
  return '-' + platform.lower().replace('_', '-')


def default_queue_suffix():
  """Get the queue suffix for the current platform."""
  queue_override = environment.get_value('QUEUE_OVERRIDE')
  if queue_override:
    return queue_suffix_for_platform(queue_override)

  return queue_suffix_for_platform(environment.platform())


def regular_queue(prefix=JOBS_PREFIX):
  """Get the regular jobs queue."""
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

  pubsub_client = pubsub.PubSubClient()
  application_id = utils.get_application_id()
  while True:
    messages = pubsub_client.pull_from_subscription(
        pubsub.subscription_name(application_id, queue), max_messages=1)

    if not messages:
      return None

    try:
      task = PubSubTask(messages[0])
    except KeyError:
      logs.log_error('Received an invalid task, discarding...')
      messages[0].ack()
      continue

    # Check that this task should be run now (past the ETA). Otherwise we defer
    # its execution.
    if not task.defer():
      return task


def get_task():
  """Get a task."""
  task = get_command_override()
  if task:
    return task

  # TODO(unassigned): Remove this hack.
  if environment.get_value('ML'):
    return get_regular_task(queue=ML_JOBS_TASKQUEUE)

  allow_all_tasks = not environment.get_value('PREEMPTIBLE')
  if allow_all_tasks:
    # Check the high-end jobs queue for bots with multiplier greater than 1.
    thread_multiplier = environment.get_value('THREAD_MULTIPLIER')
    if thread_multiplier and thread_multiplier > 1:
      task = get_high_end_task()
      if task:
        return task

    task = get_regular_task()
    if task:
      return task

  task = get_fuzz_task()
  if not task:
    logs.log_error('Failed to get any fuzzing tasks. This should not happen.')
    time.sleep(TASK_EXCEPTION_WAIT_INTERVAL)

  return task


class Task(object):
  """Represents a task."""

  def __init__(self,
               command,
               argument,
               job,
               eta=None,
               is_command_override=False,
               high_end=False):
    self.command = command
    self.argument = argument
    self.job = job
    self.eta = eta
    self.is_command_override = is_command_override
    self.high_end = high_end

  def attribute(self, _):
    return None

  def payload(self):
    """Get the payload."""
    return ' '.join([self.command, self.argument, self.job])

  def to_pubsub_message(self):
    """Convert the task to a pubsub message."""
    attributes = {
        'command': self.command,
        'argument': str(self.argument),
        'job': self.job,
    }

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


class PubSubTask(Task):
  """A Pub/Sub task."""

  def __init__(self, pubsub_message):
    self._pubsub_message = pubsub_message
    super(PubSubTask, self).__init__(
        self.attribute('command'), self.attribute('argument'),
        self.attribute('job'))

    self.eta = datetime.datetime.utcfromtimestamp(float(self.attribute('eta')))

  def attribute(self, key):
    """Return attribute value."""
    return self._pubsub_message.attributes[key]

  def defer(self):
    """Defer a task until its ETA. Returns whether or not we deferred."""
    now = utils.utcnow()
    if now >= self.eta:
      return False

    # Extend the deadline until the ETA, or MAX_ACK_DEADLINE.
    time_until_eta = int((self.eta - now).total_seconds())
    logs.log('Deferring task "%s".' % self.payload())
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


class _PubSubLeaserThread(threading.Thread):
  """Thread that continuously renews the lease for a message."""

  EXTENSION_TIME_SECONDS = 10 * 60  # 10 minutes.

  def __init__(self, message, done_event, max_lease_seconds):
    super(_PubSubLeaserThread, self).__init__()

    self.daemon = True
    self._message = message
    self._done_event = done_event
    self._max_lease_seconds = max_lease_seconds

  def run(self):
    """Run the leaser thread."""
    latest_end_time = time.time() + self._max_lease_seconds

    while True:
      try:
        time_left = latest_end_time - time.time()
        if time_left <= 0:
          logs.log('Lease reached maximum lease time of {} seconds, '
                   'stopping renewal.'.format(self._max_lease_seconds))
          break

        extension_seconds = min(self.EXTENSION_TIME_SECONDS, time_left)

        logs.log(
            'Renewing lease for task by {} seconds.'.format(extension_seconds))
        self._message.modify_ack_deadline(extension_seconds)

        # Schedule renewals earlier than the extension to avoid race conditions
        # and performing the next extension too late.
        wait_seconds = min(time_left, self.EXTENSION_TIME_SECONDS // 2)

        # Wait until the next scheduled renewal, or if the task is complete.
        if self._done_event.wait(wait_seconds):
          logs.log('Task complete, stopping renewal.')
          break
      except Exception:
        logs.log_error('Leaser thread failed.')


def add_task(command, argument, job_type, queue=None, wait_time=None):
  """Add a new task to the job queue."""
  # Old testcases may pass in queue=None explicitly,
  # so we must check this here.
  if not queue:
    queue = default_queue()

  if wait_time is None:
    wait_time = random.randint(1, TASK_CREATION_WAIT_INTERVAL)

  # Add the task.
  eta = utils.utcnow() + datetime.timedelta(seconds=wait_time)
  task = Task(command, argument, job_type, eta=eta)
  pubsub_client = pubsub.PubSubClient()
  pubsub_client.publish(
      pubsub.topic_name(utils.get_application_id(), queue),
      [task.to_pubsub_message()])


def get_task_lease_timeout():
  """Return the task lease timeout."""
  return environment.get_value('TASK_LEASE_SECONDS', TASK_LEASE_SECONDS)


def get_task_completion_deadline():
  """Return task completion deadline. This gives an additional buffer over the
  task lease deadline."""
  start_time = time.time()
  task_lease_timeout = get_task_lease_timeout()
  return start_time + task_lease_timeout - TASK_COMPLETION_BUFFER


def queue_for_platform(platform, is_high_end=False):
  """Return the queue for the platform."""
  prefix = HIGH_END_JOBS_PREFIX if is_high_end else JOBS_PREFIX
  return prefix + queue_suffix_for_platform(platform)


def queue_for_testcase(testcase):
  """Return the right queue for the testcase."""
  is_high_end = testcase.queue.startswith(HIGH_END_JOBS_PREFIX)
  return queue_for_job(testcase.job_type, is_high_end=is_high_end)


def queue_for_job(job_name, is_high_end=False):
  """Queue for job."""
  job = data_types.Job.query(data_types.Job.name == job_name).get()
  if not job:
    raise Error('Job {} not found.'.format(job_name))

  return queue_for_platform(job.platform, is_high_end)


def redo_testcase(testcase, tasks, user_email):
  """Redo specific tasks for a testcase."""
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

  # Allow new notifications to be sent for this testcase.
  notifications = ndb_utils.get_all_from_query(
      data_types.Notification.query(
          data_types.Notification.testcase_id == testcase.key.id()),
      keys_only=True)
  ndb_utils.delete_multi(notifications)

  # If we are re-doing minimization, other tasks will be done automatically
  # after minimization completes. So, don't add those tasks.
  if minimize:
    add_task('minimize', testcase_id, testcase.job_type,
             queue_for_testcase(testcase))
  else:
    if regression:
      add_task('regression', testcase_id, testcase.job_type,
               queue_for_testcase(testcase))

    if progression:
      add_task('progression', testcase_id, testcase.job_type,
               queue_for_testcase(testcase))

    if impact:
      add_task('impact', testcase_id, testcase.job_type,
               queue_for_testcase(testcase))

    if blame:
      add_task('blame', testcase_id, testcase.job_type,
               queue_for_testcase(testcase))


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
  from datastore import data_handler
  data_handler.update_heartbeat(force_update=True)


def track_task_end():
  """Remove cached task information."""
  persistent_cache.delete_value(TASK_PAYLOAD_KEY)
  persistent_cache.delete_value(TASK_END_TIME_KEY)

  # Don't wait on |run_heartbeat|, remove task information as soon as it ends.
  from datastore import data_handler
  data_handler.update_heartbeat(force_update=True)
