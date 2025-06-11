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
"""Module for executing the different parts of a utask."""

import contextlib
import enum
import importlib
import time
from typing import Optional

from google.protobuf import timestamp_pb2

from clusterfuzz._internal import swarming
from clusterfuzz._internal.base.tasks import task_utils
from clusterfuzz._internal.bot.tasks.utasks import uworker_io
from clusterfuzz._internal.bot.webserver import http_server
from clusterfuzz._internal.google_cloud_utils import storage
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.metrics import monitoring_metrics
from clusterfuzz._internal.protos import uworker_msg_pb2
from clusterfuzz._internal.system import environment

# Define an alias to appease pylint.
Timestamp = timestamp_pb2.Timestamp  # pylint: disable=no-member


class Mode(enum.Enum):
  """The execution mode of `uworker_main` tasks in a bot process."""

  # `uworker_main` tasks are executed on Cloud Batch.
  BATCH = 'batch'

  # `uworker_main` tasks are executed on bots via a Pub/Sub queue.
  QUEUE = 'queue'

  # `uworker_main` tasks are executed on swarming.
  SWARMING = 'swarming'


class _Subtask(enum.Enum):
  """Parts of a task that may be executed on separate machines."""

  PREPROCESS = 'preprocess'
  UWORKER_MAIN = 'uworker_main'
  POSTPROCESS = 'postprocess'


def _timestamp_now() -> Timestamp:
  ts = Timestamp()
  ts.GetCurrentTime()
  return ts


def _get_execution_mode(utask_module, job_type):
  """Determines whether this task in executed on swarming or batch."""
  command = task_utils.get_command_from_module(utask_module.__name__)
  if swarming.is_swarming_task(command, job_type):
    return Mode.SWARMING
  return Mode.BATCH


class _MetricRecorder(contextlib.AbstractContextManager):
  """Records task execution metrics, even in case of error and exceptions.

  Members:
    start_time_ns (int): The time at which this recorder was constructed, in
      nanoseconds since the Unix epoch.
    utask_main_failure: this class stores the uworker_output.ErrorType 
      object returned by utask_main, and uses it to emmit a metric.
  """

  def __init__(self, subtask: _Subtask):
    self.start_time_ns = time.time_ns()
    self._subtask = subtask
    self._labels = None
    self.utask_main_failure = None
    self._utask_success_conditions = [
        None,  # This can be a successful return value in, ie, fuzz task
        uworker_msg_pb2.ErrorType.NO_ERROR,  # pylint: disable=no-member
        uworker_msg_pb2.ErrorType.ANALYZE_NO_CRASH,  # pylint: disable=no-member
        uworker_msg_pb2.ErrorType.PROGRESSION_BAD_STATE_MIN_MAX,  # pylint: disable=no-member
        uworker_msg_pb2.ErrorType.REGRESSION_NO_CRASH,  # pylint: disable=no-member
        uworker_msg_pb2.ErrorType.REGRESSION_LOW_CONFIDENCE_IN_REGRESSION_RANGE,  # pylint: disable=no-member
        uworker_msg_pb2.ErrorType.MINIMIZE_CRASH_TOO_FLAKY,  # pylint: disable=no-member
        uworker_msg_pb2.ErrorType.LIBFUZZER_MINIMIZATION_UNREPRODUCIBLE,  # pylint: disable=no-member
        uworker_msg_pb2.ErrorType.ANALYZE_CLOSE_INVALID_UPLOADED,  # pylint: disable=no-member
    ]

    if subtask == _Subtask.PREPROCESS:
      self._preprocess_start_time_ns = self.start_time_ns
    else:
      self._preprocess_start_time_ns = None

  def set_task_details(self,
                       utask_module,
                       job_type: str,
                       execution_mode: Mode,
                       platform: str,
                       preprocess_start_time: Optional[Timestamp] = None):
    """Sets task details that might not be known at instantation time.

    Must be called once for metrics to be recorded when exiting the context.

    Args:
      utask_module: The Python module corresponding to the task being executed.
      job_type: The name of the job against which the task is being executed.
      platform: The platform we are executing on, as given by
        `environment.platform()`.
      preprocess_start_time: Timestamp at which the preprocess subtask for
        this task started executing, possibly in a different process. Must be
        specified iff the subtask is not `Subtask.PREPROCESS`.
    """
    self._labels = {
        'task': task_utils.get_command_from_module(utask_module.__name__),
        'job': job_type,
        'subtask': self._subtask.value,
        'mode': execution_mode.value,
        'platform': platform,
    }

    if preprocess_start_time is not None:
      # We already know the start time if the subtask is preprocess.
      assert self._preprocess_start_time_ns is None
      self._preprocess_start_time_ns = preprocess_start_time.ToNanoseconds()
    else:
      # Ensure we always have a value after this method returns.
      assert self._preprocess_start_time_ns is not None

  def _infer_uworker_main_outcome(self, exc_type, uworker_error) -> bool:
    """Returns True if task succeeded, False otherwise."""
    if exc_type or uworker_error not in self._utask_success_conditions:
      return False
    return True

  def __exit__(self, _exc_type, _exc_value, _traceback):
    # Ignore exception details, let Python continue unwinding the stack.

    if self._labels is None:
      # `set_task_details()` was not called, we are missing information.
      return

    now = time.time_ns()

    duration_secs = (now - self.start_time_ns) / 10**9
    monitoring_metrics.UTASK_SUBTASK_DURATION_SECS.add(duration_secs,
                                                       self._labels)

    e2e_duration_secs = (now - self._preprocess_start_time_ns) / 10**9
    monitoring_metrics.UTASK_SUBTASK_E2E_DURATION_SECS.add(
        e2e_duration_secs, self._labels)

    # The only case where a task might fail without throwing, is in
    # utask_main, by returning an ErrorType proto which indicates
    # failure.
    task_succeeded = self._infer_uworker_main_outcome(_exc_type,
                                                      self.utask_main_failure)
    monitoring_metrics.TASK_OUTCOME_COUNT.increment({
        **self._labels, 'task_succeeded': task_succeeded
    })
    if task_succeeded:
      error_condition = 'N/A'
    elif _exc_type:
      error_condition = 'UNHANDLED_EXCEPTION'
    else:
      error_condition = uworker_msg_pb2.ErrorType.Name(  # pylint: disable=no-member
          self.utask_main_failure)
    # Get rid of job as a label, so we can have another metric to make
    # error conditions more explicit, respecting the 30k distinct
    # labels limit recommended by gcp.
    trimmed_labels = {
        **self._labels, 'task_succeeded': task_succeeded,
        'error_condition': error_condition
    }
    del trimmed_labels['job']
    monitoring_metrics.TASK_OUTCOME_COUNT_BY_ERROR_TYPE.increment(
        trimmed_labels)


def ensure_uworker_env_type_safety(uworker_env):
  """Converts all values in |uworker_env| to str types.
  ClusterFuzz parses env var values so that the type implied by the value
  (which in every OS I've seen is a string), is the Python type of the value.
  E.g. if "DO_BLAH=1" in the environment, environment.get_value('DO_BLAH') is 1,
  not '1'. This is dangerous when using protos because the environment is a
  proto map, and values in these can only have one type, which in this case is
  string. Therefore we must make sure values in uworker_envs are always strings
  so we don't try to save an int to a string map."""
  for k in uworker_env:
    uworker_env[k] = str(uworker_env[k])


def _preprocess(utask_module, task_argument, job_type, uworker_env,
                recorder: _MetricRecorder, execution_mode: Mode):
  """Shared logic for preprocessing between preprocess_no_io and the I/O
  tworker_preprocess."""
  ensure_uworker_env_type_safety(uworker_env)
  set_uworker_env(uworker_env)

  recorder.set_task_details(utask_module, job_type, execution_mode,
                            environment.platform())

  logs.info('Starting utask_preprocess: %s.' % utask_module)
  uworker_input = utask_module.utask_preprocess(task_argument, job_type,
                                                uworker_env)
  if not uworker_input:
    logs.error('No uworker_input returned from preprocess')
    return None

  logs.info('Preprocess finished.')

  task_payload = environment.get_value('TASK_PAYLOAD')
  if task_payload:
    uworker_input.uworker_env['INITIAL_TASK_PAYLOAD'] = task_payload

  uworker_input.preprocess_start_time.FromNanoseconds(recorder.start_time_ns)

  assert not uworker_input.module_name
  uworker_input.module_name = utask_module.__name__
  return uworker_input


def _start_web_server_if_needed(job_type):
  """Start web server for blackbox fuzzer jobs (non-engine fuzzer jobs)."""
  if environment.is_engine_fuzzer_job(job_type):
    return

  try:
    http_server.start()
  except Exception:
    logs.error('Failed to start web server, skipping.')


@logs.task_stage_context(logs.Stage.PREPROCESS)
def tworker_preprocess_no_io(utask_module, task_argument, job_type,
                             uworker_env):
  """Executes the preprocessing step of the utask |utask_module| and returns the
  serialized output."""
  with _MetricRecorder(_Subtask.PREPROCESS) as recorder:
    uworker_input = _preprocess(utask_module, task_argument, job_type,
                                uworker_env, recorder, Mode.QUEUE)
    if not uworker_input:
      return None

    return uworker_io.serialize_uworker_input(uworker_input)


@logs.task_stage_context(logs.Stage.MAIN)
def uworker_main_no_io(utask_module, serialized_uworker_input):
  """Executes the main part of a utask on the uworker (locally if not using
  remote executor)."""
  with _MetricRecorder(_Subtask.UWORKER_MAIN) as recorder:
    logs.info('Starting utask_main: %s.' % utask_module)
    uworker_input = uworker_io.deserialize_uworker_input(
        serialized_uworker_input)

    set_uworker_env(uworker_input.uworker_env)
    uworker_input.uworker_env.clear()

    recorder.set_task_details(utask_module, uworker_input.job_type, Mode.QUEUE,
                              environment.platform(),
                              uworker_input.preprocess_start_time)

    uworker_output = utask_module.utask_main(uworker_input)
    if uworker_output is None:
      return None

    # NOTE: Keep this in sync with `uworker_main()`.
    if uworker_output.error_type != uworker_msg_pb2.ErrorType.NO_ERROR:  # pylint: disable=no-member
      recorder.utask_main_failure = uworker_output.error_type
    uworker_output.bot_name = environment.get_value('BOT_NAME', '')
    uworker_output.platform_id = environment.get_platform_id()

    return uworker_io.serialize_uworker_output(uworker_output)


# TODO(metzman): Stop passing module to this function and `uworker_main_no_io`.
# Make them consistent with the I/O versions.
@logs.task_stage_context(logs.Stage.POSTPROCESS)
def tworker_postprocess_no_io(utask_module, uworker_output, uworker_input):
  """Executes the postprocess step on the trusted (t)worker (in this case it is
  the same bot as the uworker)."""
  logs.info('Starting postprocess on trusted worker.')
  with _MetricRecorder(_Subtask.POSTPROCESS) as recorder:
    uworker_output = uworker_io.deserialize_uworker_output(uworker_output)

    # Do this to simulate out-of-band tamper-proof storage of the input.
    uworker_input = uworker_io.deserialize_uworker_input(uworker_input)
    uworker_output.uworker_input.CopyFrom(uworker_input)

    set_uworker_env(uworker_output.uworker_input.uworker_env)

    recorder.set_task_details(utask_module, uworker_input.job_type, Mode.QUEUE,
                              environment.platform(),
                              uworker_input.preprocess_start_time)

    utask_module.utask_postprocess(uworker_output)


@logs.task_stage_context(logs.Stage.PREPROCESS)
def tworker_preprocess(utask_module, task_argument, job_type, uworker_env):
  """Executes the preprocessing step of the utask |utask_module| and returns the
  signed download URL for the uworker's input and the (unsigned) download URL
  for its output."""
  with _MetricRecorder(_Subtask.PREPROCESS) as recorder:
    execution_mode = _get_execution_mode(utask_module, job_type)
    uworker_input = _preprocess(utask_module, task_argument, job_type,
                                uworker_env, recorder, execution_mode)
    if not uworker_input:
      # Bail if preprocessing failed since we can't proceed.
      return None

    # Write the uworker's input to GCS and get the URL to download the input in
    # case the caller needs it.
    # Return both the uworker input signed download URL for the remote executor
    # to pass to the batch job and for the local executor to download locally,
    # and the uworker output download URL for the local executor to download
    # the output after local execution of `utask_main`.
    return uworker_io.serialize_and_upload_uworker_input(uworker_input)


def set_uworker_env(uworker_env: dict) -> None:
  """Sets all env vars in |uworker_env| in the actual environment."""
  for key, value in uworker_env.items():
    environment.set_value(key, value)


@logs.task_stage_context(logs.Stage.MAIN)
def uworker_main(input_download_url) -> None:
  """Executes the main part of a utask on the uworker (locally if not using
  remote executor)."""
  with _MetricRecorder(_Subtask.UWORKER_MAIN) as recorder:
    try:
      uworker_input = uworker_io.download_and_deserialize_uworker_input(
          input_download_url)
    except storage.ExpiredSignedUrlError as e:
      raise storage.ExpiredSignedUrlError(
          'Expired token, failed to download uworker_input: '
          f'{e.url}. {e.response_text}', e.url, e.response_text)
    uworker_output_upload_url = uworker_input.uworker_output_upload_url
    uworker_input.ClearField('uworker_output_upload_url')

    set_uworker_env(uworker_input.uworker_env)
    uworker_input.uworker_env.clear()

    logs.info('Starting HTTP server.')
    _start_web_server_if_needed(uworker_input.job_type)

    utask_module = get_utask_module(uworker_input.module_name)
    execution_mode = Mode.SWARMING if environment.is_swarming_bot(
    ) else Mode.BATCH
    recorder.set_task_details(
        utask_module, uworker_input.job_type, execution_mode,
        environment.platform(), uworker_input.preprocess_start_time)

    logs.info('Starting utask_main: %s.' % utask_module)
    uworker_output = utask_module.utask_main(uworker_input)

    if uworker_output.error_type != uworker_msg_pb2.ErrorType.NO_ERROR:  # pylint: disable=no-member
      recorder.utask_main_failure = uworker_output.error_type

    # NOTE: Keep this in sync with `uworker_main_no_io()`.
    uworker_output.bot_name = environment.get_value('BOT_NAME', '')
    uworker_output.platform_id = environment.get_platform_id()

    uworker_io.serialize_and_upload_uworker_output(uworker_output,
                                                   uworker_output_upload_url)
    logs.info('Finished uworker_main.')
    return True


def get_utask_module(module_name):
  return importlib.import_module(module_name)


def uworker_bot_main():
  """The entrypoint for a uworker."""
  logs.info('Starting utask_main on untrusted worker.')
  input_download_url = environment.get_value('UWORKER_INPUT_DOWNLOAD_URL')
  uworker_main(input_download_url)
  return 0


@logs.task_stage_context(logs.Stage.POSTPROCESS)
def tworker_postprocess(output_download_url) -> None:
  """Executes the postprocess step on the trusted (t)worker."""
  logs.info('Starting postprocess untrusted worker.')
  with _MetricRecorder(_Subtask.POSTPROCESS) as recorder:
    uworker_output = uworker_io.download_and_deserialize_uworker_output(
        output_download_url)

    set_uworker_env(uworker_output.uworker_input.uworker_env)

    utask_module = get_utask_module(uworker_output.uworker_input.module_name)
    execution_mode = _get_execution_mode(utask_module,
                                         uworker_output.uworker_input.job_type)
    recorder.set_task_details(
        utask_module, uworker_output.uworker_input.job_type, execution_mode,
        environment.platform(),
        uworker_output.uworker_input.preprocess_start_time)

    utask_module.utask_postprocess(uworker_output)
