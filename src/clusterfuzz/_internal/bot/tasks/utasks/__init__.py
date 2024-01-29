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

import enum
import importlib
import time

from google.protobuf import timestamp_pb2

from clusterfuzz._internal.base import task_utils
from clusterfuzz._internal.bot.tasks.utasks import uworker_io
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.metrics import monitoring_metrics
from clusterfuzz._internal.system import environment

# Define an alias to appease pylint.
Timestamp = timestamp_pb2.Timestamp  # pylint: disable=no-member


class _Mode(enum.Enum):
  """The execution mode of `uworker_main` tasks in a bot process."""

  # `uworker_main` tasks are executed on Cloud Batch.
  BATCH = "batch"

  # `uworker_main` tasks are executed on bots via a Pub/Sub queue.
  QUEUE = "queue"


class _Subtask(enum.Enum):
  """Parts of a task that may be executed on separate machines."""

  PREPROCESS = "preprocess"
  UWORKER_MAIN = "uworker_main"
  POSTPROCESS = "postprocess"


def _timestamp_now() -> Timestamp:
  ts = Timestamp()
  ts.GetCurrentTime()
  return ts


def _record_e2e_duration(start: Timestamp, utask_module, job_type: str,
                         subtask: _Subtask, mode: _Mode):
  duration = start.ToSeconds() - time.time()
  monitoring_metrics.UTASK_E2E_DURATION_SECS.add(
      duration, {
          'task': task_utils.get_command_from_module(utask_module.__name__),
          'job': job_type,
          'subtask': subtask.value,
          'mode': mode.value,
          'platform': environment.platform(),
      })


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


def tworker_preprocess_no_io(utask_module, task_argument, job_type,
                             uworker_env):
  """Executes the preprocessing step of the utask |utask_module| and returns the
  serialized output."""
  start = _timestamp_now()
  logs.log('Starting utask_preprocess: %s.' % utask_module)
  ensure_uworker_env_type_safety(uworker_env)
  set_uworker_env(uworker_env)
  uworker_input = utask_module.utask_preprocess(task_argument, job_type,
                                                uworker_env)
  if not uworker_input:
    logs.log_error('No uworker_input returned from preprocess')
    return None

  uworker_input.preprocess_start_time.CopyFrom(start)

  assert not uworker_input.module_name
  uworker_input.module_name = utask_module.__name__

  result = uworker_io.serialize_uworker_input(uworker_input)
  _record_e2e_duration(start, utask_module, job_type, _Subtask.PREPROCESS,
                       _Mode.QUEUE)
  return result


def uworker_main_no_io(utask_module, serialized_uworker_input):
  """Exectues the main part of a utask on the uworker (locally if not using
  remote executor)."""
  start = _timestamp_now()
  logs.log('Starting utask_main: %s.' % utask_module)
  uworker_input = uworker_io.deserialize_uworker_input(serialized_uworker_input)

  # Deal with the environment.
  set_uworker_env(uworker_input.uworker_env)
  uworker_input.uworker_env.clear()
  uworker_output = utask_module.utask_main(uworker_input)
  if uworker_output is None:
    return None
  result = uworker_io.serialize_uworker_output(uworker_output)
  _record_e2e_duration(start, utask_module, uworker_input.job_type,
                       _Subtask.UWORKER_MAIN, _Mode.QUEUE)
  return result


def tworker_postprocess_no_io(utask_module, uworker_output, uworker_input):
  """Executes the postprocess step on the trusted (t)worker (in this case it is
  the same bot as the uworker)."""
  # TODO(metzman): Stop passing module to this function and uworker_main_no_io.
  # Make them consistent with the I/O versions.
  start = _timestamp_now()
  uworker_output = uworker_io.deserialize_uworker_output(uworker_output)
  # Do this to simulate out-of-band tamper-proof storage of the input.
  uworker_input = uworker_io.deserialize_uworker_input(uworker_input)
  uworker_output.uworker_input.CopyFrom(uworker_input)
  set_uworker_env(uworker_output.uworker_input.uworker_env)
  utask_module.utask_postprocess(uworker_output)
  _record_e2e_duration(start, utask_module, uworker_input.job_type,
                       _Subtask.POSTPROCESS, _Mode.QUEUE)


def tworker_preprocess(utask_module, task_argument, job_type, uworker_env):
  """Executes the preprocessing step of the utask |utask_module| and returns the
  signed download URL for the uworker's input and the (unsigned) download URL
  for its output."""
  start = _timestamp_now()
  logs.log('Starting utask_preprocess: %s.' % utask_module)
  ensure_uworker_env_type_safety(uworker_env)
  set_uworker_env(uworker_env)
  # Do preprocessing.
  uworker_input = utask_module.utask_preprocess(task_argument, job_type,
                                                uworker_env)
  if not uworker_input:
    # Bail if preprocessing failed since we can't proceed.
    return None

  uworker_input.preprocess_start_time.CopyFrom(start)

  assert not uworker_input.module_name
  uworker_input.module_name = utask_module.__name__

  # Write the uworker's input to GCS and get the URL to download the input in
  # case the caller needs it.
  uworker_input_signed_download_url, uworker_output_download_gcs_url = (
      uworker_io.serialize_and_upload_uworker_input(uworker_input))

  _record_e2e_duration(start, utask_module, job_type, _Subtask.PREPROCESS,
                       _Mode.BATCH)

  # Return the uworker_input_signed_download_url for the remote executor to pass
  # to the batch job and for the local executor to download locally. Return
  # uworker_output_download_gcs_url for the local executor to download the
  # output after local execution of the utask_main.
  return uworker_input_signed_download_url, uworker_output_download_gcs_url


def set_uworker_env(uworker_env: dict) -> None:
  """Sets all env vars in |uworker_env| in the actual environment."""
  for key, value in uworker_env.items():
    environment.set_value(key, value)


def uworker_main(input_download_url) -> None:
  """Exectues the main part of a utask on the uworker (locally if not using
  remote executor)."""
  start = _timestamp_now()
  uworker_input = uworker_io.download_and_deserialize_uworker_input(
      input_download_url)
  uworker_output_upload_url = uworker_input.uworker_output_upload_url
  uworker_input.ClearField('uworker_output_upload_url')

  # Deal with the environment.
  set_uworker_env(uworker_input.uworker_env)
  uworker_input.uworker_env.clear()

  utask_module = get_utask_module(uworker_input.module_name)
  logs.log('Starting utask_main: %s.' % utask_module)
  uworker_output = utask_module.utask_main(uworker_input)
  uworker_io.serialize_and_upload_uworker_output(uworker_output,
                                                 uworker_output_upload_url)
  logs.log('Finished uworker_main.')
  _record_e2e_duration(start, utask_module, uworker_input.job_type,
                       _Subtask.UWORKER_MAIN, _Mode.BATCH)
  return True


def get_utask_module(module_name):
  return importlib.import_module(module_name)


def uworker_bot_main():
  """The entrypoint for a uworker."""
  logs.log('Starting utask_main on untrusted worker.')
  input_download_url = environment.get_value('UWORKER_INPUT_DOWNLOAD_URL')
  uworker_main(input_download_url)
  return 0


def tworker_postprocess(output_download_url) -> None:
  """Executes the postprocess step on the trusted (t)worker."""
  start = _timestamp_now()
  uworker_output = uworker_io.download_and_deserialize_uworker_output(
      output_download_url)
  set_uworker_env(uworker_output.uworker_input.uworker_env)
  utask_module = get_utask_module(uworker_output.uworker_input.module_name)
  utask_module.utask_postprocess(uworker_output)
  job_type = uworker_output.uworker_input.job_type
  _record_e2e_duration(start, utask_module, job_type, _Subtask.POSTPROCESS,
                       _Mode.BATCH)
