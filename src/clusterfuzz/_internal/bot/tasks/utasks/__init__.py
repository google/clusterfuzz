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

from clusterfuzz._internal.bot.tasks.utasks import uworker_io
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment


def tworker_preprocess_no_io(utask_module, task_argument, job_type,
                             uworker_env):
  logs.log('Starting utask_preprocess: %s.' % utask_module)
  uworker_input = utask_module.utask_preprocess(task_argument, job_type,
                                                uworker_env)
  if not uworker_input:
    return None
  assert 'job_type' not in uworker_input
  uworker_input['job_type'] = job_type
  return uworker_io.serialize_uworker_input(uworker_input)


def uworker_main_no_io(utask_module, serialized_uworker_input):
  """Exectues the main part of a utask on the uworker (locally if not using
  remote executor)."""
  logs.log('Starting utask_main: %s.' % utask_module)
  uworker_input = uworker_io.deserialize_uworker_input(uworker_input)
  # Deal with the environment.
  uworker_env = uworker_input.pop('uworker_env')
  set_uworker_env(uworker_env)

  uworker_output = utask_module.utask_main(**uworker_input)
  uworker_output.uworker_env = uworker_env
  uworker_output.uworker_input = uworker_input
  return uworker_io.serialize_uworker_output(uworker_output)


def uworker_postprocess_no_io(utask_module, uworker_output):
  uworker_output_dict = uworker_io.deserialize_uworker_output(uworker_output)

  uworker_output = uworker_io.uworker_output_from_dict(uworker_output_dict)
  utask_module.utask_postprocess(uworker_output)


def tworker_preprocess(utask_module, task_argument, job_type, uworker_env):
  """Executes the preprocessing step of the utask |utask_module| and returns the
  signed download URL for the uworker's input and the (unsigned) download URL
  for its output."""
  logs.log('Starting utask_preprocess: %s.' % utask_module)
  # Do preprocessing.
  uworker_input = utask_module.utask_preprocess(task_argument, job_type,
                                                uworker_env)
  if not uworker_input:
    # Bail if preprocessing failed since we can't proceed.
    return None

  # Get URLs for the uworker's output. We need a signed upload URL so it can
  # write its output. Also get a download URL in case the caller wants to read
  # the output.
  uworker_output_upload_url, uworker_output_download_gcs_url = (
      uworker_io.get_uworker_output_urls())

  # Write the uworker's input to GCS and get the URL to download the input in
  # case the caller needs it.
  uworker_input_download_url = uworker_io.serialize_and_upload_uworker_input(
      uworker_input, job_type, uworker_output_upload_url)

  # Return the uworker_input_download_url for the remote executor to pass to the
  # batch job and for the local executor to download locally. Return
  # uworker_output_download_gcs_url for the local executor to download the
  # output after local execution of the utask_main.
  return uworker_input_download_url, uworker_output_download_gcs_url


def set_uworker_env(uworker_env: dict) -> None:
  """Sets all env vars in |uworker_env| in the actual environment."""
  for key, value in uworker_env.items():
    environment.set_value(key, value)


def uworker_main(utask_module, input_download_url) -> None:
  """Exectues the main part of a utask on the uworker (locally if not using
  remote executor)."""
  logs.log('Starting utask_main: %s.' % utask_module)
  uworker_input = uworker_io.download_and_deserialize_uworker_input(
      input_download_url)
  uworker_output_upload_url = uworker_input.pop('uworker_output_upload_url')

  # Deal with the environment.
  uworker_env = uworker_input.pop('uworker_env')
  set_uworker_env(uworker_env)

  uworker_output = utask_module.utask_main(**uworker_input)
  uworker_output.uworker_env = uworker_env
  uworker_output.uworker_input = uworker_input
  uworker_io.serialize_and_upload_uworker_output(uworker_output,
                                                 uworker_output_upload_url)


def tworker_postprocess(utask_module, output_download_url) -> None:
  """Executes the postprocess step on the trusted (t)worker."""
  logs.log('Starting utask_postprocess: %s.' % utask_module)
  uworker_output_dict = uworker_io.download_and_deserialize_uworker_output(
      output_download_url)
  uworker_output = uworker_io.uworker_output_from_dict(uworker_output_dict)
  utask_module.utask_postprocess(uworker_output)
