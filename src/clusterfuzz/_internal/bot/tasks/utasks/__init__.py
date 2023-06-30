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

import importlib

from clusterfuzz._internal.bot.tasks.utasks import uworker_io
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment


def tworker_preprocess_no_io(utask_module, task_argument, job_type,
                             uworker_env):
  logs.log('Starting utask_preprocess: %s.' % utask_module)
  uworker_input = utask_module.utask_preprocess(task_argument, job_type,
                                                uworker_env)
  assert not uworker_input.module_name
  uworker_input.module_name = utask_module.__name__
  if not uworker_input:
    return None
  return uworker_io.serialize_uworker_input(uworker_input)


def uworker_main_no_io(utask_module, serialized_uworker_input):
  """Exectues the main part of a utask on the uworker (locally if not using
  remote executor)."""
  logs.log('Starting utask_main: %s.' % utask_module)
  uworker_input = uworker_io.deserialize_uworker_input(serialized_uworker_input)

  # Deal with the environment.
  set_uworker_env(uworker_input.uworker_env)
  delattr(uworker_input, 'uworker_env')

  uworker_output = utask_module.utask_main(uworker_input)
  if uworker_output is None:
    return None
  return uworker_io.serialize_uworker_output(uworker_output)


def add_uworker_input_to_output(uworker_output, uworker_input):
  uworker_env = uworker_input.uworker_env
  delattr(uworker_input, 'uworker_env')
  uworker_output.uworker_env = uworker_env
  uworker_output.uworker_input = uworker_input


def tworker_postprocess_no_io(utask_module, uworker_output, uworker_input):
  uworker_output = uworker_io.deserialize_uworker_output(uworker_output)
  # Do this to simulate out-of-band tamper-proof storage of the input.
  uworker_input = uworker_io.deserialize_uworker_input(uworker_input)
  add_uworker_input_to_output(uworker_output, uworker_input)
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

  # Write the uworker's input to GCS and get the URL to download the input in
  # case the caller needs it.
  uworker_input_signed_download_url, uworker_output_download_gcs_url = (
      uworker_io.serialize_and_upload_uworker_input(uworker_input))

  # Return the uworker_input_signed_download_url for the remote executor to pass
  # to the batch job and for the local executor to download locally. Return
  # uworker_output_download_gcs_url for the local executor to download the
  # output after local execution of the utask_main.
  return uworker_input_signed_download_url, uworker_output_download_gcs_url


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
  uworker_output_upload_url = uworker_input.uworker_output_upload_url  # pylint: disable=no-member
  delattr(uworker_input, 'uworker_output_upload_url')

  # Deal with the environment.
  uworker_env = uworker_input.uworker_env  # pylint: disable=no-member
  delattr(uworker_input, 'uworker_env')
  set_uworker_env(uworker_env)

  uworker_output = utask_module.utask_main(uworker_input)
  uworker_io.serialize_and_upload_uworker_output(uworker_output,
                                                 uworker_output_upload_url)
  return True


def get_utask_module(module_name):
  full_module_name = f'clusterfuzz._internal.bot.tasks.utasks.{module_name}'
  return importlib.import_module(full_module_name)


def uworker_bot_main():
  module_name = environment.get_value('UWORKER_MODULE_NAME')
  get_utask_module(module_name)
  input_download_url = environment.get_value('UWORKER_INPUT_DOWNLOAD_URL')
  uworker_main(module, input_download_url)
  return True


def uworker_bot_main():
  module_name = environment.get_value('UWORKER_MODULE_NAME')
  full_module_name = f'clusterfuzz._internal.bot.tasks.utasks.{module_name}'
  module = importlib.import_module(full_module_name)
  input_download_url = environment.get_value('UWORKER_INPUT_DOWNLOAD_URL')
  uworker_main(module, input_download_url)
  return True


def tworker_postprocess(output_download_url) -> None:
  """Executes the postprocess step on the trusted (t)worker."""
  uworker_output = uworker_io.download_and_deserialize_uworker_output(
      output_download_url)
  utask_module = get_utask_module(uworker_output.uworker_input.module_name)
  utask_module.utask_postprocess(uworker_output)
