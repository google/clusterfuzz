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
"""Environment modification functions."""

import os
import re

import six

try:
  from clusterfuzz._internal.protos import untrusted_runner_pb2

  from . import file_host
  from . import host
except ImportError:
  # TODO(ochang): Fix this.
  pass

FORWARDED_ENVIRONMENT_VARIABLES = [
    re.compile(pattern) for pattern in (
        r'^AFL_.*',
        r'^APPLICATION_ID$',
        r'^ASAN_OPTIONS$',
        r'^BACKUP_BUCKET$',
        r'^CORPUS_BUCKET$',
        r'^MUTATOR_PLUGINS_BUCKET$',
        r'^FUZZ_CORPUS_DIR$',
        r'^FUZZER_DIR$',
        r'^FUZZER_NAME_REGEX$',
        r'^FUZZING_STRATEGIES$',
        r'^FUZZ_TARGET$',
        r'^FUZZ_TEST_TIMEOUT$',
        r'^GSUTIL_PATH$',
        r'^JOB_NAME$',
        r'^LOCAL_DEVELOPMENT$',
        r'^MSAN_OPTIONS$',
        r'^PATH$',
        r'^PY_UNITTESTS$',
        r'^QUARANTINE_BUCKET$',
        r'^SHARED_CORPUS_BUCKET$',
        r'^STRATEGY_SELECTION_DISTRIBUTION$',
        r'^STRATEGY_SELECTION_METHOD$',
        r'^TASK_NAME$',
        r'^TASK_PAYLOAD$',
        r'^TEST_TIMEOUT$',
        r'^TSAN_OPTIONS$',
        r'^UBSAN_OPTIONS$',
        r'^UNPACK_ALL_FUZZ_TARGETS_AND_FILES$',
        r'^USE_MINIJAIL$',
        r'^USER$',
    )
]

REBASED_ENVIRONMENT_VARIABLES = set([
    'FUZZER_DIR',
])


def is_forwarded_environment_variable(environment_variable):
  """Return whether or not |environment_variable| should be forwarded."""
  return any(
      pattern.match(environment_variable)
      for pattern in FORWARDED_ENVIRONMENT_VARIABLES)


def should_rebase_environment_value(environment_variable):
  """Return whether or not |environment_variable|'s value should be rebased."""
  return environment_variable in REBASED_ENVIRONMENT_VARIABLES


def update_environment(env):
  """Update worker's environment."""
  processed_env = {}
  for key, value in six.iteritems(env):
    if should_rebase_environment_value(key):
      value = file_host.rebase_to_worker_root(value)

    processed_env[key] = value

  request = untrusted_runner_pb2.UpdateEnvironmentRequest(env=processed_env)
  host.stub().UpdateEnvironment(request)


def set_environment_vars(env, source_env):
  """Copy allowed environment variables from |source_env|."""
  if not source_env:
    return

  for name, value in six.iteritems(source_env):
    if is_forwarded_environment_variable(name):
      # Avoid creating circular dependencies from importing environment by
      # using os.getenv.
      if os.getenv('TRUSTED_HOST') and should_rebase_environment_value(name):
        value = file_host.rebase_to_worker_root(value)

      env[name] = value


def get_env_for_untrusted_process(overrides):
  """Return environment for running an untrusted process."""
  env = {}
  if overrides is not None:
    set_environment_vars(env, overrides)
  else:
    set_environment_vars(env, os.environ)
  return env


def forward_environment_variable(key, value):
  """Forward the environment variable if needed."""
  if not host.is_initialized():
    return

  if is_forwarded_environment_variable(key):
    update_environment({key: value})


def reset_environment():
  """Reset environment variables."""
  request = untrusted_runner_pb2.ResetEnvironmentRequest()
  host.stub().ResetEnvironment(request)
