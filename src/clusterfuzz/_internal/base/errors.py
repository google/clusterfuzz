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
"""Functions for errors management."""

from typing import Any
from typing import Sequence

# Phrases to look in an error stacktrace to determine if something bad happened
# which is non recoverable and we just want to hang in that situation without
# proceeding further. This also helps to later come up and debug the problem.
BOT_ERROR_HANG_LIST: list[str] = ['no space left']

# Phrases to look in an error stacktrace to determine whether the bot should
# terminate or not.
BOT_ERROR_TERMINATION_LIST: list[str] = [
    'can\'t start new thread',
    'cannot allocate memory',
    'hostexception',
    'interrupted function call',
    'out of memory',
    'systemexit:',
    'Expired token, failed to download uworker_input',
]


def error_in_list(error_stacktrace: str, error_list: Sequence[str]) -> bool:
  """Returns if the error exists in the error list."""
  # Change all strings to lowercase for comparison.
  error_stacktrace = error_stacktrace.lower()
  lowered_error_list = [error.lower() for error in error_list]

  for error in lowered_error_list:
    if error in error_stacktrace:
      return True

  return False


class Error(Exception):
  """Base exception class for errors."""


class InvalidTestcaseError(Error):
  """Error thrown when there is an attempt to access an invalid test case."""

  def __init__(self, testcase_id: Any) -> None:
    super().__init__(f'Invalid test case {testcase_id!r}.')


class InvalidFuzzerError(Error):
  """Error thrown when there is an attempt to set up a nonexistent fuzzer."""

  def __init__(self) -> None:
    super().__init__('Invalid fuzzer.')


class BadStateError(Error):
  """We are in an unexpected state that we cannot recover from."""

  def __init__(self, message: str | None = None) -> None:
    super().__init__('Entered a bad state.' or message)


class BuildNotFoundError(Error):
  """Exception type for build not found failures."""

  def __init__(self, revision: int | str | None, job_type: str | None) -> None:
    self.revision = revision
    self.job_type = job_type
    super().__init__()

  def __str__(self) -> str:
    return f'Build not found (revision {self.revision}, job {self.job_type}).'


class BadConfigError(Error):
  """Error thrown when configuration is bad."""

  def __init__(self, config_dir: str) -> None:
    super().__init__(
        'Bad configuration at: {config_dir}'.format(config_dir=config_dir))


class ConfigParseError(Error):
  """Error thrown when we failed to parse a config yaml file."""

  def __init__(self, file_path: str) -> None:
    self.file_path = file_path
    super().__init__()

  def __str__(self) -> str:
    return 'Failed to parse config file %s.' % self.file_path


class InvalidConfigKey(Error):
  """Error thrown when we failed to parse a config yaml file."""

  def __init__(self, key_name: str) -> None:
    self.key_name = key_name
    super().__init__()

  def __str__(self) -> str:
    return 'Invalid config key %s.' % self.key_name


class QueueLimitReachedError(Error):
  """Error thrown when the queue limit is reached."""

  def __init__(self, size: int, queue: str) -> None:
    super().__init__(f'Queue {queue} has reached the limit of {size}.')
