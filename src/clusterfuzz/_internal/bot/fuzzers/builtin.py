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
"""Builtin fuzzer."""
# NOTE: This module is deprecated and will be replaced with
# lib.clusterfuzz.fuzz.engine.

import os
import random
import sys

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.bot import testcase_manager
from clusterfuzz._internal.bot.fuzzers import engine_common
from clusterfuzz._internal.bot.fuzzers import utils as fuzzers_utils
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.system import shell


class BuiltinFuzzerResult(object):
  """Result of running a builtin fuzzer."""

  def __init__(self, output, corpus_directory=None):
    self.output = output
    self.corpus_directory = corpus_directory


class BuiltinFuzzerException(Exception):
  """Exception that should be thrown when there is an issue preventing a builtin
  fuzzer from running, or if there is a very unusual exception encountered
  during a run."""


class BuiltinFuzzer(object):
  """Builtin fuzzer."""

  def run(self, input_directory, output_directory, no_of_files):
    raise NotImplementedError

  @property
  def fuzzer_directory(self):
    return os.path.abspath(
        os.path.dirname(sys.modules[self.__module__].__file__))


def get_corpus_directory(input_directory, project_qualified_name):
  """Get the corpus directory given a project qualified fuzz target name."""
  corpus_directory = os.path.join(input_directory, project_qualified_name)
  if environment.is_trusted_host():
    from clusterfuzz._internal.bot.untrusted_runner import file_host
    corpus_directory = file_host.rebase_to_worker_root(corpus_directory)

  # Create corpus directory if it does not exist already.
  if environment.is_trusted_host():
    from clusterfuzz._internal.bot.untrusted_runner import file_host
    file_host.create_directory(corpus_directory, create_intermediates=True)
  else:
    shell.create_directory(corpus_directory)
  return corpus_directory


class EngineFuzzer(BuiltinFuzzer):
  """Builtin fuzzer for fuzzing engines such as libFuzzer."""

  def generate_arguments(self, fuzzer_path):
    """Generate arguments for the given fuzzer."""
    raise NotImplementedError

  def _get_fuzzer_binary_name_and_path(self):
    """Returns the fuzzer binary name and its path."""
    # Fuchsia doesn't use file paths to call fuzzers, just the name of the
    # fuzzer, so we set both from FUZZ_TARGET here.
    if environment.platform() == 'FUCHSIA':
      fuzzer_binary_name = fuzzer_path = environment.get_value('FUZZ_TARGET')
      return fuzzer_binary_name, fuzzer_path
    build_directory = environment.get_value('BUILD_DIR')

    if not build_directory:
      raise BuiltinFuzzerException('BUILD_DIR environment variable is not set.')

    fuzzers = fuzzers_utils.get_fuzz_targets(build_directory)

    if not fuzzers:
      raise BuiltinFuzzerException(
          'No fuzzer binaries found in |BUILD_DIR| directory.')

    fuzzer_binary_name = environment.get_value('FUZZ_TARGET')
    if fuzzer_binary_name:
      fuzzer_path = _get_fuzzer_path(fuzzers, fuzzer_binary_name)
    else:
      fuzzer_path = random.SystemRandom().choice(fuzzers)
      fuzzer_binary_name = os.path.basename(fuzzer_path)
    return fuzzer_binary_name, fuzzer_path

  def run(self, input_directory, output_directory, no_of_files):
    """Run the fuzzer to generate testcases."""

    fuzzer_binary_name, fuzzer_path = self._get_fuzzer_binary_name_and_path()

    project_qualified_name = data_types.fuzz_target_project_qualified_name(
        utils.current_project(), fuzzer_binary_name)

    arguments = self.generate_arguments(fuzzer_path)
    corpus_directory = get_corpus_directory(input_directory,
                                            project_qualified_name)

    # Create fuzz testcases.
    for i in range(no_of_files):
      # Contents of testcase file don't matter at this point. Need to create
      # something non-null so that it is not ignored.
      testcase_file_path = os.path.join(
          output_directory, '%s%d' % (testcase_manager.FUZZ_PREFIX, i))
      utils.write_data_to_file(' ', testcase_file_path)

      # Write the flags file containing command line for running launcher
      # script.
      flags_file_path = os.path.join(
          output_directory, '%s%d' % (testcase_manager.FLAGS_PREFIX, i))
      flags = ['%TESTCASE%', fuzzer_binary_name]
      if arguments:
        flags.append(arguments)

      flags_file_content = ' '.join(flags)
      utils.write_data_to_file(flags_file_content, flags_file_path)

    output = 'Generated %d testcase for fuzzer %s.\n' % (no_of_files,
                                                         fuzzer_binary_name)
    output += 'metadata::fuzzer_binary_name: %s\n' % fuzzer_binary_name

    issue_owners = engine_common.get_issue_owners(fuzzer_path)
    if issue_owners:
      output += 'metadata::issue_owners: %s\n' % ','.join(issue_owners)

    issue_labels = engine_common.get_issue_labels(fuzzer_path)
    if issue_labels:
      output += 'metadata::issue_labels: %s\n' % ','.join(issue_labels)

    issue_components = engine_common.get_issue_components(fuzzer_path)
    if issue_components:
      output += 'metadata::issue_components: %s\n' % ','.join(issue_components)

    # Update *SAN_OPTIONS in current environment from .options file. This
    # environment is used in fuzz task later for deriving the environment
    # string in |get_environment_settings_as_string| and embedding this as
    # part of stacktrace.
    engine_common.process_sanitizer_options_overrides(fuzzer_path)

    return BuiltinFuzzerResult(output=output, corpus_directory=corpus_directory)


def _get_fuzzer_path(target_list, fuzzer_name):
  """Return the full fuzzer path and actual binary name of |fuzzer_name|."""
  fuzzer_filename = environment.get_executable_filename(fuzzer_name)
  for path in target_list:
    if os.path.basename(path) == fuzzer_filename:
      return path

  raise BuiltinFuzzerException('Failed to find chosen target ' + fuzzer_name)
