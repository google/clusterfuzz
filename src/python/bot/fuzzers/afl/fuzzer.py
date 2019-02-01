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
"""Write arguments for launcher.py to flags file.
"""

import os

from base import utils
from bot.fuzzers import builtin
from metrics import logs
from system import environment

# The name of the file that run.py puts in the input directory so AFL doesn't
# complain, since it needs at least one input file.
AFL_DUMMY_INPUT = 'in1'


def write_dummy_file(input_dir):
  """Afl will refuse to run if the corpus directory is empty or contains empty
  files. So write the bare minimum to get afl to run if there is no corpus
  yet."""
  # TODO(metzman): Ask lcamtuf to allow AFL to run with an empty input corpus.
  dummy_input_path = os.path.join(input_dir, AFL_DUMMY_INPUT)
  if environment.is_trusted_host():
    from bot.untrusted_runner import file_host
    file_host.write_data_to_worker(' ', dummy_input_path)
  else:
    utils.write_data_to_file(' ', dummy_input_path)


class Afl(builtin.EngineFuzzer):
  """Builtin AFL fuzzer."""

  def generate_arguments(self, fuzzer_path):  # pylint: disable=unused-argument
    """Generate arguments for fuzzer using .options file or default values."""
    return ''

  def _check_system_settings(self):
    """Check system settings required for AFL."""
    kernel_core_pattern_file_path = '/proc/sys/kernel/core_pattern'
    if (os.path.exists(kernel_core_pattern_file_path) and
        open(kernel_core_pattern_file_path).read().strip() != 'core'):
      logs.log_fatal_and_exit('AFL needs core_pattern to be set to core.')

    cpu_scaling_file_path = (
        '/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor')
    if (os.path.exists(cpu_scaling_file_path) and
        open(cpu_scaling_file_path).read().strip() != 'performance'):
      logs.log_warn('For optimal AFL performance, '
                    'set on-demand cpu scaling to performance.')

  def run(self, input_directory, output_directory, no_of_files):
    self._check_system_settings()

    result = super(Afl, self).run(input_directory, output_directory,
                                  no_of_files)

    write_dummy_file(result.corpus_directory)
    return result
