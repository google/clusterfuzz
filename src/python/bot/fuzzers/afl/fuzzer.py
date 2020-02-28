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
    file_host.write_data_to_worker(b' ', dummy_input_path)
  else:
    utils.write_data_to_file(' ', dummy_input_path)


class Afl(builtin.EngineFuzzer):
  """Builtin AFL fuzzer."""

  def generate_arguments(self, fuzzer_path):  # pylint: disable=unused-argument
    """Generate arguments for fuzzer using .options file or default values."""
    return ''

  def run(self, input_directory, output_directory, no_of_files):
    result = super(Afl, self).run(input_directory, output_directory,
                                  no_of_files)

    write_dummy_file(result.corpus_directory)
    return result
