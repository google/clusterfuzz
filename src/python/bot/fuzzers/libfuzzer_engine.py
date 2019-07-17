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
"""libFuzzer engine interface."""

from bot.fuzzers import engine


class LibFuzzerOptions(engine.FuzzOptions):
  """LibFuzzer engine options."""

  def __init__(self, corpus_dir, arguments, strategies):
    super(LibFuzzerOptions, self).__init__(self, corpus_dir, arguments,
                                           strategies)


class LibFuzzerEngine(engine.Engine):
  """LibFuzzer engine implementation."""

  @property
  def name(self):
    return 'libFuzzer'

  def prepare(self, corpus_dir, target_path, build_dir):
    """Prepare for a fuzzing session, by generating options. Returns a
    FuzzOptions object."""
    raise NotImplementedError

  def fuzz(self, target_path, options, max_time):
    """Run a fuzz session. Returns a Result."""
    raise NotImplementedError

  def reproduce(self, target_path, input_path, arguments, max_time):
    """Reproduce a crash given an input. Returns a Result."""
    raise NotImplementedError

  def minimize_corpus(self, target_path, dirs, max_time):
    """Optional (but recommended): run corpus minimization. Returns a Result."""
    raise NotImplementedError

  def minimize_testcase(self, target_path, input_path, output_path, max_time):
    """Optional: minimize a testcase. Returns a bool."""
    raise NotImplementedError

  def cleanse(self, target_path, input_path, output_path, max_time):
    """Optional: scrub a testcase of potentially sensitive bytes. Returns a
    bool."""
    raise NotImplementedError
