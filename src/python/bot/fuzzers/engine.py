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
"""Fuzzing engine interface."""

from builtins import object

_ENGINES = {}


class FuzzOptions(object):
  """Represents options passed to the engine. Can be overridden to provide more
  options."""

  def __init__(self, corpus_dir, arguments, strategies):
    self.corpus_dir = corpus_dir
    self.arguments = arguments
    self.strategies = strategies


class Crash(object):
  """Represents a crash found by the fuzzing engine."""

  def __init__(self, input_path, stacktrace, reproduce_args):
    self.input_path = input_path
    self.stacktrace = stacktrace
    self.reproduce_args = reproduce_args


class Result(object):
  """Represents a result of a fuzzing session: a list of crashes found and the
  stats generated."""

  def __init__(self, crashes, stats):
    self.crashes = crashes
    self.stats = stats


class Engine(object):
  """Base interface for a grey box fuzzing engine."""

  @property
  def name(self):
    """Get the name of the engine."""
    raise NotImplementedError

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


def register_engine(impl):
  """Register a fuzzing engine."""
  if impl.name in _ENGINES:
    raise ValueError(
        'Engine {name} is already registered'.format(name=impl.name))

  _ENGINES[impl.name] = impl


def get(name):
  """Get an implemntation of a fuzzing engine, or None if one does not exist."""
  engine_class = _ENGINES.get(name)
  if engine_class:
    return engine_class()

  return None
