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
"""helpers.py contains convenient methods for writing tests."""

import contextlib
import os
import time
import types
from unittest import mock


class Matcher:
  # pylint: disable=line-too-long
  """A class used for argument matching.

  See:
    https://docs.python.org/3/library/unittest.mock-examples.html#more-complex-argument-matching.
  """

  def __init__(self, compare, some_obj):
    self.compare = compare
    self.some_obj = some_obj

  def __eq__(self, other):
    return self.compare(self.some_obj, other)


# _Object is needed because we want to add attribute to its instance.
class _Object:
  pass


def patch(testcase_obj, names):
  """Patch names and add them as attributes to testcase_obj.

  For example,
     `patch(obj, ['a.b.function', ('function2', 'c.d.method')])` adds the
     attributes `mock.function` and `mock.function2` to `obj`.

     To provide a replacement function for a mocked one, use `side_effect`
     attribute, for example:
     `self.mock.function.side_effect = replacementFunctionForTests.`
  """
  if not hasattr(testcase_obj, 'mock'):
    setattr(testcase_obj, 'mock', _Object())
  for name in names:
    if isinstance(name, tuple):
      attr_name = name[0]
      full_path = name[1]
    else:
      attr_name = name.split('.')[-1]
      full_path = name

    patcher = mock.patch(full_path, autospec=True)
    testcase_obj.addCleanup(patcher.stop)
    setattr(testcase_obj.mock, attr_name, patcher.start())

    patched = getattr(testcase_obj.mock, attr_name)

    # A class doesn't have __name__. We need to set __name__ for a method
    # because we use it when monkey-patching.
    if '__name__' in dir(patched):
      setattr(patched, '__name__', attr_name)


def patch_environ(testcase_obj, env=None):
  """Patch environment."""
  if env is None:
    env = {}

  patcher = mock.patch.dict(os.environ, env)
  testcase_obj.addCleanup(patcher.stop)
  patcher.start()


@contextlib.contextmanager
def emulate_host_os(path_module, modules):
  """Makes `modules` use `path_module` (e.g. posixpath or ntpath) as os.path.

  On Linux, os.path is posixpath, which hides bugs that only appear on Windows
  bots, where os.path is ntpath. Only the `os` name inside each of `modules` is
  replaced; the global `os` module is left untouched.
  """
  host_os = types.ModuleType('host_os')
  host_os.__dict__.update(os.__dict__)
  host_os.path = path_module
  host_os.sep = path_module.sep
  host_os.altsep = path_module.altsep
  with contextlib.ExitStack() as stack:
    for module in modules:
      stack.enter_context(mock.patch.object(module, 'os', host_os))
    yield


class MockTime:
  """Mock time because we cannot really mock time.time()."""

  def __init__(self, start_time=None):
    self.current_time = start_time or time.time()

  def advance(self, delta):
    """Move the time by delta."""
    self.current_time += delta

  def time(self):
    """Get the current time."""
    return self.current_time

  def time_ns(self):
    """Get the current time in nanoseconds."""
    return int(self.current_time * 10**9)
