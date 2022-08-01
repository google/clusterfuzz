# Copyright 2020 Google LLC
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
"""Linux Kernel Library specific modules."""
from clusterfuzz._internal.system import environment

from . import constants


def get_lkl_binary_name(unsymbolized_crash_stacktrace_split):
  """Returns the lkl binary name from a stack trace."""
  for line in unsymbolized_crash_stacktrace_split:
    match = constants.LINUX_KERNEL_LIBRARY_ASSERT_REGEX.match(line)
    if match:
      return match.group(1)

  return None


def is_lkl_stack_trace(unsymbolized_crash_stacktrace):
  """Is this an lkl stack trace?"""
  return (
      environment.is_lkl_job() and
      constants.LINUX_KERNEL_MODULE_STACK_TRACE in unsymbolized_crash_stacktrace
  )
