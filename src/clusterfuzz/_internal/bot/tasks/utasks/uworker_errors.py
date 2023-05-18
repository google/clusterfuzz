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
"""Module for enumerating errors in utasks."""
import enum


class Type(enum.Enum):
  """Errors during utask_main."""
  ANALYZE_BUILD_SETUP = 1
  ANALYZE_NO_CRASH = 2
  TESTCASE_SETUP = 3
  NO_FUZZER = 4


class Error:
  """Class representing error messages from the untrusted worker. This should
  contain the type of the error |error_type| as well as any other data to handle
  the error."""

  def __init__(self, error_type, **kwargs):
    self.error_type = error_type
    for key, value in kwargs.items():
      setattr(self, key, value)

  def to_dict(self):
    # Make a copy so calls to pop don't modify the object.
    return self.__dict__.copy()
