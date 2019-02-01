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
"""This module builds attributes for a single Testcase entity."""


def populate_example(testcase):  # pylint: disable=unused-argument
  """An example for changing testcase's attributes."""


def populate(testcase):
  """Build attributes for one testcase. Return true if the entity is
    modified."""
  populate_example(testcase)
  testcase.populate_indices()
  # The number of testcases are low enough; we can mark every entity as
  # modified.
  return True
