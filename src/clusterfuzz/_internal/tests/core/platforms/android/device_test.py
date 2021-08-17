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
"""Tests for device functions."""

from clusterfuzz._internal.platforms.android import device
from clusterfuzz._internal.tests.test_libs import android_helpers


class InitializeEnvironmentTest(android_helpers.AndroidTest):
  """Tests for """

  def test(self):
    """Ensure that initialize_environment throws no exceptions."""
    device.initialize_environment()
