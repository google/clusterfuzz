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
"""Test helpers for Android."""

import unittest

from clusterfuzz._internal.platforms.android import adb
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils


@test_utils.android_device_required
class AndroidTest(unittest.TestCase):
  """Set up state for Android tests."""

  def setUp(self):
    helpers.patch_environ(self)
    environment.set_value('OS_OVERRIDE', 'ANDROID')
    environment.set_bot_environment()
    adb.setup_adb()
    adb.run_as_root()
