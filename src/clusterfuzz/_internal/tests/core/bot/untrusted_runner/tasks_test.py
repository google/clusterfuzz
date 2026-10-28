# Copyright 2026 Google LLC
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
"""Tests for packing/unpacking stats between tasks_impl and tasks_host."""

import unittest

from clusterfuzz._internal.bot.untrusted_runner import tasks_host
from clusterfuzz._internal.bot.untrusted_runner import tasks_impl

# pylint: disable=protected-access


class PackUnpackValuesTest(unittest.TestCase):
  """Tests for tasks_impl._pack_values and tasks_host._unpack_values."""

  def test_round_trip(self):
    """Tests that all supported stat types survive a pack/unpack round trip."""
    values = {
        'float_stat': 1.5,
        'int_stat': 42,
        'str_stat': 'value',
        'fuzz_task_steps_duration': {
            'engine_prepare': 'P0DT0H0M1.500000S'
        },
    }
    packed = tasks_impl._pack_values(values)
    self.assertDictEqual(values, tasks_host._unpack_values(packed))

  def test_pack_none(self):
    """Tests that packing None returns an empty dict."""
    self.assertDictEqual({}, tasks_impl._pack_values(None))

  def test_pack_unknown_type(self):
    """Tests that packing an unsupported type raises."""
    with self.assertRaises(ValueError):
      tasks_impl._pack_values({'list_stat': [1, 2]})


if __name__ == '__main__':
  unittest.main()
