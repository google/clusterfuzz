# Copyright 2021 Google LLC
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
"""Tests for syzkaller runner."""
# pylint: disable=protected-access
import unittest

from clusterfuzz._internal.bot.fuzzers.syzkaller.runner import \
    AndroidSyzkallerRunner

EXECUTABLE_PATH = '/usr/local/google/home/username/syzkaller'


class RunnerTest(unittest.TestCase):

  def setUp(self):
    super(RunnerTest, self).setUp()
    self.target = AndroidSyzkallerRunner(EXECUTABLE_PATH)

  def test_filter_log(self):
    content = ('[  565.723853] c4   8262 BUG: KASAN: use-after-free '
               'in f2fs_register_inmem_page+0x208/0x390')
    self.assertEqual(
        self.target._filter_log(content),
        'BUG: KASAN: use-after-free in f2fs_register_inmem_page+0x208/0x390',
    )

  def test_filter_log_without_pid(self):
    content = ('[ 1850.287295] KASAN: null-ptr-deref in range '
               '[0x0000000000000088-0x000000000000008f]')
    self.assertEqual(
        self.target._filter_log(content),
        'KASAN: null-ptr-deref in range [0x0000000000000088-0x000000000000008f]',
    )
