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
"""Tests for the stack symbolizer module."""

import os
import unittest

from clusterfuzz._internal.crash_analysis.stack_parsing import stack_symbolizer
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.tests.test_libs import helpers

DATA_DIRECTORY = os.path.join(
    os.path.dirname(__file__), 'stack_symbolizer_data')


class ChromeDsymHintsTests(unittest.TestCase):
  """Tests chrome_dsym_hints."""

  def test_standalone_executable(self):
    """Tests that standalone executable work as expected."""
    self.assertEqual([], stack_symbolizer.chrome_dsym_hints('/build/binary'))

  def test_standalone_framework_or_app(self):
    """Tests that standalone frame or app bundle work as expected."""
    self.assertEqual(
        ['/build/Content Shell.dSYM'],
        stack_symbolizer.chrome_dsym_hints('/build/Content Shell.app'))
    self.assertEqual(
        ['/build/Content Shell.dSYM'],
        stack_symbolizer.chrome_dsym_hints('/build/Content Shell.framework'))

  def test_nested_bundles(self):
    """Tests that two or three nested bundles work as expected."""
    self.assertEqual(
        ['/build/Content Shell Helper.dSYM'],
        stack_symbolizer.chrome_dsym_hints(
            '/build/Content Shell.app/Contents'
            '/Frameworks/Content Shell Framework.framework/Versions/C/Helpers'
            '/Content Shell Helper.app/Contents/MacOS/Content Shell Helper'))
    self.assertEqual(
        ['/build/Content Shell Helper.dSYM'],
        stack_symbolizer.chrome_dsym_hints(
            '/build/Content Shell.app/Contents'
            '/Versions/C/Helpers'
            '/Content Shell Helper.app/Contents/MacOS/Content Shell Helper'))


class StackSymbolizerTestcase(unittest.TestCase):
  """Stack symbolizer tests."""

  def setUp(self):
    """Set environment variables used by stack symbolizer tests."""

    class ZipFileMock():

      def namelist(self):
        return ['']

    def mock_trusty_symbolize(self, offset, binary, addr):
      """Function to mock addr2line return values"""

      if (offset, binary, addr) == ('0xffff000000043210', 'test_dir/lk.elf',
                                    '0xffff000000043210'):
        return ['0xffff000000043210 in sys_brk ld-temp.o:?']
      if (offset, binary, addr) == ('0xffff000000283ccc', 'test_dir/lk.elf',
                                    '0xffff000000283ccc'):
        return ['0xffff000000283ccc in $x.0 arm64/syscall.S:57']
      if (offset, binary, addr) == ('0x0000000000087710', 'test_dir/lk.elf',
                                    '0x0000000000087710'):
        return ['0x0000000000087710 in lk.elf']
      if (offset, binary,
          addr) == ('0x0000000000035290', 'test_dir/keymaster.syms.elf',
                    '0x0000000000035290'):
        return ['0x0000000000035290 in sha512_block sha512-armv8.S:1317']
      if (offset, binary,
          addr) == ('0x00000000001392a8', 'test_dir/keymaster.syms.elf',
                    '0x00000000001392a8'):
        return ['0x00000000001392a8 in sha512_block sha512-armv8.S:809']

      self.default = ['']
      return self.default

    helpers.patch_environ(self)
    helpers.patch(self, [
        'clusterfuzz._internal.platforms.android.settings.get_build_parameters',
        'clusterfuzz._internal.platforms.android.fetch_artifact.get_latest_artifact_info',
        'clusterfuzz._internal.platforms.android.fetch_artifact.get',
        'zipfile.ZipFile',
        'clusterfuzz._internal.crash_analysis.stack_parsing.stack_symbolizer.Addr2LineSymbolizer.symbolize',
        'clusterfuzz._internal.crash_analysis.stack_parsing.stack_symbolizer.Addr2LineSymbolizer.open_addr2line',
    ])

    self.mock.get_build_parameters.return_value = {'target': 'oriole'}
    self.mock.get_latest_artifact_info.return_value = {'bid': '12345678'}
    self.mock.get.return_value = ''
    self.mock.open_addr2line.return_value = ''
    self.mock.namelist = ['']
    self.mock.symbolize.side_effect = mock_trusty_symbolize

    zipfile_mock = ZipFileMock()
    self.mock.ZipFile.return_value.__enter__.return_value = zipfile_mock

    environment.set_value('SYMBOLS_DIR', 'test/dir')

  def _read_test_data(self, name):
    """Helper function to read test data."""
    with open(os.path.join(DATA_DIRECTORY, name), encoding='utf-8') as handle:
      return handle.read()

  def test_process_trusty_stacktrace(self):
    """Test desymbolization of Trusty stacktrace"""
    print('donig a test')
    data = self._read_test_data('android_trusty.txt')
    expected_data = self._read_test_data('android_trusty_symbolized.txt')

    loop = stack_symbolizer.SymbolizationLoop()
    result = loop.process_trusty_stacktrace(data)

    self.assertEqual(result, expected_data)
