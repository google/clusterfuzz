# Copyright 2024 Google LLC
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
"""Build archive tests."""
import io
import os
import tempfile
import unittest

import parameterized

from clusterfuzz._internal.build_management import build_archive
from clusterfuzz._internal.system import archive
from clusterfuzz._internal.system import shell
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers

TESTDATA_PATH = os.path.join(os.path.dirname(__file__), 'build_archive_data')


class BuildArchiveTest(unittest.TestCase):
  """Unpack tests."""

  def test_missing_runtime_deps_file(self):
    """Tests that the chrome build handler fallbacks on the default handler
    in case of a missing runtime_deps file."""
    # """Test unpack with trusted=False passes with file having './' prefix."""
    path = os.path.join(TESTDATA_PATH, 'missing-runtime-deps.zip')
    output_directory = tempfile.mkdtemp(prefix='chromium')
    build = build_archive.open(archive_path=path)
    self.assertTrue(isinstance(build, build_archive.ChromeBuildArchive))

    self.assertCountEqual(build.list_fuzz_targets(), ["empty_fuzzer"])
    build.unpack(fuzz_target="empty_fuzzer", build_dir=output_directory)
    self.assertTrue(
        os.path.exists(os.path.join(output_directory, 'empty_fuzzer')))
    self.assertTrue(
        os.path.exists(os.path.join(output_directory, 'test/fake_dso.so')))

    # Current default behaviour will also unpack `args.gn` since it ends with
    # a non-disallowed extension.
    self.assertTrue(os.path.exists(os.path.join(output_directory, 'args.gn')))

    shell.remove_directory(output_directory)


class DefaultBuildArchiveSelectiveUnpack(unittest.TestCase):
  """Tests for _get_file_match_callback."""

  def setUp(self):
    test_helpers.patch(self, [
        'clusterfuzz._internal.system.archive.ArchiveReader',
        'clusterfuzz._internal.system.archive.open',
    ])
    self.mock.open.return_value.list_members.return_value = []
    self.build = build_archive.DefaultBuildArchive(self.mock.open.return_value)
    self.assertIsInstance(self.build, build_archive.DefaultBuildArchive)

  def _add_files_to_archive(self, files):
    res = []
    for file in files:
      res.append(
          archive.ArchiveMemberInfo(
              name=file, is_dir=False, size_bytes=0, mode=0))
    self.mock.open.return_value.list_members.return_value = res

  def _generate_possible_fuzzer_dependencies(self, dir_prefix, fuzz_target):
    """Generates all possible dependencies for the given target."""
    needed_files = [
        f'{fuzz_target}',
        f'{fuzz_target}.exe',
        f'{fuzz_target}.exe.pdb',
        f'{fuzz_target}.dict',
        f'{fuzz_target}.options',
        'shared.dll',
        'shared.dll.pdb',
        'llvm-symbolizer',
        'icudtl.dat',
        'swiftshader/libGLESv2.so',
        'instrumented_libraries/msan/lib/libgcrypt.so.11.8.2',
        'afl-fuzz',
        f'{fuzz_target}.exe',
        f'{fuzz_target}.par',
        f'{fuzz_target}.dSYM/Contents/Resources/DWARF/some_dependency',
        'src_root/some_dependency',
        'chrome_crashpad_handler',
    ]
    return [os.path.join(dir_prefix, file) for file in needed_files]

  @parameterized.parameterized.expand(['/b/build/', 'build/', './'])
  def test_possible_dependencies(self, dir_prefix):
    """Tests that the default build handler correctly unpacks the requested
    fuzzer dependencies."""
    needed_files = self._generate_possible_fuzzer_dependencies(
        dir_prefix, 'my_fuzzer')
    self._add_files_to_archive(needed_files)
    to_extract = self.build.get_target_dependencies('my_fuzzer')
    to_extract = [f.name for f in to_extract]
    self.assertCountEqual(to_extract, needed_files)

  @parameterized.parameterized.expand(['/b/build/', 'build/', './'])
  def test_other_fuzzer_not_extracted(self, dir_prefix):
    """Tests that the default build handler only unpacks the requested fuzzer
    dependencies, even if other fuzzers exist in the build."""
    needed_files = self._generate_possible_fuzzer_dependencies(
        dir_prefix, 'my_fuzzer')
    other_fuzzer_match = [
        os.path.join(dir_prefix, 'other_fuzzer.dict'),
    ]
    other_fuzzer = self._generate_possible_fuzzer_dependencies(
        dir_prefix, 'other_fuzzer')
    self._add_files_to_archive(list(set(needed_files + other_fuzzer)))
    to_extract = self.build.get_target_dependencies('my_fuzzer')
    to_extract = [f.name for f in to_extract]
    self.assertCountEqual(to_extract,
                          list(set(needed_files + other_fuzzer_match)))


class ChromeBuildArchiveSelectiveUnpack(unittest.TestCase):
  """Tests for _get_file_match_callback."""

  def setUp(self):
    test_helpers.patch(self, [
        'clusterfuzz._internal.system.archive.ArchiveReader',
        'clusterfuzz._internal.system.archive.open',
        'clusterfuzz._internal.bot.fuzzers.utils.is_fuzz_target_local',
    ])
    self.mock.open.return_value.list_members.return_value = []
    self.mock.is_fuzz_target_local.side_effect = self._mock_is_fuzz_target_local
    self.build = build_archive.ChromeBuildArchive(self.mock.open.return_value)
    self._declared_fuzzers = []
    self.maxDiff = None

  def _mock_is_fuzz_target_local(self, target, _=None):
    target = os.path.basename(target)
    return target in self._declared_fuzzers

  def _add_files_to_archive(self, files):
    res = []
    for file in files:
      res.append(
          archive.ArchiveMemberInfo(
              name=file, is_dir=False, size_bytes=0, mode=0))
    self.mock.open.return_value.list_members.return_value = res

  def _generate_possible_fuzzer_dependencies(self, dir_prefix, fuzz_target):
    """Generates all possible dependencies for the given target."""
    needed_files = [
        f'{fuzz_target}',
        f'{fuzz_target}.exe',
        f'{fuzz_target}.exe.pdb',
        f'{fuzz_target}.dict',
        f'{fuzz_target}.options',
        f'{fuzz_target}.runtime_deps',
        f'{fuzz_target}.par',
        f'{fuzz_target}.dSYM/Contents/Resources/DWARF/some_dependency',
        'shared.dll',
        'shared.dll.pdb',
        'llvm-symbolizer',
        'icudtl.dat',
        'swiftshader/libGLESv2.so',
        'instrumented_libraries/msan/lib/libgcrypt.so.11.8.2',
        'afl-fuzz',
        'src_root/some_dependency',
        'chrome_crashpad_handler',
    ]
    return [os.path.join(dir_prefix, file) for file in needed_files]

  def _generate_runtime_deps(self, deps):

    def _mock_open(_):
      buffer = io.BytesIO(b'')
      for dep in deps:
        buffer.write(dep.encode() + b'\n')
      buffer.seek(0)
      return buffer

    self.mock.open.return_value.open.side_effect = _mock_open

  def _declare_fuzzers(self, fuzzers):
    self._declared_fuzzers = fuzzers

  @parameterized.parameterized.expand(['/b/build/', 'build/', ''])
  def test_possible_dependencies(self, dir_prefix):
    """Tests that all the necessary dependencies are correctly extracted from
    the runtime_deps file."""
    deps_files = self._generate_possible_fuzzer_dependencies('', 'my_fuzzer')
    needed_files = self._generate_possible_fuzzer_dependencies(
        dir_prefix, 'my_fuzzer')
    self._add_files_to_archive(needed_files)
    self._generate_runtime_deps(deps_files)
    self._declare_fuzzers(['my_fuzzer'])
    to_extract = self.build.get_target_dependencies('my_fuzzer')
    to_extract = [f.name for f in to_extract]
    self.assertCountEqual(to_extract, needed_files)

  @parameterized.parameterized.expand(['/b/build/', 'build/', ''])
  def test_possible_dependencies_archive_without_normalized_path(
      self, dir_prefix):
    """Tests that the chrome build handler correctly handles mixed-up
    normalized and not normalized path."""
    deps_files = self._generate_possible_fuzzer_dependencies('', 'my_fuzzer')
    needed_files = self._generate_possible_fuzzer_dependencies(
        dir_prefix, 'my_fuzzer')
    self._add_files_to_archive(needed_files)

    # we want our runtime_deps to have normalized path so that they do not
    # exactly match the archive paths.
    self._generate_runtime_deps(deps_files)
    self._declare_fuzzers(['my_fuzzer'])
    to_extract = self.build.get_target_dependencies('my_fuzzer')
    to_extract = [f.name for f in to_extract]
    self.assertCountEqual(to_extract, needed_files)

  @parameterized.parameterized.expand(['/b/build/', 'build/', ''])
  def test_possible_dependencies_deps_without_normalized_path(self, dir_prefix):
    """Tests that the chrome build handler correctly handles mixed-up
    normalized and not normalized path."""
    deps_files = self._generate_possible_fuzzer_dependencies('', 'my_fuzzer')
    needed_files = self._generate_possible_fuzzer_dependencies(
        dir_prefix, 'my_fuzzer')
    self._add_files_to_archive([os.path.normpath(f) for f in needed_files])
    self._generate_runtime_deps(deps_files)
    self._declare_fuzzers(['my_fuzzer'])
    to_extract = self.build.get_target_dependencies('my_fuzzer')
    to_extract = [f.name for f in to_extract]
    self.assertCountEqual(to_extract,
                          [os.path.normpath(f) for f in needed_files])

  @parameterized.parameterized.expand(['/b/build/', 'build/', ''])
  def test_other_fuzzer_not_extracted(self, dir_prefix):
    """Tests that the chrome build handler only unpacks dependencies for the
    requested fuzzer, even if other fuzzers exist in the build."""
    deps_files = self._generate_possible_fuzzer_dependencies('', 'my_fuzzer')
    needed_files = self._generate_possible_fuzzer_dependencies(
        dir_prefix, 'my_fuzzer')
    other_fuzzer = self._generate_possible_fuzzer_dependencies(
        dir_prefix, 'other_fuzzer')
    self._add_files_to_archive(list(set(needed_files + other_fuzzer)))
    self._generate_runtime_deps(deps_files)
    self._declare_fuzzers(['my_fuzzer', 'other_fuzzer'])
    to_extract = self.build.get_target_dependencies('my_fuzzer')
    to_extract = [f.name for f in to_extract]
    self.assertCountEqual(to_extract, needed_files)

  @parameterized.parameterized.expand(['/b/build/', 'build/', ''])
  def test_dsyms_are_correctly_unpacked(self, dir_prefix):
    """Tests that even if not listed in the runtime deps, dSYMs are correctly unpacked.
    """
    needed_files = self._generate_possible_fuzzer_dependencies(
        dir_prefix, 'my_fuzzer')
    self._add_files_to_archive(needed_files)
    self._generate_runtime_deps(['my_fuzzer'])
    to_extract = self.build.get_target_dependencies('my_fuzzer')
    to_extract = [f.name for f in to_extract]
    dsym_path = os.path.join(
        dir_prefix, 'my_fuzzer.dSYM/Contents/Resources/DWARF/some_dependency')
    self.assertIn(dsym_path, to_extract)
