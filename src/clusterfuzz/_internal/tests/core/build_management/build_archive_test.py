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
import json
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
        'clusterfuzz._internal.bot.fuzzers.utils.is_fuzz_target',
    ])
    self.mock.open.return_value.list_members.return_value = []
    self.mock.is_fuzz_target.side_effect = self._mock_is_fuzz_target
    self.build = build_archive.ChromeBuildArchive(self.mock.open.return_value)
    self._declared_fuzzers = []
    self.maxDiff = None

  def _mock_is_fuzz_target(self, target, _=None):
    target = os.path.basename(target)
    return target in self._declared_fuzzers

  def _add_files_to_archive(self, files):
    res = []
    for file in files:
      res.append(
          archive.ArchiveMemberInfo(
              name=file, is_dir=False, size_bytes=0, mode=0))
    self.mock.open.return_value.list_members.return_value = res

  def _generate_possible_fuzzer_dependencies_legacy(self, dir_prefix,
                                                    fuzz_target):
    """Generates all possible dependencies for the given target.

    This implementation represents the legacy archive schema prior to version 1
    and should not be used for new tests; we keep it around for backwards
    compatibility.

    New tests should use a combination of
    `_generate_possible_fuzzer_dependencies()` and
    `_resolve_relative_dependency_paths()`.
    """
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

  def _generate_possible_fuzzer_dependencies(self, fuzz_target):
    """Returns a list of dependencies as file paths relative to
    {fuzz_target}.runtime_deps, as they appear in runtime_deps files in real
    archives.
    """
    return [
        f'./{fuzz_target}',
        f'{fuzz_target}.owners',
        f'{fuzz_target}.runtime_deps',
        f'{fuzz_target}.dSYM/Contents/Resources/DWARF/some_dependency',
        './libbase.so',
        '../../tools/valgrind/asan/',
        '../../third_party/llvm-build/Release+Asserts/bin/llvm-symbolizer',
        '../../third_party/instrumented_libs/binaries/msan-chained-origins-noble-lib/lib',
        'third_party/instrumented_libs/binaries/msan-chained-origins-noble-lib/lib/ld-linux-x86-64.so.2',
        './libatomic.so',
        'icudtl.dat',
        f'bin/run_{fuzz_target}',
        '../../testing/location_tags.json',
    ]

  def _resolve_relative_dependency_paths(self, deps_paths):
    """Returns a list of dependencies as normalized file paths, i.e. with
    relative path separators like './' and '../' resolved to their true
    directory names.
    """

    # Runtime deps include file paths that begin with ../../ so the build
    # directory is assumed to be two levels deep into the file tree.
    return [
        os.path.normpath(os.path.join('out/build/', file))
        for file in deps_paths
    ]

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

  def _set_archive_schema_version(self, version):
    self.build = build_archive.ChromeBuildArchive(self.mock.open.return_value,
                                                  version)


  @parameterized.parameterized.expand(['/b/build/', 'build/', ''])
  def test_possible_dependencies_legacy(self, dir_prefix):
    """Tests that all the necessary dependencies are correctly extracted from
    the runtime_deps file, using the legacy archive schema where dependency
    paths are interpreted as relative to the archive root and `../../` is
    remapped to `src_root/`."""
    deps_files = self._generate_possible_fuzzer_dependencies_legacy(
        '', 'my_fuzzer')
    needed_files = self._generate_possible_fuzzer_dependencies_legacy(
        dir_prefix, 'my_fuzzer')
    self._add_files_to_archive(needed_files)
    self._generate_runtime_deps(deps_files)
    self._declare_fuzzers(['my_fuzzer'])
    to_extract = self.build.get_target_dependencies('my_fuzzer')
    to_extract = [f.name for f in to_extract]
    self.assertCountEqual(to_extract, needed_files)

  @parameterized.parameterized.expand(['/b/build/', 'build/', ''])
  def test_possible_dependencies_deps_without_normalized_path_legacy(
      self, dir_prefix):
    """Tests that the chrome build handler correctly handles mixed-up
    normalized and not normalized path."""
    deps_files = self._generate_possible_fuzzer_dependencies_legacy(
        '', 'my_fuzzer')
    needed_files = self._generate_possible_fuzzer_dependencies_legacy(
        dir_prefix, 'my_fuzzer')
    self._add_files_to_archive([os.path.normpath(f) for f in needed_files])
    self._generate_runtime_deps(deps_files)
    self._declare_fuzzers(['my_fuzzer'])
    to_extract = self.build.get_target_dependencies('my_fuzzer')
    to_extract = [f.name for f in to_extract]
    self.assertCountEqual(to_extract,
                          [os.path.normpath(f) for f in needed_files])

  @parameterized.parameterized.expand(['/b/build/', 'build/', ''])
  def test_other_fuzzer_not_extracted_legacy(self, dir_prefix):
    """Tests that the chrome build handler only unpacks dependencies for the
    requested fuzzer, even if other fuzzers exist in the build."""
    deps_files = self._generate_possible_fuzzer_dependencies_legacy(
        '', 'my_fuzzer')
    needed_files = self._generate_possible_fuzzer_dependencies_legacy(
        dir_prefix, 'my_fuzzer')
    other_fuzzer = self._generate_possible_fuzzer_dependencies_legacy(
        dir_prefix, 'other_fuzzer')
    self._add_files_to_archive(list(set(needed_files + other_fuzzer)))
    self._generate_runtime_deps(deps_files)
    self._declare_fuzzers(['my_fuzzer', 'other_fuzzer'])
    to_extract = self.build.get_target_dependencies('my_fuzzer')
    to_extract = [f.name for f in to_extract]
    self.assertCountEqual(to_extract, needed_files)

  @parameterized.parameterized.expand(['/b/build/', 'build/', ''])
  def test_dsyms_are_correctly_unpacked_legacy(self, dir_prefix):
    """Tests that even if not listed in the runtime deps, dSYMs are correctly unpacked.
    """
    needed_files = self._generate_possible_fuzzer_dependencies_legacy(
        dir_prefix, 'my_fuzzer')
    self._add_files_to_archive(needed_files)
    self._generate_runtime_deps(['my_fuzzer'])
    to_extract = self.build.get_target_dependencies('my_fuzzer')
    to_extract = [f.name for f in to_extract]
    dsym_path = os.path.join(
        dir_prefix, 'my_fuzzer.dSYM/Contents/Resources/DWARF/some_dependency')
    self.assertIn(dsym_path, to_extract)

  def test_possible_dependencies(self):
    """Tests that all the necessary dependencies are correctly extracted from
    the runtime_deps file.

    Under archive schema version 1, dependency paths in `runtime_deps` files
    are interpreted as being relative to the file itself, meaning that they must
    be normalized to the equivalent path relative to the archive root before
    they can be extracted.
    """
    self._set_archive_schema_version(1)
    deps_entries = self._generate_possible_fuzzer_dependencies('my_fuzzer')
    deps_files = self._resolve_relative_dependency_paths(deps_entries)
    self._add_files_to_archive(deps_files)
    self._generate_runtime_deps(deps_entries)
    self._declare_fuzzers(['my_fuzzer'])
    to_extract = self.build.get_target_dependencies('my_fuzzer')
    to_extract = [f.name for f in to_extract]
    self.assertCountEqual(to_extract, deps_files)

  def test_other_fuzzer_not_extracted(self):
    """Tests that the chrome build handler only unpacks dependencies for the
    requested fuzzer, even if other fuzzers exist in the build."""
    self._set_archive_schema_version(1)
    deps_entries = self._generate_possible_fuzzer_dependencies('my_fuzzer')
    needed_files = self._resolve_relative_dependency_paths(deps_entries)
    other_fuzzer = self._resolve_relative_dependency_paths(
        self._generate_possible_fuzzer_dependencies('other_fuzzer'))
    self._add_files_to_archive(list(set(needed_files + other_fuzzer)))
    self._generate_runtime_deps(deps_entries)
    self._declare_fuzzers(['my_fuzzer', 'other_fuzzer'])
    to_extract = self.build.get_target_dependencies('my_fuzzer')
    to_extract = [f.name for f in to_extract]
    self.assertCountEqual(to_extract, needed_files)

  def test_dsyms_are_correctly_unpacked(self):
    """Tests that even if not listed in the runtime deps, dSYMs are correctly
    unpacked."""
    self._set_archive_schema_version(1)
    needed_files = self._resolve_relative_dependency_paths(
        self._generate_possible_fuzzer_dependencies('my_fuzzer'))
    self._add_files_to_archive(needed_files)
    self._generate_runtime_deps(['my_fuzzer'])
    to_extract = self.build.get_target_dependencies('my_fuzzer')
    to_extract = [f.name for f in to_extract]
    self.assertIn(
        'out/build/my_fuzzer.dSYM/Contents/Resources/DWARF/some_dependency',
        to_extract)


class ChromeBuildArchiveManifestTest(unittest.TestCase):
  """Test for reading clusterfuzz_manifest.json for Chrome archives."""

  def setUp(self):
    test_helpers.patch(self, [
        'clusterfuzz._internal.system.archive.ArchiveReader.file_exists',
        'clusterfuzz._internal.system.archive.ArchiveReader',
        'clusterfuzz._internal.system.archive.open',
    ])
    self.mock.file_exists.return_value = False

  def _generate_manifest(self, archive_schema_version):

    def _mock_open(_):
      buffer = io.BytesIO(b'')
      buffer.write(
          json.dumps({
              'archive_schema_version': archive_schema_version
          }).encode())
      buffer.seek(0)
      return buffer

    self.mock.open.return_value.open.side_effect = _mock_open

  def _generate_invalid_manifest(self):

    def _mock_open(_):
      buffer = io.BytesIO(b'')
      buffer.write(json.dumps({'my_field': 1}).encode())
      buffer.seek(0)
      return buffer

    self.mock.open.return_value.open.side_effect = _mock_open

  def test_manifest_is_correctly_read(self):
    """Tests that the manifest is correctly read and used to set the archive
    schema version if it exists and that the cases of a missing or invalid
    manifest are handled correctly."""

    # No manifest exists; should default to archive schema version 0 (legacy).
    test_archive = build_archive.ChromeBuildArchive(self.mock.open.return_value)
    self.assertEqual(test_archive.archive_schema_version(), 0)

    # Invalid manifest; should default to version 0.
    self.mock.file_exists.return_value = True
    self._generate_invalid_manifest()
    test_archive = build_archive.ChromeBuildArchive(self.mock.open.return_value)
    self.assertEqual(test_archive.archive_schema_version(), 0)

    # Valid manifest.
    self._generate_manifest(1)
    test_archive = build_archive.ChromeBuildArchive(self.mock.open.return_value)
    self.assertEqual(test_archive.archive_schema_version(), 1)
