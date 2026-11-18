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
"""Tests for the coverage-guided fuzz targets in test_suites/data/fuzzer."""

import os
import pathlib
import subprocess
import sys

import pytest

CLUSTERFUZZ_DIR = pathlib.Path(__file__).resolve().parents[4]
SRC_DIR = CLUSTERFUZZ_DIR / 'src'

REPRODUCIBLE_CRASH_THRESHOLD = 5
UNREPRODUCIBLE_CRASH_THRESHOLD = 105
NULL_DEREF_ERROR = (
    'ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000')


class TestCoverageGuidedFuzzers:
  """Tests for the coverage-guided fuzz targets."""

  arch: str
  max_amount_of_runs_needed_to_reproduce: int

  # TODO(b/555371391) Remove this setup once we have our own butler.py command
  @pytest.fixture(scope='class', autouse=True)
  @classmethod
  def _setup(cls):
    """Adds ClusterFuzz's src directory to sys.path and loads host constants."""
    for path in (str(SRC_DIR), str(SRC_DIR / 'third_party')):
      if path not in sys.path:
        sys.path.insert(0, path)

    from clusterfuzz._internal.bot.fuzzers.libFuzzer import constants
    from clusterfuzz._internal.system import environment

    cls.arch = environment.get_host_cpu_arch()
    cls.max_amount_of_runs_needed_to_reproduce = constants.RUNS_TO_REPRODUCE

  def _fuzzer_path(self, case_name: str) -> pathlib.Path:
    """Returns the compiled fuzzer binary path for |case_name|."""
    return (CLUSTERFUZZ_DIR / 'test_suites' / 'data' / 'fuzzer' /
            'coverage_guided' / case_name / self.arch / f'{case_name}_fuzzer')

  def _run_fuzzer(
      self,
      case_name: str,
      runs: int,
      artifact_dir: os.PathLike[str] | str | None = None,
      testcase_path: os.PathLike[str] | str | None = None,
  ) -> subprocess.CompletedProcess[str]:
    """Runs the fuzzer for |case_name|."""
    command = [str(self._fuzzer_path(case_name)), f'-runs={runs}']
    if artifact_dir is not None:
      command.append(f'-artifact_prefix={artifact_dir}{os.sep}')
    if testcase_path is not None:
      command.append(str(testcase_path))
    return subprocess.run(
        command, capture_output=True, text=True, check=False, timeout=120)

  def _get_crash_testcases(self,
                           artifact_dir: os.PathLike[str] | str) -> list[str]:
    """Returns the sorted paths of crash-* testcases in |artifact_dir|."""
    return [
        os.path.join(artifact_dir, testcase)
        for testcase in sorted(os.listdir(artifact_dir))
        if testcase.startswith('crash-')
    ]

  def test_clean_fuzzer_never_crashes(self, tmp_path):
    """Verifies that clean_fuzzer completes a fuzzing session without crashing
    or writing any crash-* testcase files."""
    result = self._run_fuzzer('clean', runs=100, artifact_dir=tmp_path)

    assert result.returncode == 0, result.stderr
    assert not self._get_crash_testcases(tmp_path)

  def test_reproducible_crash_fuzzer_crashes_during_fuzzing(self, tmp_path):
    """Verifies that reproducible_crash_fuzzer crashes with a null-pointer
    dereference during a fuzzing session and writes a crash-* testcase."""
    fuzz_result = self._run_fuzzer(
        'reproducible_crash', runs=500, artifact_dir=tmp_path)

    assert fuzz_result.returncode != 0
    assert NULL_DEREF_ERROR in fuzz_result.stderr
    assert len(self._get_crash_testcases(tmp_path)) == 1

  def test_reproducible_crash_fuzzer_reproduces_crash(self, tmp_path):
    """Verifies that reproducible_crash_fuzzer crashes again when ClusterFuzz
    re-runs a non-empty testcase for RUNS_TO_REPRODUCE iterations."""
    assert (REPRODUCIBLE_CRASH_THRESHOLD <=
            self.max_amount_of_runs_needed_to_reproduce)
    testcase = tmp_path / 'testcase'
    testcase.write_bytes(b'A')

    repro_result = self._run_fuzzer(
        'reproducible_crash',
        runs=self.max_amount_of_runs_needed_to_reproduce,
        testcase_path=testcase)

    assert repro_result.returncode != 0
    assert NULL_DEREF_ERROR in repro_result.stderr

  def test_reproducible_crash_fuzzer_does_not_crash_before_threshold(
      self, tmp_path):
    """Verifies that reproducible_crash_fuzzer does not crash on the first
    input & exits cleanly when executed for fewer iterations than
    REPRODUCIBLE_CRASH_THRESHOLD."""
    result = self._run_fuzzer(
        'reproducible_crash',
        runs=REPRODUCIBLE_CRASH_THRESHOLD - 1,
        artifact_dir=tmp_path)

    assert result.returncode == 0, result.stderr
    assert not self._get_crash_testcases(tmp_path)

  def test_unreproducible_crash_fuzzer_crashes_during_fuzzing(self, tmp_path):
    """Verifies that unreproducible_crash_fuzzer crashes with a null-pointer
    dereference during a fuzzing session and writes a crash-* testcase."""
    fuzz_result = self._run_fuzzer(
        'unreproducible_crash', runs=500, artifact_dir=tmp_path)

    assert fuzz_result.returncode != 0
    assert NULL_DEREF_ERROR in fuzz_result.stderr
    assert len(self._get_crash_testcases(tmp_path)) == 1

  def test_unreproducible_crash_fuzzer_does_not_reproduce_crash(self, tmp_path):
    """Verifies that unreproducible_crash_fuzzer exits cleanly without crashing
    when ClusterFuzz re-runs a testcase for RUNS_TO_REPRODUCE iterations."""
    error_message = (f'Expected RUNS_TO_REPRODUCE '
                     f'({self.max_amount_of_runs_needed_to_reproduce}) < '
                     f'{UNREPRODUCIBLE_CRASH_THRESHOLD} so '
                     'unreproducible_crash_fuzzer does not reproduce.')
    assert (self.max_amount_of_runs_needed_to_reproduce <
            UNREPRODUCIBLE_CRASH_THRESHOLD), error_message
    testcase = tmp_path / 'testcase'
    testcase.write_bytes(b'A')

    repro_result = self._run_fuzzer(
        'unreproducible_crash',
        runs=self.max_amount_of_runs_needed_to_reproduce,
        testcase_path=testcase)

    assert repro_result.returncode == 0, repro_result.stderr
