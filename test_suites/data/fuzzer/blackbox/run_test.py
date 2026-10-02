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
"""Tests for the fake blackbox fuzzer (run.py)."""

import os
import subprocess
import sys

import pytest

FUZZER_UNDER_TEST = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), 'run.py')


@pytest.fixture(autouse=True)
def _clear_fuzzer_env(monkeypatch: pytest.MonkeyPatch) -> None:
  """Keeps the caller's FAILING_CASES / UNIQUE_CRASHES out of the tests."""
  monkeypatch.delenv('FAILING_CASES', raising=False)
  monkeypatch.delenv('UNIQUE_CRASHES', raising=False)


def _generate_testcases(
    output_dir: os.PathLike[str] | str,
    no_of_files: int,
    extra_args: list[str] | None = None) -> subprocess.CompletedProcess[str]:
  """Runs the fuzzer the way fuzz_task.py does (`--flag=value`)."""
  command = [
      sys.executable, FUZZER_UNDER_TEST, '--input_dir=',
      f'--output_dir={output_dir}', f'--no_of_files={no_of_files}'
  ]
  command.extend(extra_args or [])
  return subprocess.run(command, capture_output=True, text=True, check=True)


def _run_testcase(
    path: os.PathLike[str] | str) -> subprocess.CompletedProcess[str]:
  """Runs the testcase with Python and returns the CompletedProcess."""
  return subprocess.run(
      [sys.executable, path], capture_output=True, text=True, check=False)


def _assert_python_crash(result: subprocess.CompletedProcess[str]) -> None:
  """Asserts |result| is a crash with the expected exception type."""
  assert result.returncode != 0
  assert 'RuntimeError' in result.stderr


def test_all_successfull_by_default(tmp_path):
  """Without failing_cases, all testcases are `fuzz-` prefixed and exit with
  0."""
  _generate_testcases(tmp_path, 3)

  assert sorted(os.listdir(tmp_path)) == ['fuzz-0.py', 'fuzz-1.py', 'fuzz-2.py']
  for testcase in sorted(os.listdir(tmp_path)):
    assert _run_testcase(os.path.join(tmp_path, testcase)).returncode == 0


@pytest.mark.parametrize('source', ['cli', 'env'])
def test_failing_cases(tmp_path, monkeypatch, source):
  """failing_cases=2 of 4 makes the first 2 testcases exit with 1 and the last
  2 with 0, set via --failing_cases or FAILING_CASES."""
  if source == 'cli':
    result = _generate_testcases(tmp_path, 4, extra_args=['--failing_cases=2'])
  else:
    monkeypatch.setenv('FAILING_CASES', '2')
    result = _generate_testcases(tmp_path, 4)

  assert '(2 failing, 2 successfull)' in result.stdout
  return_codes = [
      _run_testcase(os.path.join(tmp_path, testcase)).returncode
      for testcase in sorted(os.listdir(tmp_path))
  ]
  assert return_codes == [1, 1, 0, 0]


def test_cli_overrides_env(tmp_path, monkeypatch):
  """--failing_cases=0 wins over FAILING_CASES=2: all testcases exit with 0."""
  monkeypatch.setenv('FAILING_CASES', '2')
  _generate_testcases(tmp_path, 2, extra_args=['--failing_cases=0'])

  for testcase in sorted(os.listdir(tmp_path)):
    assert _run_testcase(os.path.join(tmp_path, testcase)).returncode == 0


def test_failing_cases_clamped(tmp_path):
  """failing_cases greater than no_of_files is clamped: 5 of 2 gives 2
  failing, 0 successfull."""
  result = _generate_testcases(tmp_path, 2, extra_args=['--failing_cases=5'])

  assert '(2 failing, 0 successfull)' in result.stdout


def test_failing_testcase_output_is_python_crash(tmp_path):
  """A failing testcase emits a RuntimeError crash."""
  _generate_testcases(tmp_path, 1, extra_args=['--failing_cases=1'])

  result = _run_testcase(os.path.join(tmp_path, 'fuzz-0.py'))

  _assert_python_crash(result)


@pytest.mark.parametrize('source', ['cli', 'env'])
def test_unique_crashes(tmp_path, monkeypatch, source):
  """unique_crashes with failing_cases=2 of 3 makes the first 2 testcases
  crash and the last exit with 0, set via CLI or env."""
  if source == 'cli':
    result = _generate_testcases(
        tmp_path, 3, extra_args=['--unique_crashes', '--failing_cases=2'])
  else:
    monkeypatch.setenv('UNIQUE_CRASHES', 'True')
    monkeypatch.setenv('FAILING_CASES', '2')
    result = _generate_testcases(tmp_path, 3)

  assert '(2 failing, 1 successfull, unique crash states)' in result.stdout
  testcases = sorted(os.listdir(tmp_path))
  for testcase in testcases[:2]:
    testcase_result = _run_testcase(os.path.join(tmp_path, testcase))
    _assert_python_crash(testcase_result)
  assert _run_testcase(os.path.join(tmp_path, testcases[2])).returncode == 0


def test_unique_crashes_without_failing_cases_is_noop(tmp_path):
  """--unique_crashes alone produces no failing testcases: all exit with
  0."""
  result = _generate_testcases(tmp_path, 2, extra_args=['--unique_crashes'])

  assert '(0 failing, 2 successfull)' in result.stdout
  for testcase in sorted(os.listdir(tmp_path)):
    assert _run_testcase(os.path.join(tmp_path, testcase)).returncode == 0


@pytest.mark.parametrize('value', ['False', 'true', '1'])
def test_unique_crashes_env_requires_true(tmp_path, monkeypatch, value):
  """UNIQUE_CRASHES values other than exactly 'True' are ignored: the
  failing testcase crashes with RuntimeError."""
  monkeypatch.setenv('UNIQUE_CRASHES', value)
  monkeypatch.setenv('FAILING_CASES', '1')
  _generate_testcases(tmp_path, 1)

  result = _run_testcase(os.path.join(tmp_path, 'fuzz-0.py'))
  _assert_python_crash(result)
