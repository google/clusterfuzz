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
"""Lint changed code in current branch."""

import os
import sys

import yaml

from local.butler import appengine
from local.butler import common
from local.butler import format as formatter

_GOLINT_EXCEPTIONS = [
    'types.go'  # Not all model names conform to Go naming conventions.
]
_LICENSE_CHECK_FILENAMES = ['Dockerfile']
_LICENSE_CHECK_EXTENSIONS = [
    '.bash',
    '.c',
    '.cc',
    '.cpp',
    '.css',
    '.h',
    '.htm',
    '.html',
    '.js',
    '.go',
    '.proto',
    '.ps1',
    '.py',
    '.sh',
    '.yaml',
]
_LICENSE_CHECK_IGNORE_FILENAMES = ['technology.css']
_LICENSE_CHECK_IGNORE_DIRECTORIES = [
    'third_party',
    'templates',  # Generated code.
]
_LICENSE_CHECK_STRING = 'http://www.apache.org/licenses/LICENSE-2.0'
_LICENSE_CHECK_IGNORE = 'LICENSE_CHECK_IGNORE'
_PY_TEST_SUFFIX = '_test.py'
_PY_INIT_FILENAME = '__init__.py'
_YAML_EXCEPTIONS = ['bad.yaml']

_error_occurred = False


def _error(message=None):
  """Print error and track state via a global."""
  if message:
    print(message)

  global _error_occurred
  _error_occurred = True


def _execute_command_and_track_error(command):
  """Executes command, tracks error state."""
  returncode, output = common.execute(command, exit_on_error=False)
  if returncode != 0:
    _error()

  return output.decode('utf-8')


def license_validate(file_path):
  """Run license header validation."""
  filename = os.path.basename(file_path)
  extension = os.path.splitext(file_path)[1]
  if (filename not in _LICENSE_CHECK_FILENAMES and
      extension not in _LICENSE_CHECK_EXTENSIONS):
    return

  path_directories = file_path.split(os.sep)
  if any(d in _LICENSE_CHECK_IGNORE_DIRECTORIES for d in path_directories):
    return

  source_filename = os.path.basename(file_path)
  if source_filename in _LICENSE_CHECK_IGNORE_FILENAMES:
    return

  with open(file_path) as f:
    data = f.read()
    if _LICENSE_CHECK_STRING in data or _LICENSE_CHECK_IGNORE in data:
      return

  _error('Failed: Missing license header for %s.' % file_path)


def py_import_order(file_path):
  """Validate that python imports are alphabetized."""

  def _validate_block(import_block):
    """Ensure that a single block is ordered properly."""
    if not import_block:
      return []

    sorted_import_block = sorted(import_block, key=lambda i: i.lower())
    if sorted_import_block == import_block:
      return []

    return ['\n'.join(sorted_import_block)]

  with open(file_path) as f:
    file_content = f.read()

  imports = []
  corrected_import_blocks = []
  for line in file_content.splitlines():
    if line.startswith('import ') or line.startswith('from '):
      imports.append(line)
    else:
      corrected_import_blocks += _validate_block(imports)
      imports = []

  # Though rare, if a file ends with an import we must still validate them.
  corrected_import_blocks += _validate_block(imports)

  if not corrected_import_blocks:
    return

  suggestions = '\n\n--------\n\n'.join(corrected_import_blocks)
  _error(('Failed: File {filename} has non-alphabetized import blocks. '
          'Suggested order:\n\n{suggestions}').format(
              filename=file_path, suggestions=suggestions))


def py_test_init_check(file_path):
  """Check test directory has a __init__.py file. Otherwise, the test does not
  execute at all."""
  if not file_path.endswith(_PY_TEST_SUFFIX):
    return

  test_directory = os.path.dirname(file_path)
  if _PY_INIT_FILENAME not in os.listdir(test_directory):
    _error(f'Failed: Missing {_PY_INIT_FILENAME} file in test '
           f'directory {test_directory}.')


def yaml_validate(file_path):
  """Run yaml validation."""
  if os.path.basename(file_path) in _YAML_EXCEPTIONS:
    return

  try:
    with open(file_path) as f:
      yaml.safe_load(f.read())
  except Exception as e:
    _error('Failed: Invalid yaml file %s.\n\n%s' % (file_path, e))


def is_auto_generated_file(filepath):
  """Check if file is auto-generated so we dont lint it"""
  return (filepath.endswith('_pb2.py') or filepath.endswith('pb2_grpc.py') or
          os.path.dirname(filepath) == os.path.join(
              'src', 'clusterfuzz', '_internal', 'bot', 'tokenizer',
              'grammars'))


def seperate_python_tests(python_files):
  """Returns a tuple containing a list of python tests and a list of python
  non-tests in |python_files|."""
  nontests = []
  tests = []
  for file_path in python_files:
    if '_test.py' in file_path:
      tests.append(file_path)
    else:
      nontests.append(file_path)

  return tests, nontests


def execute(_):
  """Lint changed code."""
  pythonpath = os.getenv('PYTHONPATH', '')
  os.environ['PYTHONPATH'] = appengine.find_sdk_path() + ':' + pythonpath

  if 'GOOGLE_CLOUDBUILD' in os.environ:
    # Explicitly compare against master if we're running on the CI
    _, output = common.execute('git diff --name-only master FETCH_HEAD')
  else:
    _, output = common.execute('git diff --name-only FETCH_HEAD')

  file_paths = [
      f.decode('utf-8') for f in output.splitlines() if os.path.exists(f)
  ]

  py_changed_tests = []
  py_changed_nontests = []
  go_changed_file_paths = []
  yaml_changed_file_paths = []
  for file_path in file_paths:
    if file_path.endswith('.go'):
      go_changed_file_paths.append(file_path)
      continue
    if file_path.endswith('.yaml'):
      yaml_changed_file_paths.append(file_path)
      continue
    if not file_path.endswith('.py') or is_auto_generated_file(file_path):
      continue
    if file_path.endswith('_test.py'):
      py_changed_tests.append(file_path)
    else:
      py_changed_nontests.append(file_path)

  # Use --score no to make output less noisy.
  base_pylint_cmd = 'pylint --score=no --jobs=0'
  # Test for existence of files before running tools to avoid errors from
  # misusing the tools.
  if py_changed_nontests:
    _execute_command_and_track_error(
        f'{base_pylint_cmd} {" ".join(py_changed_nontests)}')
  if py_changed_tests:
    _execute_command_and_track_error(
        f'{base_pylint_cmd} --max-line-length=240 {" ".join(py_changed_tests)}')

  py_changed_file_paths = py_changed_nontests + py_changed_tests
  if py_changed_file_paths:
    _execute_command_and_track_error(
        f'yapf -p -d {" ".join(py_changed_file_paths)}')
    _execute_command_and_track_error(f'{formatter.ISORT_CMD} -c '
                                     f'{" ".join(py_changed_file_paths)}')

  for file_path in py_changed_file_paths:
    py_test_init_check(file_path)

  go_changed_file_paths = [f for f in file_paths if f.endswith('.go')]
  golint_path = os.path.join('local', 'bin', 'golint')
  for file_path in go_changed_file_paths:
    if not os.path.basename(file_path) in _GOLINT_EXCEPTIONS:
      _execute_command_and_track_error(golint_path + ' ' + file_path)

    output = _execute_command_and_track_error('gofmt -d ' + file_path)
    if output.strip():
      _error()

  yaml_changed_file_paths = [f for f in file_paths if f.endswith('.yaml')]
  for file_path in yaml_changed_file_paths:
    yaml_validate(file_path)

  for file_path in file_paths:
    license_validate(file_path)

  if _error_occurred:
    print('Linting failed, see errors above.')
    sys.exit(1)
  else:
    print('Linting passed.')
