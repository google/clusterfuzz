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
_PY_TEST_SUFFIX = '_test.py'
_PY_INIT_FILENAME = '__init__.py'
_YAML_EXCEPTIONS = ['bad.yaml']


def license_validate(file_path):
  """Run license validation for the given source path."""
  filename = os.path.basename(file_path)
  extension = os.path.splitext(file_path)[1]
  if (filename not in _LICENSE_CHECK_FILENAMES and
      extension not in _LICENSE_CHECK_EXTENSIONS):
    return

  path_directories = file_path.split(os.sep)
  for directory in _LICENSE_CHECK_IGNORE_DIRECTORIES:
    if directory in path_directories:
      return

  source_filename = os.path.basename(file_path)
  for check_filename in _LICENSE_CHECK_IGNORE_FILENAMES:
    if check_filename == source_filename:
      return

  if _LICENSE_CHECK_STRING in open(file_path).read():
    return

  print 'Missing license header for %s.' % file_path
  sys.exit(1)


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

  def _validate_imports(data):
    """Test that a file's contents are ordered properly."""
    imports = []
    from_imports = []
    corrected_import_blocks = []
    for line in data.splitlines():
      if line.startswith('import '):
        imports.append(line)
      else:
        corrected_import_blocks += _validate_block(imports)
        imports = []

      if line.startswith('from '):
        from_imports.append(line)
      else:
        corrected_import_blocks += _validate_block(from_imports)
        from_imports = []

    # Though rare, if a file ends with an import we must still validate them.
    corrected_import_blocks += _validate_block(imports)
    corrected_import_blocks += _validate_block(from_imports)

    if not corrected_import_blocks:
      return

    suggestions = '\n\n--------\n\n'.join(corrected_import_blocks)
    print('File {filename} has non-alphabetized import blocks. '
          'Suggested order:\n\n{suggestions}').format(
              filename=file_path, suggestions=suggestions)
    sys.exit(1)

  with open(file_path) as handle:
    _validate_imports(handle.read())


def py_test_init_check(file_path):
  """Check test directory has a __init__.py file. Otherwise, the test does not
  execute at all."""
  if not file_path.endswith(_PY_TEST_SUFFIX):
    return

  test_directory = os.path.dirname(file_path)
  if _PY_INIT_FILENAME not in os.listdir(test_directory):
    print 'Missing {filename} file in test directory {dir}.'.format(
        filename=_PY_INIT_FILENAME, dir=test_directory)
    sys.exit(1)


def yaml_validate(file_path):
  """Run yaml validation for the given source path."""
  if os.path.basename(file_path) in _YAML_EXCEPTIONS:
    return

  try:
    with open(file_path) as handle:
      yaml.safe_load(handle.read())
  except Exception as e:
    print 'Failed yaml validation for %s.\n\n%s' % (file_path, e)
    sys.exit(1)


def execute(_):
  """Lint changed code."""
  pythonpath = os.getenv('PYTHONPATH', '')
  os.environ['PYTHONPATH'] = appengine.find_sdk_path() + ':' + pythonpath

  if 'GOOGLE_CLOUDBUILD' in os.environ:
    # Explicitly compare against master if we're running on the CI
    _, output = common.execute('git diff --name-only master FETCH_HEAD')
  elif 'TRAVIS_BRANCH' in os.environ:
    _, output = common.execute(
        'git diff --name-only HEAD $(git merge-base HEAD FETCH_HEAD)')
  else:
    _, output = common.execute('git diff --name-only FETCH_HEAD')

  file_paths = [f for f in output.splitlines() if os.path.exists(f)]
  py_changed_file_paths = [
      f for f in file_paths if f.endswith('.py') and
      # Exclude auto-generated files.
      not f.endswith('_pb2.py') and not f.endswith('_pb2_grpc.py')
  ]
  go_changed_file_paths = [f for f in file_paths if f.endswith('.go')]
  yaml_changed_file_paths = [f for f in file_paths if f.endswith('.yaml')]

  for file_path in py_changed_file_paths:
    common.execute('pylint ' + file_path)
    common.execute('yapf -d ' + file_path)
    py_import_order(file_path)
    py_test_init_check(file_path)

  golint_path = os.path.join('local', 'bin', 'golint')
  for file_path in go_changed_file_paths:
    if not os.path.basename(file_path) in _GOLINT_EXCEPTIONS:
      common.execute(golint_path + ' ' + file_path)

    _, output = common.execute('gofmt -d ' + file_path)
    if output.strip():
      sys.exit(1)

  for file_path in yaml_changed_file_paths:
    yaml_validate(file_path)

  for file_path in file_paths:
    license_validate(file_path)
