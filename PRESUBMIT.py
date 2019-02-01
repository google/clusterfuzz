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
"""Presubmit script."""

import fnmatch
import os
import platform
import subprocess
import threading
import yaml

from distutils import spawn

GOLINT_EXCEPTIONS = [
    'types.go'  # Not all model names conform to Go naming conventions.
]

PY_TEST_SUFFIX = '_test.py'
PY_INIT_FILENAME = '__init__.py'

LICENSE_CHECK_FILENAMES = [
    'Dockerfile',
]
LICENSE_CHECK_EXTENSIONS = [
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
LICENSE_CHECK_STRING = 'http://www.apache.org/licenses/LICENSE-2.0'

LICENSE_CHECK_IGNORE_FILENAMES = [
    'technology.css',
]
LICENSE_CHECK_IGNORE_DIRECTORIES = [
    'third_party',
    'templates',  # Generated code.
]


def _run_checker(output_api, files, check_func):
  """Runs check on given files."""
  result = []
  for current_file in files:
    absolute_path = current_file.AbsoluteLocalPath()
    if not os.path.exists(absolute_path):
      # Removed in CL.
      continue

    if (absolute_path.endswith('_pb2.py') or
        absolute_path.endswith('_pb2_grpc.py')):
      # Auto-generated.
      continue

    check_result = check_func(absolute_path)
    if check_result:
      result.append(
          output_api.PresubmitPromptWarning(
              'Failed check for ' + absolute_path, long_text=check_result))

  return result


def _has_affected_file(input_api, filename):
  """Check if a file was affected."""
  return any(
      os.path.basename(affected.LocalPath()) == filename
      for affected in input_api.change.AffectedFiles())


def _check_data_types(input_api, output_api):
  """Check that if data_types.py is modified, we've run
  generate_datastore_models.py."""
  if not _has_affected_file(input_api, 'data_types.py'):
    return []

  if _has_affected_file(input_api, 'types.go'):
    return []

  return [
      output_api.PresubmitPromptWarning(
          'data_types.py was changed, but types.go was not. '
          'You may need to run '
          '`python butler.py generate_datastore_models`')
  ]


def CheckChangeOnUpload(input_api, output_api):  # pylint: disable=invalid-name
  """CL upload presubmit."""
  # Only Linux is supported.
  if platform.system() != 'Linux':
    return []

  result = []
  all_files = input_api.change.AffectedFiles()
  affected_py_files = [
      py_file for py_file in all_files
      if py_file.AbsoluteLocalPath().endswith('.py')
  ]
  result.extend(_run_checker(output_api, affected_py_files, py_test_check))
  result.extend(_run_checker(output_api, affected_py_files, py_lint))
  result.extend(_run_checker(output_api, affected_py_files, py_format))
  result.extend(_run_checker(output_api, affected_py_files, py_import_order))

  affected_go_files = [
      go_file for go_file in all_files
      if go_file.AbsoluteLocalPath().endswith('.go')
  ]
  result.extend(_run_checker(output_api, affected_go_files, go_lint))

  affected_yaml_files = [
      yaml_file for yaml_file in all_files
      if yaml_file.AbsoluteLocalPath().endswith('.yaml')
  ]
  result.extend(_run_checker(output_api, affected_yaml_files, yaml_validate))

  result.extend(_run_checker(output_api, all_files, license_validate))

  if result:
    return result

  print 'All files passed presubmit checks.'
  print 'Running tests ...'
  return_code, test_output = run_tests()
  if return_code != 0:
    result.append(
        output_api.PresubmitPromptWarning(
            'Failed tests:', long_text=test_output))

  result.extend(_check_data_types(input_api, output_api))
  return result


def CheckChangeOnCommit(input_api, output_api):  # pylint: disable=invalid-name
  """Commit presubmit."""
  return CheckChangeOnUpload(input_api, output_api)


def py_lint(python_source_path):
  """Run pylint for the given source path."""
  try:
    subprocess.check_output([
        'pylint',
        python_source_path,
    ])
  except subprocess.CalledProcessError as e:
    return 'Failed pylint for %s.\n\n%s' % (python_source_path, e.output)

  return None


def py_format(python_source_path):
  """Run yapf for the given source path."""
  try:
    subprocess.check_output([
        'yapf',
        '-d',
        python_source_path,
    ])
  except subprocess.CalledProcessError as e:
    return 'Failed yapf for %s.\n\n%s' % (python_source_path, e.output)

  return None


def py_test_check(python_source_path):
  """Checks test directory has a __init__.py file. Otherwise, the test does not
  execute at all."""
  if not python_source_path.endswith(PY_TEST_SUFFIX):
    return None

  test_directory = os.path.dirname(python_source_path)
  if PY_INIT_FILENAME not in os.listdir(test_directory):
    return 'Missing {filename} file in test directory {dir}.'.format(
        filename=PY_INIT_FILENAME, dir=test_directory)

  return None


def py_import_order(python_source_path):
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
      return None

    suggestions = '\n\n--------\n\n'.join(corrected_import_blocks)
    return ('File {filename} has non-alphabetized import blocks. '
            'Suggested order:\n\n{suggestions}').format(
                filename=python_source_path, suggestions=suggestions)

  with open(python_source_path) as handle:
    return _validate_imports(handle.read())

  return None


def go_lint(source_path):
  """Run golint for the given source path."""
  if os.path.basename(source_path) in GOLINT_EXCEPTIONS:
    return ''

  golint_path = os.path.join('local', 'bin', 'golint')
  assert os.path.exists(golint_path)

  try:
    return subprocess.check_output([golint_path, source_path])
  except subprocess.CalledProcessError as e:
    return 'Failed golint for %s.\n\n%s' % (source_path, e.output)


def yaml_validate(source_path):
  """Run yaml validation for the given source path."""
  exceptions = [
      'bad.yaml',
  ]
  if os.path.basename(source_path) in exceptions:
    return ''

  try:
    yaml.safe_load(open(source_path).read())
    return ''
  except Exception as e:
    return 'Failed yaml validation for %s.\n\n%s' % (source_path, e.output)


def license_validate(source_path):
  """Run yaml validation for the given source path."""
  filename = os.path.basename(source_path)
  extension = os.path.splitext(source_path)[1]
  if (filename not in LICENSE_CHECK_FILENAMES and
      extension not in LICENSE_CHECK_EXTENSIONS):
    return ''

  path_directories = source_path.split(os.sep)
  for directory in LICENSE_CHECK_IGNORE_DIRECTORIES:
    if directory in path_directories:
      return ''

  source_filename = os.path.basename(source_path)
  for check_filename in LICENSE_CHECK_IGNORE_FILENAMES:
    if check_filename == source_filename:
      return ''

  if LICENSE_CHECK_STRING in open(source_path).read():
    return ''

  return 'Missing license header for %s.' % source_path


def remove_pycs():
  """Remove all *.pyc because they can be stale."""
  for root, _, filenames in os.walk('.'):
    for filename in fnmatch.filter(filenames, '*.pyc'):
      os.remove(os.path.join(root, filename))


def execute_cmd(cmd, environments, cwd=None):
  """Execute command."""
  proc = subprocess.Popen(
      cmd,
      shell=True,
      stdout=subprocess.PIPE,
      stderr=subprocess.STDOUT,
      env=environments,
      cwd=cwd)
  return proc


def read_thread(proc, lines):
  """Read output from process."""
  while True:
    line = proc.stdout.readline()
    if not line:
      break

    lines.append(line)


def wait_proc_and_get_result(proc):
  """Wait and get result."""
  lines = []
  reader = threading.Thread(target=read_thread, args=(proc, lines))
  reader.daemon = True
  reader.start()
  proc.wait()
  reader.join()

  return proc.returncode, ''.join(lines)


def run_tests():
  """Run Go, Python and Javascript tests."""
  tests = [
      run_js_tests,
      lambda: run_py_tests('appengine'),
      lambda: run_py_tests('core'),
      run_go_tests,
  ]

  return_code = 0
  output = ''

  for test in tests:
    proc = test()
    proc_code, proc_output = wait_proc_and_get_result(proc)
    if proc_code != 0:
      return_code = 1
      output += proc_output

  return return_code, output


def run_js_tests():
  """Run Javascript tests."""
  has_xvfb = spawn.find_executable('xvfb-run')
  return execute_cmd(
      '%s python butler.py js_unittest' % ('xvfb-run' if has_xvfb else ''),
      os.environ.copy())


def run_py_tests(target):
  """Run Python tests."""
  remove_pycs()
  environments = os.environ.copy()
  environments.update({'INTEGRATION': '1', 'SLOW_TESTS': '0'})

  return execute_cmd(
      'python butler.py py_unittest --target {target} '
      '--parallel'.format(target=target),
      environments)


def run_go_tests():
  """Run Go tests."""
  return execute_cmd('python butler.py go_unittest', os.environ.copy())
