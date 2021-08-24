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
"""py_unittest.py runs tests under src/appengine and butler/tests"""

import io
import itertools
import logging
import multiprocessing
import os
import platform
import signal
import sys
import time
import traceback
import unittest

from local.butler import appengine
from local.butler import common
from src.clusterfuzz._internal.config import local_config

APPENGINE_TEST_DIRECTORY = os.path.join('src', 'clusterfuzz', '_internal',
                                        'tests', 'appengine')
CORE_TEST_DIRECTORY = os.path.join('src', 'clusterfuzz', '_internal', 'tests',
                                   'core')
SLOW_TEST_THRESHOLD = 2  # In seconds.
TESTS_TIMEOUT = 20 * 60  # In seconds.


class TrackedTestResult(unittest.TextTestResult):
  """Result object that tracks slow-running tests."""

  def __init__(self, *args, **kwargs):
    super(TrackedTestResult, self).__init__(*args, **kwargs)
    self.slow_tests = []

  def startTest(self, test):
    self._start_time = time.time()
    super(TrackedTestResult, self).startTest(test)

  def addSuccess(self, test):
    elapsed_time = time.time() - self._start_time
    super(TrackedTestResult, self).addSuccess(test)

    if elapsed_time <= SLOW_TEST_THRESHOLD:
      return

    description = self.getDescription(test).splitlines()[0]
    self.slow_tests.append((elapsed_time, description))


class TrackedTestRunner(unittest.TextTestRunner):
  """TextTestRunner wrapper that reports additional information we collect."""

  def __init__(self, *args, **kwargs):
    kwargs['resultclass'] = TrackedTestResult
    super(TrackedTestRunner, self).__init__(*args, **kwargs)

  def run(self, test):
    result = super(TrackedTestRunner, self).run(test)

    if not result.slow_tests:
      return result

    self.stream.writeln('\nSlow tests:')
    for elapsed_time, test_name in sorted(result.slow_tests, reverse=True):
      print('%6.2fs: %s' % (elapsed_time, test_name))

    return result


class TestResult(object):
  """Test results."""

  def __init__(self, output, num_errors, num_failures, num_skipped, total_run):
    self.output = output
    self.num_errors = num_errors
    self.num_failures = num_failures
    self.num_skipped = num_skipped
    self.total_run = total_run


def test_worker_init():
  """Initialise test worker process."""
  if platform.system() != 'Windows':
    # Prevent KeyboardInterrupt error output.
    signal.signal(signal.SIGINT, signal.SIG_IGN)


def run_one_test_parallel(args):
  """Test worker."""
  try:
    os.environ['PARALLEL_TESTS'] = '1'

    test_modules, suppress_output = args
    suite = unittest.loader.TestLoader().loadTestsFromNames(test_modules)

    stream = io.StringIO()

    # Verbosity=0 since we cannot see real-time test execution order when tests
    # are executed in parallel.
    tests = ', '.join(test_modules)
    print('Running', tests)
    result = unittest.TextTestRunner(
        stream=stream, verbosity=0, buffer=suppress_output).run(suite)
    print('Done running', tests)

    stream.flush()
    value = stream.getvalue()

    return TestResult(value, len(result.errors), len(result.failures),
                      len(result.skipped), result.testsRun)
  except BaseException:
    # Print exception traceback here, as it will be lost otherwise.
    traceback.print_exc()
    raise


def run_tests_single_core(args, test_directory, top_level_dir):
  """Run tests (single CPU)."""
  suites = unittest.loader.TestLoader().discover(
      test_directory, pattern=args.pattern, top_level_dir=top_level_dir)

  # TODO(mbarbella): Re-implement code coverage after migrating to Python 3.
  # Verbosity=2 since we want to see real-time test execution with test name
  # and result.
  result = TrackedTestRunner(
      verbosity=2, buffer=(not args.unsuppress_output)).run(suites)

  if result.errors or result.failures:
    sys.exit(1)


def run_tests_parallel(args, test_directory, top_level_dir):
  """Run tests (multiple CPUs)."""
  suites = unittest.loader.TestLoader().discover(
      test_directory, pattern=args.pattern, top_level_dir=top_level_dir)

  test_classes = []  # pylint: disable=protected-access
  for suite in suites:
    for subsuite in suite._tests:  # pylint: disable=protected-access
      # According to:
      # https://github.com/python/cpython/blob/2.7/Lib/unittest/loader.py#L24,
      # this is how we can get a ModuleImportFailure error.
      if subsuite.__class__.__name__ == 'ModuleImportFailure':
        unittest.TextTestRunner(verbosity=1).run(subsuite)
        raise Exception('A failure occurred while importing the module.')

      for test_class in subsuite._tests:  # pylint: disable=protected-access
        test_classes.append((test_class.__module__,
                             test_class.__class__.__name__))
  test_classes = sorted(test_classes)

  test_modules = []
  for module_path, _ in itertools.groupby(test_classes, key=lambda k: k[0]):
    test_modules.append(module_path)
  test_modules = sorted(test_modules)

  cpu_count = multiprocessing.cpu_count()
  pool = multiprocessing.Pool(cpu_count, test_worker_init)

  total_result = TestResult('', 0, 0, 0, 0)

  # partition tests
  test_args = []

  tests_per_cpu = max(1, len(test_modules) // cpu_count)
  for i in range(0, len(test_modules), tests_per_cpu):
    group = test_modules[i:i + tests_per_cpu]
    test_args.append((group, not args.unsuppress_output))

  results = pool.map_async(run_one_test_parallel, test_args)

  while True:
    try:
      # KeyboardInterrupt never gets raised unless we pass a timeout.
      results = results.get(timeout=TESTS_TIMEOUT)
      break
    except KeyboardInterrupt:
      pool.terminate()
      pool.join()
      sys.exit(1)

  pool.close()
  pool.join()

  for result in results:
    if result.num_failures or result.num_errors:
      print(result.output)

    total_result.num_errors += result.num_errors
    total_result.num_failures += result.num_failures
    total_result.num_skipped += result.num_skipped
    total_result.total_run += result.total_run

  print('Ran %d tests (%d skipped, %d errors, %d failures).' %
        (total_result.total_run, total_result.num_skipped,
         total_result.num_errors, total_result.num_failures))

  if total_result.num_errors or total_result.num_failures:
    sys.exit(1)


def execute(args):
  """Run Python unit tests. For unittests involved appengine, sys.path needs
  certain modification."""
  os.environ['PY_UNITTESTS'] = 'True'

  if os.getenv('INTEGRATION') or os.getenv('UNTRUSTED_RUNNER_TESTS'):
    # Set up per-user buckets used by integration tests.
    os.environ['CORPUS_BUCKET'] = common.test_bucket('TEST_CORPUS_BUCKET')
    os.environ['QUARANTINE_BUCKET'] = common.test_bucket(
        'TEST_QUARANTINE_BUCKET')
    os.environ['BACKUP_BUCKET'] = common.test_bucket('TEST_BACKUP_BUCKET')
    os.environ['COVERAGE_BUCKET'] = common.test_bucket('TEST_COVERAGE_BUCKET')

  # Kill leftover instances of emulators and dev appserver.
  common.kill_leftover_emulators()

  # Don't use absolute paths to make it easier to compare results in tests.
  os.environ['CONFIG_DIR_OVERRIDE'] = os.path.join('.', 'configs', 'test')

  top_level_dir = os.path.join('src', 'clusterfuzz', '_internal')
  if args.target == 'appengine':
    # Build template files.
    appengine.build_templates()

    test_directory = APPENGINE_TEST_DIRECTORY
    sys.path.insert(0, os.path.abspath(os.path.join('src', 'appengine')))

    for i, path in enumerate(sys.path):
      if 'third_party' in path:
        # Replace third_party with App Engine third_party/.
        sys.path[i] = os.path.abspath(
            os.path.join('src', 'appengine', 'third_party'))

    if sys.version_info.major == 2:
      # TODO(ochang): Remove once migrated to Python 3.
      appengine_sdk_path = appengine.find_sdk_path()
      sys.path.insert(0, appengine_sdk_path)

      # Get additional App Engine third party imports.
      import dev_appserver
      dev_appserver.fix_google_path()
      sys.path.extend(dev_appserver.EXTRA_PATHS)

      # Loading appengine_main from the current project ensures that any
      # changes to configuration there are available to all tests (e.g.
      # sys.path modifications, namespaces, etc.)
      try:
        from src.appengine import main as appengine_main
        (appengine_main)  # pylint: disable=pointless-statement
      except ImportError:
        print('Note: unable to import appengine_main.')

      # google.auth uses App Engine credentials based on importability of
      # google.appengine.api.app_identity.
      try:
        from google.auth import app_engine as auth_app_engine
        if auth_app_engine.app_identity:
          auth_app_engine.app_identity = None
      except ImportError:
        pass
  elif args.target == 'core':
    test_directory = CORE_TEST_DIRECTORY
  else:
    # Config module tests.
    os.environ['CONFIG_DIR_OVERRIDE'] = args.config_dir
    test_directory = os.path.join(args.config_dir, 'modules')
    top_level_dir = None

    # Modules may use libs from our App Engine directory.
    sys.path.insert(0, os.path.abspath(os.path.join('src', 'appengine')))

    # Fix paths again to get config modules added to the import path.
    from clusterfuzz._internal.base import modules
    modules.fix_module_search_paths()

  # Set expected environment variables.
  local_config.ProjectConfig().set_environment()

  # Needed for NDB to work with cloud datastore emulator.
  os.environ['DATASTORE_USE_PROJECT_ID_AS_APP_ID'] = 'true'

  if args.verbose:
    # Force logging to console for this process and child processes.
    os.environ['LOG_TO_CONSOLE'] = 'True'
  else:
    # Disable logging.
    logging.disable(logging.CRITICAL)

  if args.pattern is None:
    args.pattern = '*_test.py'

  if args.parallel:
    # TODO(tanin): Support coverage.
    run_tests_parallel(args, test_directory, top_level_dir)
  else:
    run_tests_single_core(args, test_directory, top_level_dir)
