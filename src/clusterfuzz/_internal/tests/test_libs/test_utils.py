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
"""Generic helper functions useful in tests."""

import atexit
import datetime
import io
import os
import shutil
import socket
import subprocess
import tempfile
import threading
import unittest

import requests
import six

from clusterfuzz._internal.config import local_config
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import ndb_init
from clusterfuzz._internal.google_cloud_utils import pubsub
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.system import process_handler

CURRENT_TIME = datetime.datetime.utcnow()
EMULATOR_TIMEOUT = 20

# Per-process emulator instances.
_emulators = {}


def create_generic_testcase(created_days_ago=28):
  """Create a simple test case."""
  testcase = data_types.Testcase()

  # Add more values here as needed. Intended to be the bare minimum for what we
  # need to simulate a test case.
  testcase.absolute_path = '/a/b/c/test.html'
  testcase.crash_address = '0xdeadbeef'
  testcase.crash_revision = 1
  testcase.crash_state = 'crashy_function()'
  testcase.crash_stacktrace = testcase.crash_state
  testcase.crash_type = 'fake type'
  testcase.comments = 'Fuzzer: test'
  testcase.fuzzed_keys = 'abcd'
  testcase.minimized_keys = 'efgh'
  testcase.fuzzer_name = 'fuzzer1'
  testcase.open = True
  testcase.one_time_crasher_flag = False
  testcase.job_type = 'test_content_shell_drt'
  testcase.status = 'Processed'
  testcase.timestamp = CURRENT_TIME - datetime.timedelta(days=created_days_ago)
  testcase.project_name = 'project'
  testcase.platform = 'linux'
  testcase.put()

  return testcase


def entities_equal(entity_1, entity_2, check_key=True):
  """Return a bool on whether two input entities are the same."""
  if check_key:
    return entity_1.key == entity_2.key

  return entity_1.to_dict() == entity_2.to_dict()


def entity_exists(entity):
  """Return a bool on where the entity exists in datastore."""
  return entity.get_by_id(entity.key.id())


def adhoc(func):
  """Mark the testcase as an adhoc. Adhoc tests are NOT expected to run before
    merging and are NOT counted toward test coverage; they are used to test
    tricky situations.

    Another way to think about it is that, if there was no adhoc test, we
    would write a Python script (which is not checked in) to test what we want
    anyway... so, it's better to check in the script.

    For example, downloading a chrome revision (10GB) and
    unpacking it. It can be enabled using the env ADHOC=1."""
  return unittest.skipIf(not environment.get_value('ADHOC', False),
                         'Adhoc tests are not enabled.')(
                             func)


def integration(func):
  """Mark the testcase as integration because it depends on network resources
    and/or is slow. The integration tests should, at least, be run before
    merging and are counted toward test coverage. It can be enabled using the
    env INTEGRATION=1."""
  return unittest.skipIf(not environment.get_value('INTEGRATION', False),
                         'Integration tests are not enabled.')(
                             func)


def slow(func):
  """Slow tests which are skipped during presubmit."""
  return unittest.skipIf(not environment.get_value('SLOW_TESTS', True),
                         'Skipping slow tests.')(
                             func)


def reproduce_tool(func):
  """Tests for the test case reproduction script."""
  return unittest.skipIf(
      not environment.get_value('REPRODUCE_TOOL_TESTS', False),
      'Skipping reproduce tool tests.')(
          func)


def android_device_required(func):
  """Skip Android-specific tests if we cannot run them."""
  reason = None
  if not environment.get_value('ANDROID_SERIAL'):
    reason = 'Android device tests require that ANDROID_SERIAL is set.'
  elif not environment.get_value('INTEGRATION'):
    reason = 'Integration tests are not enabled.'
  elif environment.platform() != 'LINUX':
    reason = 'Android device tests can only run on a Linux host.'

  return unittest.skipIf(reason is not None, reason)(func)


class EmulatorInstance(object):
  """Emulator instance."""

  def __init__(self, proc, port, read_thread, data_dir):
    self._proc = proc
    self._port = port
    self._read_thread = read_thread
    self._data_dir = data_dir

  def cleanup(self):
    """Stop and clean up the emulator."""
    process_handler.terminate_root_and_child_processes(self._proc.pid)
    self._read_thread.join()
    if self._data_dir:
      shutil.rmtree(self._data_dir, ignore_errors=True)

  def reset(self):
    """Reset emulator state."""
    req = requests.post('http://localhost:{}/reset'.format(self._port))
    req.raise_for_status()


def _find_free_port():
  """Find a free port."""
  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  sock.bind(('localhost', 0))
  _, port = sock.getsockname()
  sock.close()

  return port


def wait_for_emulator_ready(proc,
                            emulator,
                            indicator,
                            timeout=EMULATOR_TIMEOUT,
                            output_lines=None):
  """Wait for emulator to be ready."""
  if output_lines is None:
    output_lines = []

  def _read_thread(proc, ready_event):
    """Thread to continuously read from the process stdout."""
    ready = False
    while True:
      line = proc.stdout.readline()
      if not line:
        break

      if output_lines is not None:
        output_lines.append(line)

      if not ready and indicator in line:
        ready = True
        ready_event.set()

  # Wait for process to become ready.
  ready_event = threading.Event()
  thread = threading.Thread(target=_read_thread, args=(proc, ready_event))
  thread.daemon = True
  thread.start()

  if not ready_event.wait(timeout):
    output = b'\n'.join(output_lines).decode()
    raise RuntimeError(
        f'{emulator} emulator did not get ready in time: {output}.')

  return thread


def start_cloud_emulator(emulator,
                         args=None,
                         data_dir=None,
                         store_on_disk=False):
  """Start a cloud emulator."""
  ready_indicators = {
      'datastore': b'is now running',
      'pubsub': b'Server started',
  }

  store_on_disk_flag = ('--store-on-disk'
                        if store_on_disk else '--no-store-on-disk')
  default_flags = {
      'datastore': [store_on_disk_flag, '--consistency=1'],
      'pubsub': [],
  }

  if emulator not in ready_indicators:
    raise RuntimeError('Unsupported emulator')

  if data_dir:
    cleanup_dir = None
  else:
    temp_dir = tempfile.mkdtemp()
    data_dir = temp_dir
    cleanup_dir = temp_dir

  port = _find_free_port()

  command = [
      'gcloud', 'beta', 'emulators', emulator, 'start',
      '--data-dir=' + data_dir, '--host-port=localhost:' + str(port),
      '--project=' + local_config.GAEConfig().get('application_id')
  ]
  if args:
    command.extend(args)

  command.extend(default_flags[emulator])

  # Start emulator.
  proc = subprocess.Popen(
      command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

  thread = wait_for_emulator_ready(proc, emulator, ready_indicators[emulator])

  # Set env vars.
  env_vars = subprocess.check_output([
      'gcloud', 'beta', 'emulators', emulator, 'env-init',
      '--data-dir=' + data_dir
  ])

  for line in env_vars.splitlines():
    key, value = line.split()[1].split(b'=')
    os.environ[key.strip().decode('utf-8')] = value.strip().decode('utf-8')

  return EmulatorInstance(proc, port, thread, cleanup_dir)


def create_pubsub_topic(client, project, name):
  """Create topic if it doesn't exist."""
  full_name = pubsub.topic_name(project, name)
  if client.get_topic(full_name):
    return

  client.create_topic(full_name)


def create_pubsub_subscription(client, project, topic, name):
  """Create subscription if it doesn't exist."""
  topic_name = pubsub.topic_name(project, topic)
  full_name = pubsub.subscription_name(project, name)
  if client.get_subscription(full_name):
    return

  client.create_subscription(full_name, topic_name)


def setup_pubsub(project):
  """Set up pubsub topics and subscriptions."""
  config = local_config.Config('pubsub.queues')
  client = pubsub.PubSubClient()

  queues = config.get('resources')

  for queue in queues:
    create_pubsub_topic(client, project, queue['name'])
    create_pubsub_subscription(client, project, queue['name'], queue['name'])


def with_cloud_emulators(*emulator_names):
  """Decorator for starting cloud emulators from a unittest.TestCase."""

  def decorator(cls):
    """Decorator."""

    class Wrapped(cls):
      """Wrapped class."""

      @classmethod
      def setUpClass(cls):
        """Class setup."""
        for emulator_name in emulator_names:
          if emulator_name not in _emulators:
            _emulators[emulator_name] = start_cloud_emulator(emulator_name)
            atexit.register(_emulators[emulator_name].cleanup)

          if emulator_name == 'datastore':
            cls._context_generator = ndb_init.context()
            cls._context_generator.__enter__()

        super(Wrapped, cls).setUpClass()

      @classmethod
      def tearDownClass(cls):
        """Class teardown."""
        for emulator_name in emulator_names:
          if emulator_name == 'datastore':
            cls._context_generator.__exit__(None, None, None)

        super(Wrapped, cls).tearDownClass()

      def setUp(self):
        for emulator in six.itervalues(_emulators):
          emulator.reset()

        super().setUp()

    Wrapped.__module__ = cls.__module__
    Wrapped.__name__ = cls.__name__
    return Wrapped

  return decorator


def set_up_pyfakefs(test_self, allow_root_user=True):
  """Helper to set up Pyfakefs."""
  real_cwd = os.path.realpath(os.getcwd())
  config_dir = os.path.realpath(environment.get_config_directory())
  test_self.setUpPyfakefs(allow_root_user=allow_root_user)
  test_self.fs.add_real_directory(config_dir, lazy_read=False)
  os.chdir(real_cwd)


def supported_platforms(*platforms):
  """Decorator for enabling tests only on certain platforms."""

  def decorator(func):  # pylint: disable=unused-argument
    """Decorator."""
    return unittest.skipIf(environment.platform() not in platforms,
                           'Unsupported platform.')(
                               func)

  return decorator


MockStdout = io.StringIO  # pylint: disable=invalid-name
