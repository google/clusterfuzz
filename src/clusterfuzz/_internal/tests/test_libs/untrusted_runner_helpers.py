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
"""Test helpers for untrusted_runner."""

import os
import shutil
import subprocess
import tempfile
import unittest

from clusterfuzz._internal.bot.tasks import commands
from clusterfuzz._internal.bot.untrusted_runner import file_host
from clusterfuzz._internal.bot.untrusted_runner import host
from clusterfuzz._internal.bot.untrusted_runner import untrusted
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.google_cloud_utils import pubsub
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.system import shell
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from clusterfuzz._internal.tests.test_libs import test_utils

TEST_LIBS_DIR = os.path.dirname(os.path.realpath(__file__))
TEST_LIBS_DATA_DIR = os.path.join(TEST_LIBS_DIR, 'data')


def untrusted_process():
  """Start an untrusted process."""
  os.environ['BOT_NAME'] = 'localhost'
  untrusted.start_server()


def _test_data_dir():
  """Return path to directory for bot and server data."""
  root_dir = os.environ['ROOT_DIR']
  return os.path.join(root_dir, '_test_data')


def _create_test_bot():
  """Start test bot."""
  # TODO(ochang): Use Docker container instead.
  bot_path = os.path.join(_test_data_dir(), 'worker_bot')
  if os.path.exists(bot_path):
    shutil.rmtree(bot_path, ignore_errors=True)

  env = os.environ.copy()
  env['UNTRUSTED_WORKER'] = 'True'
  env['BOT_NAME'] = 'localhost'
  bot_proc = subprocess.Popen(
      ['python', 'butler.py', 'run_bot', bot_path], env=env)

  return bot_proc, os.path.join(bot_path, 'clusterfuzz')


def _create_test_root():
  """Create test ROOT_DIR for the trusted host."""
  root_path = os.path.join(_test_data_dir(), 'test_root')
  if os.path.exists(root_path):
    shutil.rmtree(root_path, ignore_errors=True)

  real_root = os.environ['ROOT_DIR']
  os.makedirs(root_path)

  # TODO(ochang): Make sure we don't copy files that aren't tracked in git.
  shutil.copytree(
      os.path.join(real_root, 'bot'), os.path.join(root_path, 'bot'))
  shutil.copytree(
      os.path.join(real_root, 'resources'), os.path.join(
          root_path, 'resources'))

  os.mkdir(os.path.join(root_path, 'src'))
  shutil.copytree(
      os.path.join(real_root, 'src', 'appengine'),
      os.path.join(root_path, 'src', 'appengine'))
  shutil.copytree(
      os.path.join(real_root, 'src', 'python'),
      os.path.join(root_path, 'src', 'python'))
  shutil.copytree(
      os.path.join(real_root, 'src', 'clusterfuzz'),
      os.path.join(root_path, 'src', 'clusterfuzz'))
  shutil.copytree(
      os.path.join(real_root, 'src', 'third_party'),
      os.path.join(root_path, 'src', 'third_party'))

  return root_path


def _which(prog):
  """Return full path to |prog| (based on $PATH)."""
  for path in os.getenv('PATH', '').split(':'):
    candidate = os.path.join(path, prog)
    if os.path.exists(candidate):
      return candidate

  return None


@unittest.skipIf(not os.getenv('UNTRUSTED_RUNNER_TESTS'),
                 'Skipping untrusted runner tests.')
@test_utils.with_cloud_emulators('datastore', 'pubsub')
class UntrustedRunnerIntegrationTest(unittest.TestCase):
  """Base class for doing integration testing of untrusted_runner."""

  @classmethod
  def setUpClass(cls):
    cls.saved_env = os.environ.copy()
    os.environ['HOST_INSTANCE_NAME'] = 'host'
    os.environ['HOST_INSTANCE_NUM'] = '0'
    os.environ['BOT_NAME'] = 'host-0'
    os.environ['LOCAL_DEVELOPMENT'] = 'True'
    os.environ['SOURCE_VERSION_OVERRIDE'] = 'VERSION'
    os.environ['CONFIG_DIR_OVERRIDE'] = os.path.abspath(
        os.path.join(os.environ['ROOT_DIR'], 'configs', 'test'))

    cert_location = os.path.join(TEST_LIBS_DATA_DIR, 'untrusted_cert.pem')
    key_location = os.path.join(TEST_LIBS_DATA_DIR, 'untrusted_key.pem')
    os.environ['UNTRUSTED_TLS_CERT_FOR_TESTING'] = cert_location
    os.environ['UNTRUSTED_TLS_KEY_FOR_TESTING'] = key_location

    cls.bot_proc, bot_root_dir = _create_test_bot()

    os.environ['TRUSTED_HOST'] = 'True'
    os.environ['WORKER_ROOT_DIR'] = bot_root_dir
    os.environ['WORKER_BOT_TMPDIR'] = os.path.join(bot_root_dir, 'bot_tmpdir')

    environment.set_default_vars()

    data_types.HostWorkerAssignment(
        host_name='host',
        instance_num=0,
        worker_name='localhost',
        project_name='project',
        id='host-0').put()

    with open(cert_location, 'rb') as f:
      cert_contents = f.read()

    with open(key_location, 'rb') as f:
      key_contents = f.read()

    data_types.WorkerTlsCert(
        project_name='project',
        cert_contents=cert_contents,
        key_contents=key_contents,
        id='project').put()

    host.init()

  @classmethod
  def tearDownClass(cls):
    if cls.bot_proc:
      try:
        cls.bot_proc.terminate()
      except OSError:
        # Could already be killed.
        pass

    os.environ.clear()
    os.environ.update(cls.saved_env)

  def setUp(self):
    self.tmp_dir = tempfile.mkdtemp()
    os.environ['BOT_TMPDIR'] = os.path.join(self.tmp_dir, 'bot_tmpdir')

    test_helpers.patch(self, [
        'clusterfuzz._internal.datastore.data_handler.'
        'get_data_bundle_bucket_name',
        'clusterfuzz._internal.system.environment.'
        'set_environment_parameters_from_file',
    ])

    test_helpers.patch_environ(self)

    # Our tests write data/logs into subdirs of ROOT_DIR. Pivot the ROOT_DIR to
    # a temporary one.
    new_root = _create_test_root()

    os.environ['ROOT_DIR'] = new_root
    self.saved_cwd = os.getcwd()
    os.chdir(new_root)

    environment.set_bot_environment()

    fuzz_inputs = os.environ['FUZZ_INPUTS']
    shell.remove_directory(fuzz_inputs, recreate=True)

    worker_fuzz_inputs = file_host.rebase_to_worker_root(fuzz_inputs)
    shell.remove_directory(worker_fuzz_inputs, recreate=True)

    environment.set_value('GSUTIL_PATH', os.path.dirname(_which('gsutil')))

    test_utils.setup_pubsub('test-clusterfuzz')
    test_utils.create_pubsub_topic(pubsub.PubSubClient(), 'test-clusterfuzz',
                                   'jobs-project-linux')

  def tearDown(self):
    shutil.rmtree(self.tmp_dir)
    os.chdir(self.saved_cwd)

  def _setup_env(self, job_type=None):
    """Set up bot environment."""
    if not job_type:
      return

    job = data_types.Job.query(data_types.Job.name == job_type).get()
    environment.set_value('JOB_NAME', job_type)
    commands.update_environment_for_job(job.environment_string)
