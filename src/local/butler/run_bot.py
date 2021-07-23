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
"""run_bot.py run a Clusterfuzz bot locally."""
import os
import signal

from local.butler import appengine
from local.butler import common
from local.butler import constants


def _setup_bot_directory(args):
  """Set up the bot directory."""
  appengine.symlink_config_dir()

  src_root_dir = os.path.abspath('.')
  if os.path.exists(args.directory):
    print('Bot directory already exists. Re-using...')
  else:
    print('Creating new CF bot directory...')
    os.makedirs(args.directory)

  clusterfuzz_dir = os.path.join(args.directory, 'clusterfuzz')
  bot_src_dir = os.path.join(clusterfuzz_dir, 'src')
  if not os.path.exists(clusterfuzz_dir):
    os.makedirs(clusterfuzz_dir)
    os.mkdir(bot_src_dir)

  common.update_dir(
      os.path.join(src_root_dir, 'src', 'appengine'),
      os.path.join(bot_src_dir, 'appengine'))
  common.update_dir(
      os.path.join(src_root_dir, 'src', 'python'),
      os.path.join(bot_src_dir, 'python'))
  common.update_dir(
      os.path.join(src_root_dir, 'src', 'clusterfuzz'),
      os.path.join(bot_src_dir, 'clusterfuzz'))
  common.update_dir(
      os.path.join(src_root_dir, 'src', 'third_party'),
      os.path.join(bot_src_dir, 'third_party'))

  common.update_dir(
      os.path.join(src_root_dir, 'resources'),
      os.path.join(clusterfuzz_dir, 'resources'))
  common.update_dir(
      os.path.join(src_root_dir, 'bot'), os.path.join(clusterfuzz_dir, 'bot'))


def _setup_environment_and_configs(args, appengine_path):
  """Set up environment variables and configuration files."""
  clusterfuzz_dir = os.path.abspath(os.path.join(args.directory, 'clusterfuzz'))

  # Matches startup scripts.
  os.environ['PYTHONPATH'] = ':'.join([
      os.getenv('PYTHONPATH', ''),
      appengine_path,
      os.path.join(clusterfuzz_dir, 'src'),
  ])

  os.environ['ROOT_DIR'] = clusterfuzz_dir
  if not os.getenv('BOT_NAME'):
    os.environ['BOT_NAME'] = args.name

  os.environ['LD_LIBRARY_PATH'] = '{0}:{1}'.format(
      os.path.join(clusterfuzz_dir, 'src', 'clusterfuzz', '_internal',
                   'scripts'), os.getenv('LD_LIBRARY_PATH', ''))

  tmpdir = os.path.join(clusterfuzz_dir, 'bot_tmpdir')
  if not os.path.exists(tmpdir):
    os.mkdir(tmpdir)
  os.environ['TMPDIR'] = tmpdir
  os.environ['BOT_TMPDIR'] = tmpdir

  os.environ['KILL_STALE_INSTANCES'] = 'False'
  os.environ['LOCAL_DEVELOPMENT'] = 'True'
  os.environ['DATASTORE_EMULATOR_HOST'] = constants.DATASTORE_EMULATOR_HOST
  os.environ['PUBSUB_EMULATOR_HOST'] = constants.PUBSUB_EMULATOR_HOST
  os.environ['APPLICATION_ID'] = constants.TEST_APP_ID

  if not os.getenv('UNTRUSTED_WORKER'):
    local_gcs_buckets_path = os.path.abspath(
        os.path.join(args.server_storage_path, 'local_gcs'))
    assert os.path.exists(local_gcs_buckets_path), (
        'Server storage path not found, make sure to start run_server with '
        'the same storage path.')

    os.environ['LOCAL_GCS_BUCKETS_PATH'] = local_gcs_buckets_path

  if args.android_serial:
    if not os.getenv('OS_OVERRIDE'):
      os.environ['OS_OVERRIDE'] = 'ANDROID'

    os.environ['ANDROID_SERIAL'] = args.android_serial


def execute(args):
  """Run the bot."""
  appengine_path = appengine.find_sdk_path()

  _setup_bot_directory(args)
  _setup_environment_and_configs(args, appengine_path)

  try:
    os.chdir(os.path.join(args.directory, 'clusterfuzz'))
    proc = common.execute_async('python src/python/bot/startup/run_bot.py')

    def _stop_handler(*_):
      print('Bot has been stopped. Exit.')
      proc.kill()

    signal.signal(signal.SIGTERM, _stop_handler)
    common.process_proc_output(proc)
    proc.wait()
  except KeyboardInterrupt:
    _stop_handler()
