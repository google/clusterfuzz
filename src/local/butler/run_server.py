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
"""run_server.py run the Clusterfuzz server locally."""
from distutils import spawn
import os
import shutil
import threading
import time
import urllib2

from local.butler import appengine
from local.butler import common
from local.butler import constants
from python.config import local_config
from python.tests.test_libs import test_utils


def bootstrap_db():
  """Bootstrap the DB."""

  def bootstrap():
    # Wait for the server to run.
    time.sleep(10)
    print 'Bootstrapping datastore...'
    common.execute(
        ('python butler.py run setup '
         '--non-dry-run --local --config-dir={config_dir}'
        ).format(config_dir=constants.TEST_CONFIG_DIR),
        exit_on_error=False)

  thread = threading.Thread(target=bootstrap)
  thread.start()


def create_local_bucket(local_gcs_buckets_path, name):
  """Create a local bucket."""
  blobs_bucket = os.path.join(local_gcs_buckets_path, name)
  if not os.path.exists(blobs_bucket):
    os.mkdir(blobs_bucket)


def bootstrap_gcs(storage_path):
  """Bootstrap GCS."""
  local_gcs_buckets_path = os.path.join(storage_path, 'local_gcs')
  if not os.path.exists(local_gcs_buckets_path):
    os.mkdir(local_gcs_buckets_path)

  config = local_config.ProjectConfig()
  create_local_bucket(local_gcs_buckets_path, config.get('blobs.bucket'))
  create_local_bucket(local_gcs_buckets_path, config.get('deployment.bucket'))
  create_local_bucket(local_gcs_buckets_path, config.get('bigquery.bucket'))
  create_local_bucket(local_gcs_buckets_path, config.get('backup.bucket'))
  create_local_bucket(local_gcs_buckets_path, config.get('logs.fuzzer.bucket'))
  create_local_bucket(local_gcs_buckets_path, config.get('env.CORPUS_BUCKET'))
  create_local_bucket(local_gcs_buckets_path,
                      config.get('env.QUARANTINE_BUCKET'))
  create_local_bucket(local_gcs_buckets_path,
                      config.get('env.SHARED_CORPUS_BUCKET'))
  create_local_bucket(local_gcs_buckets_path,
                      config.get('env.FUZZ_LOGS_BUCKET'))

  # Symlink local GCS bucket path to appengine src dir to bypass sandboxing
  # issues.
  common.symlink(
      src=local_gcs_buckets_path,
      target=os.path.join(appengine.SRC_DIR_PY, 'local_gcs'))


def _dev_appserver_path():
  """Return the actual path to dev_appserver. It uses the path to
  dev_appserver.py to find the cloud emulator, so that fails if it is a
  symlink."""
  dev_appserver_path = spawn.find_executable('dev_appserver.py')
  if not os.path.islink(dev_appserver_path):
    return dev_appserver_path

  return os.path.normpath(
      os.path.join(
          os.path.dirname(dev_appserver_path), os.readlink(dev_appserver_path)))


def start_cron_threads():
  """Start threads to trigger essential cron jobs."""

  request_timeout = 10 * 60  # 10 minutes.

  def trigger(interval_seconds, target):
    while True:
      time.sleep(interval_seconds)

      url = 'http://{host}/{target}'.format(
          host=constants.CRON_SERVICE_HOST, target=target)
      request = urllib2.Request(url)
      request.add_header('X-Appengine-Cron', 'true')
      response = urllib2.urlopen(request, timeout=request_timeout)
      response.read(60)  # wait for request to finish.

  crons = (
      (90, 'cleanup'),
      (60, 'triage'),
      (6 * 3600, 'schedule-progression-tasks'),
      (12 * 3600, 'schedule-corpus-pruning'),
  )

  for interval, cron in crons:
    thread = threading.Thread(target=trigger, args=(interval, cron))
    thread.daemon = True
    thread.start()


def execute(args):
  """Run the server."""
  os.environ['LOCAL_DEVELOPMENT'] = 'True'
  common.kill_leftover_emulators()

  if not args.skip_install_deps:
    common.install_dependencies()

  # Do this everytime as a past deployment might have changed these.
  appengine.symlink_dirs()

  # Deploy all yaml files from test project for basic appengine deployment and
  # local testing to work. This needs to be called on every iteration as a past
  # deployment might have overwritten or deleted these config files.
  yaml_paths = local_config.GAEConfig().get_absolute_path('deployment.prod')
  appengine.copy_yamls_and_preprocess(yaml_paths)

  # Build templates.
  appengine.build_templates()

  # Clean storage directory if needed.
  if args.bootstrap or args.clean:
    if os.path.exists(args.storage_path):
      print 'Clearing local datastore by removing %s.' % args.storage_path
      shutil.rmtree(args.storage_path)
  if not os.path.exists(args.storage_path):
    os.makedirs(args.storage_path)

  # Set up local GCS buckets and symlinks.
  bootstrap_gcs(args.storage_path)

  # Start pubsub emulator.
  pubsub_emulator = test_utils.start_cloud_emulator(
      'pubsub',
      args=['--host-port=' + constants.PUBSUB_EMULATOR_HOST],
      data_dir=args.storage_path)
  test_utils.setup_pubsub(constants.TEST_APP_ID)

  # Start our custom GCS emulator.
  local_gcs = common.execute_async(
      'bazel run //go/testing/gcs '
      '--sandbox_writable_path=$(pwd)/../local/storage/local_gcs '
      '-- -storage-path=$(pwd)/../local/storage/local_gcs',
      cwd='src')

  if args.bootstrap:
    bootstrap_db()

  start_cron_threads()

  try:
    common.execute(
        '{dev_appserver_path} -A {project} --skip_sdk_update_check=1 '
        '--storage_path={storage_path} --port={appserver_port} '
        '--admin_port={admin_port} '
        '--datastore_emulator_port={datastore_emulator_port} '
        '--require_indexes=true --log_level={log_level} '
        '--dev_appserver_log_level={log_level} '
        '--support_datastore_emulator=true '
        '--env_var LOCAL_DEVELOPMENT=True '
        '--env_var PUBSUB_EMULATOR_HOST={pubsub_emulator_host} '
        '--env_var LOCAL_GCS_BUCKETS_PATH=local_gcs '
        '--env_var LOCAL_GCS_SERVER_HOST={local_gcs_server_host} '
        'src/appengine src/appengine/cron-service.yaml'.format(
            dev_appserver_path=_dev_appserver_path(),
            project=constants.TEST_APP_ID,
            storage_path=args.storage_path,
            appserver_port=constants.DEV_APPSERVER_PORT,
            admin_port=constants.DEV_APPSERVER_ADMIN_PORT,
            datastore_emulator_port=constants.DATASTORE_EMULATOR_PORT,
            log_level=args.log_level,
            pubsub_emulator_host=constants.PUBSUB_EMULATOR_HOST,
            local_gcs_server_host=constants.LOCAL_GCS_SERVER_HOST))
  except KeyboardInterrupt:
    print 'Server has been stopped. Exit.'
    pubsub_emulator.cleanup()
    local_gcs.terminate()
