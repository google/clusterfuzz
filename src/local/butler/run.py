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
"""run.py runs a one-off script (e.g. migration) with appropriate envs (e.g.
  datastore)."""

import importlib
import os

from local.butler import constants
from src.clusterfuzz._internal.config import local_config
from src.clusterfuzz._internal.datastore import ndb_init


def execute(args):
  """Run Python unit tests under v2. For unittests involved appengine, sys.path
     needs certain modification."""
  os.environ['CONFIG_DIR_OVERRIDE'] = args.config_dir
  local_config.ProjectConfig().set_environment()

  if args.local:
    os.environ['DATASTORE_EMULATOR_HOST'] = constants.DATASTORE_EMULATOR_HOST
    os.environ['PUBSUB_EMULATOR_HOST'] = constants.PUBSUB_EMULATOR_HOST
    os.environ['DATASTORE_USE_PROJECT_ID_AS_APP_ID'] = 'true'
    os.environ['LOCAL_DEVELOPMENT'] = 'True'

  if not args.non_dry_run:
    print('Running in dry-run mode, no datastore writes are committed. '
          'For permanent modifications, re-run with --non-dry-run.')

  with ndb_init.context():
    script = importlib.import_module(
        'local.butler.scripts.%s' % args.script_name)
    script.execute(args)

  if not args.local:
    print()
    print('Please remember to run the migration individually on all projects.')
    print()
