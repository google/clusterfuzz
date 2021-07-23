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
"""Run clean indexes on both internal and external."""

import os
import sys

from local.butler import common
from src.clusterfuzz._internal.config import local_config

INDEX_FILE_PATH = 'src/appengine/index.yaml'


def _cleanup_indexes(project, index_yaml_path):
  """Cleanup indexes."""
  common.execute(('gcloud datastore indexes cleanup '
                  '--quiet --project {project} {index_yaml_path}').format(
                      project=project, index_yaml_path=index_yaml_path))


def execute(args):
  """Clean indexes."""
  if not os.path.exists(args.config_dir):
    print('Please provide a valid configuration directory.')
    sys.exit(1)
  os.environ['CONFIG_DIR_OVERRIDE'] = args.config_dir

  config = local_config.GAEConfig()
  application_id = config.get('application_id')

  _cleanup_indexes(application_id, INDEX_FILE_PATH)
