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
"""go_unittest.py runs tests under src/go"""

import os

from local.butler import common


def execute(args):
  """Build and run all tests under src/go."""
  go_directory = os.path.join('src', 'go')

  common.execute('bazel build //...', cwd=go_directory)
  if args.verbose or args.unsuppress_output:
    test_output_arg = '--test_output=all'
  else:
    test_output_arg = '--test_output=errors'

  common.execute(
      'bazel test --sandbox_writable_path={home} '  # Necessary for gcloud.
      '{test_output_arg} '
      '--test_env=CONFIG_DIR_OVERRIDE={config_dir_override} '
      '--test_env=ROOT_DIR={root_dir} '
      '--test_env=INTEGRATION={integration} '
      '--test_env=CLUSTERFUZZ_MUTABLE_TEST_BUCKET={test_bucket} //...'.format(
          home=os.getenv('HOME'),
          test_output_arg=test_output_arg,
          config_dir_override=os.path.abspath(os.path.join('configs', 'test')),
          root_dir=os.getenv('ROOT_DIR'),
          integration=os.getenv('INTEGRATION', '0'),
          test_bucket=common.test_bucket_for_user()),
      cwd=go_directory)
