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
"""package.py handles the package command"""

import os
import re
import sys
import zipfile

from local.butler import appengine
from local.butler import common
from local.butler import constants

MIN_SUPPORTED_NODEJS_VERSION = 4


def _clear_zip(target_zip_path):
  """Remove zip and manifest file."""
  if os.path.exists(constants.PACKAGE_TARGET_MANIFEST_PATH):
    os.remove(constants.PACKAGE_TARGET_MANIFEST_PATH)

  if os.path.exists(target_zip_path):
    os.remove(target_zip_path)


def _add_to_zip(output_file, src_file_path, dest_file_path=None):
  """Add the src_file_path to the output_file with the right target path."""
  if dest_file_path is None:
    dest_file_path = src_file_path
  output_file.write(src_file_path, os.path.join('clusterfuzz', dest_file_path))


def _is_nodejs_up_to_date():
  """Check if node is of version MINIMUM_NODEJS_VERSION."""
  return_code, output = common.execute('node -v')

  if return_code != 0:
    return False

  m = re.match(br'v([0-9]+)\..+', output.strip())

  if not m:
    return False

  major_version = int(m.group(1))
  return major_version >= MIN_SUPPORTED_NODEJS_VERSION


def _get_files(path):
  """Iterate through files in path."""
  for root, _, filenames in os.walk(path):
    for filename in filenames:
      if filename.endswith('.pyc') or (os.sep + '.git') in root:
        continue

      yield os.path.join(root, filename)


def package(revision,
            target_zip_dir=constants.PACKAGE_TARGET_ZIP_DIRECTORY,
            target_manifest_path=constants.PACKAGE_TARGET_MANIFEST_PATH,
            platform_name=None,
            python3=False):
  """Prepare clusterfuzz-source.zip."""
  is_ci = os.getenv('TEST_BOT_ENVIRONMENT')
  if not is_ci and common.is_git_dirty():
    print('Your branch is dirty. Please fix before packaging.')
    sys.exit(1)

  if not _is_nodejs_up_to_date():
    print('You do not have nodejs, or your nodejs is not at least version 4.')
    sys.exit(1)

  common.install_dependencies(platform_name=platform_name)

  # This needs to be done before packaging step to let src/appengine/config be
  # archived for bot.
  appengine.symlink_dirs()

  _, ls_files_output = common.execute('git -C . ls-files', print_output=False)
  file_paths = [path.decode('utf-8') for path in ls_files_output.splitlines()]

  if not os.path.exists(target_zip_dir):
    os.makedirs(target_zip_dir)

  target_zip_name = constants.LEGACY_ZIP_NAME
  if platform_name:
    if python3:
      target_zip_name = platform_name + '-3.zip'
    else:
      target_zip_name = platform_name + '.zip'

  target_zip_path = os.path.join(target_zip_dir, target_zip_name)
  _clear_zip(target_zip_path)

  output_file = zipfile.ZipFile(target_zip_path, 'w', zipfile.ZIP_DEFLATED)

  # Add files from git.
  for file_path in file_paths:
    if (file_path.startswith('config') or file_path.startswith('local') or
        file_path.startswith(os.path.join('src', 'appengine')) or
        file_path.startswith(os.path.join('src', 'local')) or
        file_path.startswith(
            os.path.join('src', 'clusterfuzz', '_internal', 'tests'))):
      continue
    _add_to_zip(output_file, file_path)

  # These are project configuration yamls.
  for path in _get_files(os.path.join('src', 'appengine', 'config')):
    _add_to_zip(output_file, path)

  # These are third party dependencies.
  for path in _get_files(os.path.join('src', 'third_party')):
    _add_to_zip(output_file, path)

  output_file.close()

  with open(target_manifest_path, 'w') as f:
    f.write('%s\n' % revision)

  with zipfile.ZipFile(target_zip_path, 'a', zipfile.ZIP_DEFLATED) as f:
    _add_to_zip(f, target_manifest_path, constants.PACKAGE_TARGET_MANIFEST_PATH)

  print('Revision: %s' % revision)

  print()
  print('%s is ready.' % target_zip_path)
  return target_zip_path


def execute(args):
  if args.platform == 'all':
    for platform_name in list(constants.PLATFORMS.keys()):
      package(
          revision=common.compute_staging_revision(),
          platform_name=platform_name)
  else:
    package(
        revision=common.compute_staging_revision(), platform_name=args.platform)
