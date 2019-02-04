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
"""guard.py checks virtualenv environment and dev requirements."""
import os
import subprocess


def check_virtualenv():
  root_path = os.path.realpath(
      os.path.join(os.path.dirname(__file__), '..', '..', '..'))
  is_in_virtualenv = os.getenv('VIRTUAL_ENV') == os.path.join(root_path, 'ENV')

  if not is_in_virtualenv:
    raise Exception(
        'You are not in a virtual env environment. Please install it with'
        ' `./local/install_deps.bash` or load it with'
        ' `source ENV/bin/activate`. Then, you can re-run this command.')


def check_dev_requirements():
  """Check that dev requirements are installed."""
  freeze_output = subprocess.check_output('pip freeze', shell=True)
  installed_pips = freeze_output.strip().splitlines()

  with open('src/local/requirements.txt', 'r') as f:
    required_pips = f.read().strip().splitlines()

  with open('docker/ci/requirements.txt', 'r') as f:
    required_pips.extend(f.read().strip().splitlines())

  for pip in required_pips:
    if pip not in installed_pips:
      raise Exception(
          '%s is not installed as required by `src/local/requirements.txt`.'
          ' Please run `pip install -U -r src/local/requirements.txt` and '
          '`pip install -U -r docker/ci/requirements.txt` to get %s' % (pip,
                                                                        pip))


def check():
  """Check if we are in virtualenv and dev requirements are installed."""
  if os.getenv('TEST_BOT_ENVIRONMENT'):
    # Don't need to do these checks if we're in the bot environment.
    return

  check_virtualenv()
  check_dev_requirements()
