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
import sys


def check_virtualenv():
  """Check that we're in a virtualenv."""
  if sys.version_info.major != 3:
    raise RuntimeError('Python 2 is no longer supported!')

  is_in_virtualenv = bool(os.getenv('VIRTUAL_ENV'))

  if not is_in_virtualenv:
    raise Exception(
        'You are not in a virtual env environment. Please install it with'
        ' `./local/install_deps.bash` or load it with'
        ' `pipenv shell`. Then, you can re-run this command.')


def check():
  """Check if we are in virtualenv and dev requirements are installed."""
  if os.getenv('TEST_BOT_ENVIRONMENT'):
    # Don't need to do these checks if we're in the bot environment.
    return

  check_virtualenv()
