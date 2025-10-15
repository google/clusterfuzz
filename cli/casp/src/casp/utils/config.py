# Copyright 2025 Google LLC
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
"""Config utility functions."""

import json
import os

CONFIG_DIR = os.path.expanduser('~/.casp')
CONFIG_FILE = os.path.join(CONFIG_DIR, 'config.json')


def save_config(data):
  """Saves configuration data."""
  os.makedirs(CONFIG_DIR, exist_ok=True)
  with open(CONFIG_FILE, 'w') as f:
    json.dump(data, f)


def load_config():
  """Loads configuration data."""
  if not os.path.exists(CONFIG_FILE):
    return {}
  with open(CONFIG_FILE) as f:
    return json.load(f)
