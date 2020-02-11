# Copyright 2020 Google LLC
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
"""Python 3 entrypoint."""
import importlib
import os
import sys

# Add necessary directories to path.
sys.path.append('python')
sys.path.append('third_party')

config_modules_path = os.path.join('config', 'modules')
if os.path.exists(config_modules_path):
  sys.path.append(config_modules_path)

try:
  # Run any module initialization code.
  import module_init
  module_init.appengine()
except ImportError:
  pass

if os.environ.get('GAE_ENV'):
  import pkg_resources
  importlib.reload(pkg_resources)

  import firebase_admin
  firebase_admin.initialize_app()

import server
app = server.app
