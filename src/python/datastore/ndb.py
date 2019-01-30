# Copyright 2018 Google LLC
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
"""NDB importer."""

from system import environment
if (not environment.is_running_on_app_engine() and
    not environment.get_value('PY_UNITTESTS')):
  import ndb_patcher
  ndb_patcher.patch_ndb()

from google.appengine.ext.ndb import *  # pylint:disable=wildcard-import
