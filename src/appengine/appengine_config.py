# -*- coding: utf-8 -*-
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
"""appengine_config initialises before the server starts."""
import os
import sys

from google.appengine.ext import vendor

# True if the app is running inside the dev appserver, false otherwise.  This
# is not the opposite of IS_RUNNING_IN_PRODUCTION; it is possible (in tests,
# for example) for both IS_RUNNING_IN_DEV_APPSERVER and IS_RUNNING_IN_PRODUCTION
# to be false.
IS_RUNNING_IN_DEV_APPSERVER = (
    os.getenv('SERVER_SOFTWARE') and
    os.getenv('SERVER_SOFTWARE').startswith('Development/') and
    'testbed' not in os.getenv('SERVER_SOFTWARE'))
# True if the app is running inside an AppEngine production environment, such
# as prom.corp or appspot.com.  False if it's running inside dev_appserver or
# unsupported (such as from unit tests).
IS_RUNNING_IN_PRODUCTION = (
    os.getenv('SERVER_SOFTWARE') and
    os.getenv('SERVER_SOFTWARE').startswith('Google App Engine/'))

# Add necessary directories to path.
config_modules_path = os.path.join('config', 'modules')

if IS_RUNNING_IN_PRODUCTION or IS_RUNNING_IN_DEV_APPSERVER:
  vendor.add('third_party')
  vendor.add('python')
  if os.path.exists(config_modules_path):
    vendor.add(config_modules_path)

  # Hack for python-ndb.
  import pkg_resources
  pkg_resources.working_set.add_entry('third_party')
else:
  sys.path.insert(0, 'third_party')
  sys.path.insert(0, 'python')
  if os.path.exists(config_modules_path):
    sys.path.insert(0, config_modules_path)

try:
  # Run any module initialization code.
  import module_init
  module_init.appengine()
except ImportError:
  pass

# https://github.com/googleapis/python-ndb/issues/249
import six
reload(six)

# Adding the protobuf module to the google module. Otherwise, we couldn't
# import google.protobuf because google.appengine already took the name.
import google
google.__path__.insert(0, os.path.join('third_party', 'google'))

if IS_RUNNING_IN_DEV_APPSERVER:
  from base import modules
  modules.disable_known_module_warnings()

# In tests this is done in test_utils.with_cloud_emulators.
if IS_RUNNING_IN_PRODUCTION or IS_RUNNING_IN_DEV_APPSERVER:
  # Use the App Engine Requests adapter. This makes sure that Requests uses
  # URLFetch. This is a workaround till we migrate to Python 3 on App Engine
  # Flex.
  import requests_toolbelt.adapters.appengine
  requests_toolbelt.adapters.appengine.monkeypatch()

  import firebase_admin
  firebase_admin.initialize_app()
