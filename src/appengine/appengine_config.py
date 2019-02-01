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

from google.appengine.ext import ndb
from google.appengine.ext import vendor
from webob import multidict


def from_fieldstorage(cls, fs):
  """Create a dict from a cgi.FieldStorage instance.

  See this for more details:
  http://code.google.com/p/googleappengine/issues/detail?id=2749
  """
  import base64
  import quopri

  obj = cls()
  if fs.list:
    # fs.list can be None when there's nothing to parse
    for field in fs.list:
      if field.filename:
        obj.add(field.name, field)
      else:

        # first, set a common charset to utf-8.
        common_charset = 'utf-8'

        # second, check Content-Transfer-Encoding and decode
        # the value appropriately
        field_value = field.value
        transfer_encoding = field.headers.get('Content-Transfer-Encoding', None)

        if transfer_encoding == 'base64':
          field_value = base64.b64decode(field_value)

        if transfer_encoding == 'quoted-printable':
          field_value = quopri.decodestring(field_value)

        if field.type_options.has_key(
            'charset') and field.type_options['charset'] != common_charset:
          # decode with a charset specified in each
          # multipart, and then encode it again with a
          # charset specified in top level FieldStorage
          field_value = field_value.decode(
              field.type_options['charset']).encode(common_charset)

        obj.add(field.name, field_value)

  return obj


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

multidict.MultiDict.from_fieldstorage = classmethod(from_fieldstorage)

# Add necessary directories to path.
if IS_RUNNING_IN_PRODUCTION or IS_RUNNING_IN_DEV_APPSERVER:
  vendor.add('third_party')
  vendor.add('python')
else:
  sys.path.insert(0, 'third_party')
  sys.path.insert(0, 'python')

# Adding the protobuf module to the google module. Otherwise, we couldn't
# import google.protobuf because google.appengine already took the name.
import google
google.__path__.append(os.path.join('third_party', 'google'))

if IS_RUNNING_IN_DEV_APPSERVER:
  from base import modules
  modules.disable_known_module_warnings()

# In tests this is done in test_utils.with_cloud_emulators.
if IS_RUNNING_IN_PRODUCTION or IS_RUNNING_IN_DEV_APPSERVER:
  # Disable NDB caching, as NDB on GCE VMs do not use memcache and therefore
  # can't invalidate the memcache cache.
  ndb.get_context().set_memcache_policy(False)

  # Disable the in-context cache, as it can use up a lot of memory for longer
  # running tasks such as cron jobs.
  ndb.get_context().set_cache_policy(False)
