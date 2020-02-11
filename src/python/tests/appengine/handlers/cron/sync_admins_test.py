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
"""Tests for sync_admins."""

import unittest

import six
import webapp2
import webtest

from datastore import data_types
from handlers.cron import sync_admins
from tests.test_libs import helpers as test_helpers
from tests.test_libs import test_utils


@test_utils.with_cloud_emulators('datastore')
class SyncAdminsTest(unittest.TestCase):
  """Tests for sync_admins."""

  def setUp(self):
    self.app = webtest.TestApp(
        webapp2.WSGIApplication([('/sync-admins', sync_admins.Handler)]))

    test_helpers.patch(self, [
        'googleapiclient.discovery.build',
        'handlers.base_handler.Handler.is_cron',
    ])

    data_types.Admin(id='remove@email.com', email='remove@email.com').put()
    data_types.Admin(id='user1@email.com', email='keep@email.com').put()

    self.mock.is_cron.return_value = True
    self.mock.build(
        serviceName='',
        version='').projects().getIamPolicy().execute.return_value = {
            'version':
                1,
            'etag':
                'etag',
            'bindings': [
                {
                    'role':
                        'roles/appengine.appAdmin',
                    'members': [
                        'user:user1@email.com',
                        'serviceAccount:service_account@gserviceaccount.com',
                    ]
                },
                {
                    'role': 'roles/appengine.deployer',
                    'members': ['user:not_added@email.com',]
                },
                {
                    'role': 'roles/appengine.serviceAdmin',
                    'members': ['user:not_added@email.com',]
                },
                {
                    'role': 'roles/editor',
                    'members': [
                        'user:user2@email.com',
                        'user:user3@email.com',
                    ]
                },
                {
                    'role': 'roles/owner',
                    'members': ['user:user4@email.com',]
                },
                {
                    'role': 'roles/viewer',
                    'members': ['user:user5@email.com',]
                },
            ]
        }

  def test_sync_admins(self):
    """Test syncing admins."""
    self.app.get('/sync-admins')
    admins = data_types.Admin.query()
    six.assertCountEqual(self, [
        'user1@email.com',
        'user2@email.com',
        'user3@email.com',
        'user4@email.com',
        'user5@email.com',
    ], [admin.email for admin in admins])
