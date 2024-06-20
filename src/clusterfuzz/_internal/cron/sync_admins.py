# Copyright 2023 Google LLC
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
"""Cron to sync admin users."""

from googleapiclient import discovery

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import ndb_utils
from clusterfuzz._internal.metrics import logs


def admins_from_iam_policy(iam_policy):
  """Gets a list of admins from the IAM policy."""
  # Per
  # https://cloud.google.com/appengine/docs/standard/python/users/adminusers, An
  # administrator is a user who has the Viewer, Editor, or Owner primitive role,
  # or the App Engine App Admin predefined role
  roles = [
      'roles/editor',
      'roles/owner',
      'roles/viewer',
      'roles/appengine.appAdmin',
  ]

  admins = []
  for binding in iam_policy['bindings']:
    if binding['role'] not in roles:
      continue

    for member in binding['members']:
      user_type, email = member.split(':', 2)
      if user_type == 'user':
        admins.append(email)

  return admins


def update_admins(new_admins):
  """Update list of admins."""
  existing_admins = ndb_utils.get_all_from_model(data_types.Admin)

  to_remove = []
  existing_admin_emails = set()
  for admin in existing_admins:
    if admin.email not in new_admins:
      logs.info('Removing admin ' + admin.email)
      to_remove.append(admin.key)

    existing_admin_emails.add(admin.email)

  ndb_utils.delete_multi(to_remove)

  to_add = []
  for admin in new_admins:
    if admin not in existing_admin_emails:
      to_add.append(data_types.Admin(id=admin, email=admin))
      logs.info('Adding admin ' + admin)

  ndb_utils.put_multi(to_add)


def main():
  """Admin user syncing cron."""
  resource_manager = discovery.build('cloudresourcemanager', 'v1')
  project_id = utils.get_application_id()
  # pylint: disable=no-member
  policy = resource_manager.projects().getIamPolicy(
      resource=project_id, body={}).execute()

  admins = admins_from_iam_policy(policy)
  update_admins(admins)
  logs.info('Sync admins succeeded.')
  return True
