# Copyright 2026 Google LLC
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
"""Cron to sync OSS-Fuzz projects groups used as CC in the issue tracker."""

from clusterfuzz._internal.base import external_users
from clusterfuzz._internal.base import utils
from clusterfuzz._internal.config import local_config
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import ndb_utils
from clusterfuzz._internal.google_cloud_utils import google_groups
from clusterfuzz._internal.metrics import logs


def get_project_cc_group_description(project_name: str) -> str:
  """Return issue CC group description for a oss-fuzz project."""
  oss_fuzz_cc_desc = 'External CCs in OSS-Fuzz issue tracker for project'
  return f'{oss_fuzz_cc_desc}: {project_name}'


def sync_project_cc_group(project_name: str, ccs: list[str]):
  """Sync the oss-fuzz project's group used for CCing in the issue tracker."""
  group_name = external_users.get_project_cc_group(project_name)

  group_id = google_groups.get_group_id(group_name)
  # Create the group and bail out since the CIG API might delay to create a
  # new group. Add members will be done in the next cron run.
  if not group_id:
    group_description = get_project_cc_group_description(project_name)
    customer_id = local_config.ProjectConfig().get(
        'issue_cc_groups.customer_id')
    created = google_groups.create_google_group(
        group_name,
        group_description=group_description,
        customer_id=customer_id)
    if not created:
      logs.warning('Failed to create or retrieve the issue tracker CC group '
                   f'for {project_name}')
      return
    logs.info(f'Created issue tracker CC group for {project_name}. '
              'Skipping adding members as group may still not exist.')
    return

  group_memberships = google_groups.get_google_group_memberships(group_id)
  if group_memberships is None:
    logs.warning(
        f'Failed to get list of group members for {project_name}. Skipping.')
    return

  if len(group_memberships) <= 1:
    # If only the SA is a member, we know that the group has just been created
    # and we need to update settings to allow external members.
    if not google_groups.set_oss_fuzz_access_settings(group_name):
      logs.warning(f'Failed to allow external members for {group_name}')
      return

  ccs_set = set(ccs)

  to_add = ccs_set - group_memberships.keys()
  for member in to_add:
    google_groups.add_member_to_group(group_id, member)

  to_delete = group_memberships.keys() - ccs_set
  for member in to_delete:
    # Ignore the SA that created the group from members to delete.
    if utils.is_service_account(member):
      continue
    memebership_name = group_memberships[member]
    google_groups.delete_google_group_membership(group_id, member,
                                                 memebership_name)


def main():
  """Sync OSS-Fuzz projects groups used to CC owners in the issue tracker."""
  logs.info('OSS-Fuzz CC groups sync started.')

  for project in ndb_utils.get_all_from_model(data_types.OssFuzzProject):
    project_name = project.name
    ccs = project.ccs
    sync_project_cc_group(project_name, ccs)

  logs.info('OSS-Fuzz CC groups sync succeeded.')
  return True
