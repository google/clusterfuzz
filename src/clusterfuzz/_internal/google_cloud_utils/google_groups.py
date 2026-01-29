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
"""Helper for google groups management."""

from urllib import parse

from googleapiclient import discovery
from googleapiclient.errors import HttpError

from clusterfuzz._internal.config import local_config
from clusterfuzz._internal.google_cloud_utils import credentials
from clusterfuzz._internal.metrics import logs

# pylint: disable=no-member

_identity_service: discovery.Resource | None = None


def _config_identity_api() -> None:
  """Build the google cloud identity service api."""
  global _identity_service
  creds, _ = credentials.get_default()
  _identity_service = discovery.build('cloudidentity', 'v1', credentials=creds)


def get_identity_api() -> discovery.Resource | None:
  """Return cloud identity api client."""
  if _identity_service is None:
    _config_identity_api()

  return _identity_service


def get_group_id(group_name: str, exists_check: bool = False) -> str | None:
  """Retrive a google group ID."""
  identity_service = get_identity_api()
  try:
    request = identity_service.groups().lookup(groupKey_id=group_name)
    response = request.execute()
    return response.get('name')
  except HttpError:
    if not exists_check:
      logs.warning(f"Unable to look up group {group_name}.")
    return None


def check_transitive_group_membership(group_id: str, member: str) -> bool:
  """Check if an user is a member of a google group."""
  identity_service = get_identity_api()
  try:
    query_params = parse.urlencode({
        "query": "member_key_id == '{}'".format(member)
    })
    request = identity_service.groups().memberships().checkTransitiveMembership(
        parent=group_id)
    request.uri += "&" + query_params
    response = request.execute()
    return response.get('hasMembership', False)
  except HttpError:
    logs.warning(
        f'Unable to check group membership from {member} to {group_id}.')
    return False


def create_google_group(group_name: str,
                        group_display_name: str,
                        group_description: str,
                        customer_id: str | None = None) -> bool:
  """Create a google group."""
  identity_service = get_identity_api()

  customer_id = customer_id or str(
      local_config.ProjectConfig().get('groups_customer_id'))
  if not customer_id:
    logs.error('No customer ID set. Unable to create a new google group.')
    return False

  group_key = {"id": group_name}
  group = {
      "parent": "customers/" + customer_id,
      "description": group_description,
      "displayName": group_display_name,
      "groupKey": group_key,
      # Set the label to specify creation of a Google Group.
      "labels": {
          "cloudidentity.googleapis.com/groups.discussion_forum": ""
      }
  }
  try:
    request = identity_service.groups().create(body=group)
    request.uri += "&initialGroupConfig=WITH_INITIAL_OWNER"
    response = request.execute()
    logs.info(f'Created google group {group_name}', request_response=response)
    return True
  except HttpError:
    logs.error(f'Failed to create google group {group_name}')
    return False


def list_google_group_memberships(group_id: str) -> list[str] | None:
  """Get list of members from a google group."""
  identity_service = get_identity_api()
  try:
    response = identity_service.groups().memberships().list(
        parent=group_id).execute()
    memberships = [
        member.get('preferredMemberKey').get('id')
        for member in response.get('memberships')
    ]
    return memberships
  except HttpError:
    logs.error(f'Failed to get list of members from group {group_id}')
    return None


def add_member_to_group(group_id: str, member: str) -> bool:
  """Add a new member to a google group."""
  identity_service = get_identity_api()

  try:
    # Create a membership object with a role type MEMBER
    membership = {
        "preferredMemberKey": {
            "id": member
        },
        "roles": {
            "name": "MEMBER",
        }
    }
    # Create a membership using the group ID and the membership object
    response = identity_service.groups().memberships().create(
        parent=group_id, body=membership).execute()
    logs.info(
        f'Added {member} to google group {group_id}', request_response=response)
    return True
  except HttpError:
    logs.error(f'Failed to add {member} to google group {group_id}')
    return False


def delete_google_group_membership(group_id, member) -> bool:
  """Delete a google group membership."""
  identity_service = get_identity_api()

  try:
    membership_lookup_request = identity_service.groups().memberships().lookup(
        parent=group_id)
    membership_lookup_request.uri += "&memberKey.id=" + member
    membership_lookup_response = membership_lookup_request.execute()
    membership_name = membership_lookup_response.get("name")

    response = identity_service.groups().memberships().delete(
        name=membership_name).execute()
    logs.info(
        f'Removed {member} from google group {group_id}',
        request_response=response)
    return True
  except HttpError:
    logs.error(f'Failed to remove {member} from google group {group_id}')
    return False
