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
"""Test Google Groups API."""

from clusterfuzz._internal.base import errors
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import ndb_utils
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment

from googleapiclient import discovery
from urllib.parse import urlencode


def create_google_group_membership(service, group_id, member_key):
  param = "&groupKey.id=" + group_id
  try:
    lookupGroupNameRequest = service.groups().lookup()
    lookupGroupNameRequest.uri += param
    # Given a group ID and namespace, retrieve the ID for parent group
    lookupGroupNameResponse = lookupGroupNameRequest.execute()
    groupName = lookupGroupNameResponse.get("name")
    # Create a membership object with a memberKey and a single role of type MEMBER
    membership = {
      "preferredMemberKey": {"id": member_key},
      "roles" : {
        "name" : "OWNER",
        "name" : "MEMBER"
      }
    }
    # Create a membership using the ID for the parent group and a membership object
    response = service.groups().memberships().create(parent=groupName, body=membership).execute()
    print(response)
  except Exception as e:
    print(e)


def search_transitive_memberships(service, parent, page_size):
  try:
    memberships = []
    next_page_token = ''
    while True:
      query_params = urlencode(
        {
          "page_size": page_size,
          "page_token": next_page_token
        }
      )
      request = service.groups().memberships().searchTransitiveMemberships(parent=parent)
      request.uri += "&" + query_params
      response = request.execute()

      if 'memberships' in response:
        memberships += response['memberships']

      if 'nextPageToken' in response:
        next_page_token = response['nextPageToken']
      else:
        next_page_token = ''

      if len(next_page_token) == 0:
        break;

    print(memberships)
  except Exception as e:
    print(e)


def create_google_group(service, customer_id, group_id, group_display_name, group_description):
  group_key = {"id": group_id}
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
    request = service.groups().create(body=group)
    request.uri += "&initialGroupConfig=WITH_INITIAL_OWNER"
    response = request.execute()
    print(response)
  except Exception as e:
    print(e)

def check_transitive_membership(service, parent, member):
  try:
    query_params = urlencode(
      {
        "query": "member_key_id == '{}'".format(member)
      }
    )
    request = service.groups().memberships().checkTransitiveMembership(parent=parent)
    request.uri += "&" + query_params
    response = request.execute()
    return response.get('hasMembership', False)
  except Exception as e:
    print(f'Except - {e}')
    return False


def get_group_id(service, group_email):
  try:
    request = service.groups().lookup(groupKey_id=group_email)
    response = request.execute()
    return response.get('name')
  except Exception as e:
    print(f"Error looking up group {group_email}: {e}")
    return None


def execute(args):
  """Reset testcases' groups."""
  del args
  environment.set_bot_environment()
  logs.configure('run_bot')
  print()

  service = discovery.build('cloudidentity', 'v1')
  # group_id = get_group_id(service, 'mdb.clusterfuzz@google.com')
  # group_id = get_group_id(service, 'test-clusterfuzz-acl@google.com')
  group_id = get_group_id(service, 'clusterfuzz-dev@google.com')
  if not group_id:
    return

  print(group_id)
  is_member = check_transitive_membership(service, group_id, 'vtcosta@google.com')
  print(is_member)
  # create_google_group(service, customer_id='C02h8e9nw', group_id='test-clusterfuzz-acl@google.com', group_display_name='Test ACL', group_description='group for testing ACL.')
  # create_google_group_membership(service, group_id='test-clusterfuzz-acl@google.com', member_key='vtcosta@google.com')
  # create_google_group_membership(service, group_id='test-clusterfuzz-acl@google.com', member_key='andrenribeiro@google.com')
  # create_google_group_membership(service, group_id='test-clusterfuzz-acl@google.com', member_key='clusterfuzz-dev@google.com')

  # search_transitive_memberships(service, "groups/01fob9te2jnakdb", 50)
  
  # check_transitive_membership(service, "groups/01fob9te2jnakdb", 'vtcosta@google.com')
  # check_transitive_membership(service, "groups/01fob9te2jnakdb", 'andrenribeiro@google.com')
  # check_transitive_membership(service, "groups/01fob9te2jnakdb", 'carlolemos@google.com')
