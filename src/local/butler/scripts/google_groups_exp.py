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
    print(response)
    print(response['hasMembership'])
  except Exception as e:
    print(e)


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

  service = discovery.build('cloudidentity', 'v1')
  group_id = get_group_id(service, 'clusterfuzz-dev@google.com')
  print(group_id)
  if not group_id:
    return
  check_transitive_membership(service, group_id, 'vtcosta@google.com')
