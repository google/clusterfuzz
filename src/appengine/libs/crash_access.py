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
"""Manage access to crash. There are 3 union access controls:
  1. Can access everything (maybe without security).
  2. Can access crashes with specific jobs.
  3. Can access crashes with specific fuzzers.

  Crash access control is used by the testcase list page and the crash stats
  page."""

import collections

from clusterfuzz._internal.base import external_users
from clusterfuzz._internal.datastore import data_types
from libs import access
from libs import helpers

Scope = collections.namedtuple('Scope', [
    'everything', 'is_privileged', 'job_types', 'fuzzer_names',
    'allowed_job_type'
])


def get_permission_names(entity_kind):
  """Get scoped fuzzer names."""
  # pylint: disable=protected-access
  permissions = external_users._get_permissions_query_for_user(
      helpers.get_user_email(), entity_kind)

  names = []
  for permission in permissions:
    suffix = '*' if permission.is_prefix else ''
    names.append(permission.entity_name + suffix)
  return names


def get_scope():
  """Get the scope object for the user."""
  user_email = helpers.get_user_email()
  is_privileged = access.has_access(need_privileged_access=True)
  everything = (is_privileged or access.has_access())

  # pylint: disable=protected-access
  job_types = external_users._allowed_entities_for_user(
      user_email, data_types.PermissionEntityKind.JOB)

  allowed_job_type = access.get_user_job_type()
  if allowed_job_type:
    job_types.append(allowed_job_type)

  # pylint: disable=protected-access
  fuzzer_names = external_users._allowed_entities_for_user(
      user_email, data_types.PermissionEntityKind.FUZZER)

  return Scope(everything, is_privileged, job_types, fuzzer_names,
               allowed_job_type)


def add_permissions_to_params(scope, params):
  """Add permissions to params."""
  params['permissions'] = {
      'everything': scope.everything,
      'isPrivileged': scope.is_privileged,
      'jobs': get_permission_names(data_types.PermissionEntityKind.JOB),
      'fuzzers': get_permission_names(data_types.PermissionEntityKind.FUZZER)
  }

  if scope.allowed_job_type:
    params['permissions']['jobs'].append(scope.allowed_job_type)


def add_scope(query, params, security_field, job_type_field, fuzzer_name_field):
  """Add scope to the query according to permissions and modify params."""
  scope = get_scope()
  add_permissions_to_params(scope, params)

  subqueries = []

  if scope.is_privileged:  # The user can access everything.
    return

  if scope.everything:
    everything_query = query.new_subquery()
    everything_query.filter(security_field, False)
    subqueries.append(everything_query)

  if scope.job_types:
    job_query = query.new_subquery()
    job_query.filter_in(job_type_field, scope.job_types)
    subqueries.append(job_query)

  if scope.fuzzer_names:
    fuzzer_query = query.new_subquery()
    fuzzer_query.filter_in(fuzzer_name_field, scope.fuzzer_names)
    subqueries.append(fuzzer_query)

  if not subqueries:  # The user CANNOT access anything.
    raise helpers.AccessDeniedException()

  query.union(*subqueries)
