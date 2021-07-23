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
"""Service account creation/role helpers."""
import logging

import googleapiclient

from clusterfuzz._internal.base import utils

_ACCOUNT_PREFIX = 'bot-'
_MIN_LEN = 6
_MAX_LEN = 30
_HASH_PREFIX_LEN = _MAX_LEN - len(_ACCOUNT_PREFIX)


def _create_client(service_name, version='v1'):
  """Create a googleapiclient client."""
  return googleapiclient.discovery.build(service_name, version)


def _service_account_email(project_id, service_account_id):
  """Return full service account email."""
  return '%s@%s.iam.gserviceaccount.com' % (service_account_id, project_id)


def _service_account_id(project):
  """Return service account ID for project."""
  # From
  # cloud.google.com/iam/reference/rest/v1/projects.serviceAccounts/create:
  #
  # The account id that is used to generate the service account email address
  # and a stable unique id. It is unique within a project, must be 6-30
  # characters long, and match the regular expression [a-z]([-a-z0-9]*[a-z0-9])
  # to comply with RFC1035.
  account_id = _ACCOUNT_PREFIX + project.replace('_', '-')
  if not account_id[-1].isalnum():
    # Must end in '[a-z][0-9]'.
    account_id += '0'

  if len(account_id) < _MIN_LEN:
    # Must be at least |min_len| in length.
    account_id = account_id.ljust(_MIN_LEN, '0')

  # Use a hash prefix as the service account name if the project name is too
  # long.
  if len(account_id) > _MAX_LEN:
    account_id = _ACCOUNT_PREFIX + utils.string_hash(project)[:_HASH_PREFIX_LEN]

  assert len(account_id) >= _MIN_LEN and len(account_id) <= _MAX_LEN
  return account_id


def get_service_account(iam, project_id, service_account_id):
  """Try to get a service account. Returns None if it does not exist."""
  try:
    request = iam.projects().serviceAccounts().get(
        name='projects/{0}/serviceAccounts/{1}'.format(
            project_id, _service_account_email(project_id, service_account_id)))

    return request.execute()
  except googleapiclient.errors.HttpError as e:
    if e.resp.status == 404:
      return None

    raise


def get_or_create_service_account(project):
  """Get or create service account for the project."""
  iam = _create_client('iam')
  project_id = utils.get_application_id()
  service_account_id = _service_account_id(project)

  service_account = get_service_account(iam, project_id, service_account_id)
  if service_account:
    logging.info('Using existing new service account for %s.', project)
    return service_account

  logging.info('Creating new service account for %s.', project)
  request = iam.projects().serviceAccounts().create(
      name='projects/' + project_id,
      body={
          'accountId': service_account_id,
          'serviceAccount': {
              'displayName': project,
          }
      })

  return request.execute()


def _get_or_insert_iam_binding(policy, role):
  """Return the binding corresponding to the given role. Creates the binding if
  needed."""
  existing_binding = next(
      (binding for binding in policy['bindings'] if binding['role'] == role),
      None)
  if existing_binding:
    return existing_binding

  new_binding = {
      'role': role,
      'members': [],
  }

  policy['bindings'].append(new_binding)
  return new_binding


def _add_service_account_role(policy, role, service_account):
  """Add a role to a service account. Returns whether or not changes were
  made."""
  binding = _get_or_insert_iam_binding(policy, role)

  service_account_member = 'serviceAccount:' + service_account
  if service_account_member not in binding['members']:
    binding['members'].append(service_account_member)
    return True

  return False


def set_service_account_roles(service_account):
  """Set roles for service account."""
  project_id = utils.get_application_id()
  resource_manager = _create_client('cloudresourcemanager')

  request = resource_manager.projects().getIamPolicy(
      resource=project_id, body={})
  policy = request.execute()

  # Set logging and metrics permissions.
  policy_changed = False
  policy_changed |= _add_service_account_role(policy, 'roles/logging.logWriter',
                                              service_account['email'])
  policy_changed |= _add_service_account_role(
      policy, 'roles/monitoring.metricWriter', service_account['email'])

  if not policy_changed:
    return

  request = resource_manager.projects().setIamPolicy(
      resource=project_id, body={
          'policy': policy,
      })
  request.execute()
