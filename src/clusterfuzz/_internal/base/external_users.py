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
"""External user permission utilities."""

from clusterfuzz._internal.base import memoize
from clusterfuzz._internal.base import utils
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import fuzz_target_utils
from clusterfuzz._internal.datastore import ndb_utils

MEMCACHE_TTL_IN_SECONDS = 15 * 60


def _fuzzers_for_job(job_type, include_parents):
  """Return all fuzzers that have the job associated.

  Args:
    job_type: The job type.
    include_parents: Include the parent fuzzer.

  Returns:
    A list of fuzzer names.
  """
  fuzzers = []
  engine_fuzzers = data_handler.get_fuzzing_engines()

  for fuzzer in data_types.Fuzzer.query(data_types.Fuzzer.jobs == job_type):
    # Add this if we're including all parents or this is not an engine fuzzer
    # with fuzz targets.
    if include_parents or fuzzer.name not in engine_fuzzers:
      fuzzers.append(fuzzer.name)

  for target_job in fuzz_target_utils.get_fuzz_target_jobs(job=job_type):
    fuzzers.append(target_job.fuzz_target_name)

  return sorted(fuzzers)


def _expand_prefix(all_names, prefix):
  """Expand the given prefix into real entity names.

  Args:
    all_names: A list of all entity names.
    prefix: A prefix string.

  Returns:
    A list of entity names that the pattern expands to.
  """
  return [name for name in all_names if name.startswith(prefix)]


def _get_permissions_query_for_user(user_email, entity_kind=None):
  """Get a permissions query for a given user.

  Args:
    user_email: The email of the user.
    entity_kind: The type (data_types.PermissionEntityKind) of the permission to
        filter by, or None.

  Returns:
    A ndb.Query giving the permissions for the given parameters.
  """
  permissions_for_user = data_types.ExternalUserPermission.query(
      data_types.ExternalUserPermission.email == utils.normalize_email(
          user_email))

  if entity_kind is not None:
    permissions_for_user = permissions_for_user.filter(
        data_types.ExternalUserPermission.entity_kind == entity_kind)

  return permissions_for_user


def _allowed_entities_for_user(user_email, entity_kind):
  """Return the entity names that the given user can access.

  Args:
    user_email: The email of the user.
    entity_kind: The type (data_types.PermissionEntityKind) of the entity.

  Returns:
    A list of entity names that the user has access to.
  """
  if not user_email:
    return []

  allowed = []
  permissions = _get_permissions_query_for_user(user_email, entity_kind)

  if entity_kind == data_types.PermissionEntityKind.FUZZER:
    all_names = data_handler.get_all_fuzzer_names_including_children()
  else:
    all_names = data_handler.get_all_job_type_names()

  for permission in permissions:
    if permission.is_prefix:
      allowed.extend(_expand_prefix(all_names, permission.entity_name))
    elif permission.entity_name in all_names:
      allowed.append(permission.entity_name)

  return sorted(allowed)


def _is_entity_allowed_for_user(user_email, name, entity_kind):
  """Return whether if the given user has access to the entity.

  Args:
    user_email: The email of the user.
    name: The name of the entity.
    entity_kind: The type of the entity.

  Returns:
    A bool indicating whether the given user has access to the entity.
  """
  if not user_email or not name:
    return False

  permissions = _get_permissions_query_for_user(user_email, entity_kind)

  for permission in permissions:
    if permission.is_prefix:
      if name.startswith(permission.entity_name):
        return True
    elif permission.entity_name == name:
      return True

  return False


def _allowed_users_for_entity(name, entity_kind, auto_cc=None):
  """Return a list of users that have permissions for the given entity.

  Args:
    name: The name of the entity.
    entity_kind: The type (data_types.PermissionEntityKind) of the entity.
    auto_cc: The Auto CC type (data_types.AutoCCType) to filter on, or None.

  Returns:
    A list of user emails that have permission to access the given entity.
  """
  if not name:
    return []

  # Easy case: direct matches.
  direct_match_permissions = data_types.ExternalUserPermission.query(
      data_types.ExternalUserPermission.entity_kind == entity_kind,
      data_types.ExternalUserPermission.entity_name == name,
      ndb_utils.is_false(data_types.ExternalUserPermission.is_prefix),
      projection=[data_types.ExternalUserPermission.email])
  if auto_cc is not None:
    direct_match_permissions = direct_match_permissions.filter(
        data_types.ExternalUserPermission.auto_cc == auto_cc)

  allowed_users = [permission.email for permission in direct_match_permissions]

  # Find all permissions where the prefix matches the fuzzer_name.
  # Unfortunately, Datastore doesn't give us an easy way of doing so. To iterate
  # through a smaller set than every single permission, get all permissions that
  # contain a prefix string <= than the actual fuzzer name and >= the first
  # character.
  prefix_match_permissions = data_types.ExternalUserPermission.query(
      data_types.ExternalUserPermission.entity_kind == entity_kind,
      data_types.ExternalUserPermission.entity_name <= name,
      data_types.ExternalUserPermission.entity_name >= name[0],
      ndb_utils.is_true(data_types.ExternalUserPermission.is_prefix),
      projection=[
          data_types.ExternalUserPermission.email,
          data_types.ExternalUserPermission.entity_name
      ])
  if auto_cc is not None:
    prefix_match_permissions = prefix_match_permissions.filter(
        data_types.ExternalUserPermission.auto_cc == auto_cc)

  for permission in prefix_match_permissions:
    if not permission.entity_name:
      # No external user should have an empty prefix (access to all
      # fuzzers/jobs).
      continue

    if name.startswith(permission.entity_name):
      allowed_users.append(permission.email)

  return sorted(allowed_users)


def _cc_users_for_entity(name, entity_type, security_flag):
  """Return CC users for entity."""
  users = _allowed_users_for_entity(name, entity_type,
                                    data_types.AutoCCType.ALL)

  if security_flag:
    users.extend(
        _allowed_users_for_entity(name, entity_type,
                                  data_types.AutoCCType.SECURITY))

  return sorted(users)


@memoize.wrap(memoize.Memcache(MEMCACHE_TTL_IN_SECONDS))
def allowed_fuzzers_for_user(user_email,
                             include_from_jobs=False,
                             include_parents=False):
  """Return allowed fuzzers for the given user.

  Args:
    user_email: The email of the user.
    include_from_jobs: Include all fuzzers for the allowed jobs of the user.
    include_parents: Include parent fuzzers when there is no explicit permission
        for the parent fuzzer, but there are permissions for its children as a
        result of the user's job permissions. Only applies when
        include_from_jobs is set.

  Returns:
    A list of fuzzer names for which this user is allowed to view information
    about.
  """
  allowed_fuzzers = _allowed_entities_for_user(
      user_email, data_types.PermissionEntityKind.FUZZER)

  if include_from_jobs:
    allowed_jobs = allowed_jobs_for_user(user_email)
    for allowed_job in allowed_jobs:
      allowed_fuzzers.extend(_fuzzers_for_job(allowed_job, include_parents))

    allowed_fuzzers = list(set(allowed_fuzzers))

  return sorted(allowed_fuzzers)


@memoize.wrap(memoize.Memcache(MEMCACHE_TTL_IN_SECONDS))
def allowed_jobs_for_user(user_email):
  """Return allowed jobs for the given user.

  Args:
    user_email: The email of the user.

  Returns:
    A list of job names for which this user is allowed to view information
    about.
  """
  return _allowed_entities_for_user(user_email,
                                    data_types.PermissionEntityKind.JOB)


def allowed_users_for_fuzzer(fuzzer_name):
  """Return allowed external users for the given fuzzer.

  Args:
    fuzzer_name: The name of the fuzzer.

  Returns:
    A list of user emails that are allowed to view information relating to this
    fuzzer.
  """
  # TODO(ochang): Once we support jobs, take that into account.
  return _allowed_users_for_entity(fuzzer_name,
                                   data_types.PermissionEntityKind.FUZZER)


def cc_users_for_fuzzer(fuzzer_name, security_flag):
  """Return external users that should be CC'ed according to the given rule.

  Args:
    fuzzer_name: The name of the fuzzer.
    security_flag: Whether or not the CC is for a security issue.

  Returns:
    A list of user emails that should be CC'ed.
  """
  return _cc_users_for_entity(
      fuzzer_name, data_types.PermissionEntityKind.FUZZER, security_flag)


def is_fuzzer_allowed_for_user(user_email, fuzzer_name,
                               include_from_jobs=False):
  """Return whether if the given user has access to the fuzzer.

  Args:
    user_email: The email of the user.
    fuzzer_name: The name of the fuzzer.
    include_from_jobs: Include all fuzzers for the allowed jobs of the user.

  Returns:
    A bool indicating whether the given user has access to the fuzzer.
  """
  is_allowed = _is_entity_allowed_for_user(
      user_email, fuzzer_name, data_types.PermissionEntityKind.FUZZER)

  if not is_allowed and include_from_jobs:
    is_allowed = fuzzer_name in allowed_fuzzers_for_user(
        user_email, include_from_jobs=True)

  return is_allowed


def is_job_allowed_for_user(user_email, job_type):
  """Return whether if the given user has access to the job.

  Args:
    user_email: The email of the user.
    job_type: The name of the job.

  Returns:
    A bool indicating whether the given user has access to the job.
  """
  return _is_entity_allowed_for_user(user_email, job_type,
                                     data_types.PermissionEntityKind.JOB)


def is_upload_allowed_for_user(user_email):
  """Return whether if the given user has upload permissions.

  Args:
    user_email: The email of the user.

  Returns:
    A bool indicating whether the given user has upload permissions.
  """
  permissions = _get_permissions_query_for_user(
      user_email, data_types.PermissionEntityKind.UPLOADER)
  return bool(permissions.get())


def cc_users_for_job(job_type, security_flag):
  """Return external users that should be CC'ed according to the given rule.

  Args:
    job_type: The name of the job
    security_flag: Whether or not the CC is for a security issue.

  Returns:
    A list of user emails that should be CC'ed.
  """
  return _cc_users_for_entity(job_type, data_types.PermissionEntityKind.JOB,
                              security_flag)
