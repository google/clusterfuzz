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
"""Configuration Manager."""

from flask import request

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.config import db_config
from clusterfuzz._internal.datastore import data_types
from handlers import base_handler
from libs import form
from libs import handler
from libs import helpers

USER_PERMISSION_ENTITY_KINDS = [
    {
        'name': 'fuzzer',
        'value': data_types.PermissionEntityKind.FUZZER,
    },
    {
        'name': 'job',
        'value': data_types.PermissionEntityKind.JOB,
    },
    {
        'name': 'uploader',
        'value': data_types.PermissionEntityKind.UPLOADER,
    },
]

USER_PERMISSION_AUTO_CC_TYPES = [
    {
        'name': 'none',
        'value': data_types.AutoCCType.NONE,
    },
    {
        'name': 'all',
        'value': data_types.AutoCCType.ALL,
    },
    {
        'name': 'security',
        'value': data_types.AutoCCType.SECURITY,
    },
]


def get_value_by_name(item_list, name):
  """Return value for entry whose name matches the one in item list."""
  for item in item_list:
    if item['name'] == name:
      return item['value']

  return None


class Handler(base_handler.Handler):
  """Configuration manager."""

  @handler.get(handler.HTML)
  @handler.check_admin_access
  def get(self):
    """Handle a get request."""
    external_user_permissions = list(
        data_types.ExternalUserPermission.query().order(
            data_types.ExternalUserPermission.entity_kind,
            data_types.ExternalUserPermission.entity_name,
            data_types.ExternalUserPermission.email))

    template_values = {
        'config': db_config.get(),
        'permissions': external_user_permissions,
        'fieldValues': {
            'csrf_token': form.generate_csrf_token(),
            'user_permission_entity_kinds': USER_PERMISSION_ENTITY_KINDS,
            'user_permission_auto_cc_types': USER_PERMISSION_AUTO_CC_TYPES,
            'add_permission_url': '/add-external-user-permission',
            'delete_permission_url': '/delete-external-user-permission',
        }
    }

    helpers.log('Configuration', helpers.VIEW_OPERATION)
    return self.render('configuration.html', template_values)

  @handler.post(handler.FORM, handler.HTML)
  @handler.check_admin_access
  @handler.require_csrf_token
  def post(self):
    """Handle a post request."""
    config = db_config.get()
    if not config:
      config = data_types.Config()

    previous_hash = request.get('previous_hash')
    if config.previous_hash and config.previous_hash != previous_hash:
      raise helpers.EarlyExitException(
          'Your change conflicts with another configuration update. '
          'Please refresh and try again.', 500)

    build_apiary_service_account_private_key = request.get(
        'build_apiary_service_account_private_key')
    bug_report_url = request.get('bug_report_url')
    client_credentials = request.get('client_credentials')
    jira_url = request.get('jira_url')
    jira_credentials = request.get('jira_credentials')
    component_repository_mappings = request.get('component_repository_mappings')
    contact_string = request.get('contact_string')
    documentation_url = request.get('documentation_url')
    github_credentials = request.get('github_credentials')
    platform_group_mappings = request.get('platform_group_mappings')
    privileged_users = request.get('privileged_users')
    blacklisted_users = request.get('blacklisted_users')
    relax_security_bug_restrictions = request.get(
        'relax_security_bug_restrictions')
    relax_testcase_restrictions = request.get('relax_testcase_restrictions')
    reproduce_tool_client_id = request.get('reproduce_tool_client_id')
    reproduce_tool_client_secret = request.get('reproduce_tool_client_secret')
    reproduction_help_url = request.get('reproduction_help_url')
    test_account_email = request.get('test_account_email')
    test_account_password = request.get('test_account_password')
    wifi_ssid = request.get('wifi_ssid')
    wifi_password = request.get('wifi_password')
    sendgrid_api_key = request.get('sendgrid_api_key')
    sendgrid_sender = request.get('sendgrid_sender')

    config.build_apiary_service_account_private_key = (
        build_apiary_service_account_private_key)
    config.bug_report_url = bug_report_url
    config.client_credentials = client_credentials
    config.component_repository_mappings = component_repository_mappings
    config.contact_string = contact_string
    config.documentation_url = documentation_url
    config.github_credentials = github_credentials
    config.jira_credentials = jira_credentials
    config.jira_url = jira_url
    config.platform_group_mappings = platform_group_mappings
    config.privileged_users = privileged_users
    config.blacklisted_users = blacklisted_users
    config.relax_security_bug_restrictions = bool(
        relax_security_bug_restrictions)
    config.relax_testcase_restrictions = bool(relax_testcase_restrictions)
    config.reproduce_tool_client_id = reproduce_tool_client_id
    config.reproduce_tool_client_secret = reproduce_tool_client_secret
    config.reproduction_help_url = reproduction_help_url
    config.test_account_email = test_account_email
    config.test_account_password = test_account_password
    config.wifi_ssid = wifi_ssid
    config.wifi_password = wifi_password
    config.sendgrid_api_key = sendgrid_api_key
    config.sendgrid_sender = sendgrid_sender

    helpers.log('Configuration', helpers.MODIFY_OPERATION)

    # Before hashing the entity, we must put it so that the internal maps are
    # updated.
    config.put()
    config.previous_hash = utils.entity_hash(config)

    config.put()

    template_values = {
        'title':
            'Success',
        'message': ('Configuration is successfully updated. '
                    'Redirecting to the configuration page...'),
        'redirect_url':
            '/configuration',
    }
    return self.render('message.html', template_values)


class AddExternalUserPermission(base_handler.Handler):
  """Handles adding a new ExternalUserPermission."""

  @handler.post(handler.FORM, handler.HTML)
  @handler.check_admin_access
  @handler.require_csrf_token
  def post(self):
    """Handle a post request."""
    email = utils.normalize_email(request.get('email'))
    entity_kind = request.get('entity_kind')
    entity_name = request.get('entity_name')
    is_prefix = request.get('is_prefix')
    auto_cc = request.get('auto_cc')

    if not email:
      raise helpers.EarlyExitException('No email provided.', 400)

    if not entity_kind or entity_kind == 'undefined':
      raise helpers.EarlyExitException('No entity_kind provided.', 400)

    entity_kind = get_value_by_name(USER_PERMISSION_ENTITY_KINDS, entity_kind)
    if entity_kind is None:
      raise helpers.EarlyExitException('Invalid entity_kind provided.', 400)

    if entity_kind == data_types.PermissionEntityKind.UPLOADER:
      # Enforce null values for entity name and auto-cc when uploader is chosen.
      entity_name = None
      auto_cc = data_types.AutoCCType.NONE
    else:
      if not entity_name:
        raise helpers.EarlyExitException('No entity_name provided.', 400)

      if not auto_cc or auto_cc == 'undefined':
        raise helpers.EarlyExitException('No auto_cc provided.', 400)

      auto_cc = get_value_by_name(USER_PERMISSION_AUTO_CC_TYPES, auto_cc)
      if auto_cc is None:
        raise helpers.EarlyExitException('Invalid auto_cc provided.', 400)

    # Check for existing permission.
    query = data_types.ExternalUserPermission.query(
        data_types.ExternalUserPermission.email == email,
        data_types.ExternalUserPermission.entity_kind == entity_kind,
        data_types.ExternalUserPermission.entity_name == entity_name)

    permission = query.get()
    if not permission:
      # Doesn't exist, create new one.
      permission = data_types.ExternalUserPermission(
          email=email, entity_kind=entity_kind, entity_name=entity_name)

    permission.is_prefix = bool(is_prefix)
    permission.auto_cc = auto_cc
    permission.put()

    helpers.log('Configuration', helpers.MODIFY_OPERATION)
    template_values = {
        'title':
            'Success',
        'message':
            ('User %s permission for entity %s is successfully added. '
             'Redirecting to the configuration page...') % (email, entity_name),
        'redirect_url':
            '/configuration',
    }
    return self.render('message.html', template_values)


class DeleteExternalUserPermission(base_handler.Handler):
  """Handles deleting an ExternalUserPermission."""

  @handler.post(handler.FORM, handler.HTML)
  @handler.check_admin_access
  @handler.require_csrf_token
  def post(self):
    """Handle a post request."""
    email = request.get('email')
    entity_kind = request.get('entity_kind')
    entity_name = request.get('entity_name')

    if not email:
      raise helpers.EarlyExitException('No email provided.', 400)

    if not entity_kind or entity_kind == 'undefined':
      raise helpers.EarlyExitException('No entity_kind provided.', 400)

    entity_kind = get_value_by_name(USER_PERMISSION_ENTITY_KINDS, entity_kind)
    if entity_kind is None:
      raise helpers.EarlyExitException('Invalid entity_kind provided.', 400)

    if entity_kind == data_types.PermissionEntityKind.UPLOADER:
      entity_name = None
    else:
      if not entity_name:
        raise helpers.EarlyExitException('No entity_name provided.', 400)

    # Check for existing permission.
    permission = data_types.ExternalUserPermission.query(
        data_types.ExternalUserPermission.email == email,
        data_types.ExternalUserPermission.entity_kind == entity_kind,
        data_types.ExternalUserPermission.entity_name == entity_name).get()
    if not permission:
      raise helpers.EarlyExitException('Permission does not exist.', 400)
    permission.key.delete()

    helpers.log('Configuration', helpers.MODIFY_OPERATION)
    template_values = {
        'title':
            'Success',
        'message':
            ('User %s permission for entity %s is successfully deleted. '
             'Redirecting to the configuration page...') % (email, entity_name),
        'redirect_url':
            '/configuration',
    }
    return self.render('message.html', template_values)
