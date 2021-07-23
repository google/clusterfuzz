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
"""Library to manage bots using GCE instance templates and groups."""

import time

import google_auth_httplib2
import googleapiclient
from googleapiclient.discovery import build
import httplib2

from clusterfuzz._internal.base import retry
from clusterfuzz._internal.google_cloud_utils import credentials

RETRY_COUNT = 8
RETRY_DELAY = 4

REQUEST_TIMEOUT = 180

_SCOPES = [
    'https://www.googleapis.com/auth/cloud-platform',
]


class BotManagerException(Exception):
  """Base exception class."""


class OperationError(BotManagerException):
  """Errors during an operation."""


class RequestError(BotManagerException):
  """Errors during a request."""


class NotFoundError(RequestError):
  """Not found."""


class AlreadyExistsError(RequestError):
  """Already exists."""


class RetryableError(RequestError):
  """Retryable request error."""


class BotManager(object):
  """Manager for bots."""

  def __init__(self, project_id, zone):
    self.project_id = project_id
    self.zone = zone

    creds = credentials.get_default(scopes=_SCOPES)[0]
    http = google_auth_httplib2.AuthorizedHttp(
        creds, http=httplib2.Http(timeout=REQUEST_TIMEOUT))

    self.compute = build('compute', 'v1', http=http, cache_discovery=False)

  def instance_group(self, name):
    """Get an InstanceGroup resource with the given name."""
    return InstanceGroup(name, self)

  def instance_template(self, name):
    """Get an InstanceTemplate resource with the given name."""
    return InstanceTemplate(name, self)


class Resource(object):
  """Represents a resource."""

  _OPERATION_POLL_SECONDS = 5

  def __init__(self, name, manager):
    self.name = name
    self.manager = manager

  @property
  def compute(self):
    return self.manager.compute

  @property
  def project_id(self):
    return self.manager.project_id

  @property
  def zone(self):
    return self.manager.zone

  def get(self):
    raise NotImplementedError

  def exists(self):
    """Return whether or not the resource exists."""
    try:
      self.get()
      return True
    except NotFoundError:
      return False

  def _wait_for_operation(self, operation):
    """Wait for an operation to complete."""
    while True:
      if operation['status'] == 'DONE':
        if 'error' in operation:
          raise OperationError(operation['error'])

        return operation

      time.sleep(self._OPERATION_POLL_SECONDS)

      if 'zone' in operation:
        operation = self.compute.zoneOperations().get(
            project=self.project_id,
            zone=self.zone,
            operation=operation['name']).execute()
      else:
        operation = self.compute.globalOperations().get(
            project=self.project_id, operation=operation['name']).execute()

  def _identity(self, response):
    """Identify function for convenience."""
    return response

  @retry.wrap(
      RETRY_COUNT,
      RETRY_DELAY,
      'handlers.cron.helpers.bot_manager.Resource.execute',
      exception_type=RetryableError)
  def execute(self, request, result_proc=None):
    """Execute a request."""
    if result_proc is None:
      result_proc = self._wait_for_operation

    try:
      response = request.execute()
    except googleapiclient.errors.HttpError as e:
      if e.resp.status in [400, 403, 500, 503]:
        raise RetryableError(str(e))
      if e.resp.status == 404:
        raise NotFoundError(str(e))
      if e.resp.status == 409:
        raise AlreadyExistsError(str(e))

      raise RequestError(str(e))

    return result_proc(response)


class InstanceGroup(Resource):
  """Instance group."""

  # At least 80% of the instances should've been created. Some errors may be
  # expected because of limited resources in the zone.
  MIN_INSTANCES_RATIO = 0.8
  MAX_ERROR_RATIO = 1.0 - MIN_INSTANCES_RATIO

  def _wait_for_instances(self):
    """Wait for instance actions to complete."""
    while True:
      num_instances = 0
      instances_ready = 0
      errors = []

      for instance in self.list_managed_instances():
        num_instances += 1

        if instance['currentAction'] == 'NONE':
          instances_ready += 1
        elif 'lastAttempt' in instance and 'errors' in instance['lastAttempt']:
          errors.append(instance['lastAttempt']['errors'])

      if instances_ready >= max(1, num_instances * self.MIN_INSTANCES_RATIO):
        return

      if len(errors) > num_instances * self.MAX_ERROR_RATIO:
        raise OperationError(errors)

      time.sleep(1)

  def _handle_size_change(self, response):
    """Response handler for operations that change instances."""
    self._wait_for_operation(response)
    self._wait_for_instances()

  def get(self):
    """Get an instance group for a cluster."""
    return self.execute(
        self.compute.instanceGroupManagers().get(
            project=self.project_id,
            zone=self.zone,
            instanceGroupManager=self.name),
        result_proc=self._identity)

  def list_managed_instances(self, instance_filter=None):
    """List managed instances in the group."""
    next_page_token = None

    while True:
      response = self.execute(
          self.compute.instanceGroupManagers().listManagedInstances(
              project=self.project_id,
              zone=self.zone,
              instanceGroupManager=self.name,
              pageToken=next_page_token,
              filter=instance_filter),
          result_proc=self._identity)

      for instance in response['managedInstances']:
        if instance['currentAction'] != 'DELETING':
          # Instances can be stuck in DELETING, don't include them.
          yield instance

      if 'nextPageToken' in response:
        next_page_token = response['nextPageToken']
      else:
        break

  def create(self,
             base_instance_name,
             instance_template,
             size=0,
             wait_for_instances=True):
    """Create this instance group."""
    manager_body = {
        'baseInstanceName': base_instance_name,
        'instanceTemplate': 'global/instanceTemplates/' + instance_template,
        'name': self.name,
        'targetSize': size,
    }

    result_proc = None
    if wait_for_instances:
      result_proc = self._handle_size_change

    self.execute(
        self.compute.instanceGroupManagers().insert(
            project=self.project_id, zone=self.zone, body=manager_body),
        result_proc=result_proc)

  def resize(self, new_size, wait_for_instances=True):
    """Resize this instance group."""
    result_proc = None
    if wait_for_instances:
      result_proc = self._handle_size_change

    self.execute(
        self.compute.instanceGroupManagers().resize(
            project=self.project_id,
            zone=self.zone,
            instanceGroupManager=self.name,
            size=new_size),
        result_proc=result_proc)

  def delete(self):
    """Delete this instance group."""
    self.execute(self.compute.instanceGroupManagers().delete(
        project=self.project_id, zone=self.zone,
        instanceGroupManager=self.name))


class InstanceTemplate(Resource):
  """Instance template."""

  def get(self):
    """Get the instance template."""
    return self.execute(
        self.compute.instanceTemplates().get(
            instanceTemplate=self.name, project=self.project_id),
        result_proc=self._identity)

  def delete(self):
    """Delete the instance template."""
    self.execute(self.compute.instanceTemplates().delete(
        instanceTemplate=self.name, project=self.project_id))

  def create(self, template_body):
    """Create the instance template."""
    template_body['name'] = self.name
    self.execute(self.compute.instanceTemplates().insert(
        project=self.project_id, body=template_body))
