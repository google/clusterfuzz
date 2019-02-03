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
"""Manage job types."""

from base import tasks
from datastore import data_handler
from datastore import data_types
from fuzzing import fuzzer_selection
from handlers import base_handler
from libs import form
from libs import gcs
from libs import handler
from libs import helpers


def get_queues():
  """Return list of task queues."""
  queues = []
  for name, display_name in tasks.TASK_QUEUE_DISPLAY_NAMES.iteritems():
    queue = {
        'name': name,
        'display_name': display_name,
    }
    queues.append(queue)

  queues.sort(key=lambda q: q['display_name'])
  return queues


class Handler(base_handler.Handler):
  """Manage sets of environment variables for bots."""

  @handler.check_user_access(need_privileged_access=True)
  @handler.get(handler.HTML)
  def get(self):
    """Handle a get request."""
    helpers.log('Jobs', helpers.VIEW_OPERATION)

    template_values = self.get_results()
    self.render('jobs.html', template_values)

  @staticmethod
  def get_results():
    """Get results for the jobs page."""
    jobs = list(data_types.Job.query().order(data_types.Job.name))
    templates = list(data_types.JobTemplate.query().order(
        data_types.JobTemplate.name))
    queues = get_queues()

    return {
        'jobs': jobs,
        'templates': templates,
        'fieldValues': {
            'csrf_token': form.generate_csrf_token(),
            'queues': queues,
            'update_job_url': '/update-job',
            'update_job_template_url': '/update-job-template',
            'upload_info': gcs.prepare_blob_upload()._asdict(),
        },
    }


class UpdateJob(base_handler.GcsUploadHandler):
  """Job update handler."""

  @handler.check_user_access(need_privileged_access=True)
  @handler.require_csrf_token
  def post(self):
    """Handle a post request."""
    name = self.request.get('name')
    if not name:
      raise helpers.EarlyExitException('Please give this job a name!', 400)

    if not data_types.Job.VALID_NAME_REGEX.match(name):
      raise helpers.EarlyExitException(
          'Job name can only contain letters, numbers, dashes and underscores.',
          400)

    templates = self.request.get('templates', '').splitlines()
    for template in templates:
      if not data_types.JobTemplate.query(
          data_types.JobTemplate.name == template).get():
        raise helpers.EarlyExitException('Invalid template name(s) specified.',
                                         400)

    new_platform = self.request.get('platform')
    if not new_platform or new_platform == 'undefined':
      raise helpers.EarlyExitException('No platform provided for job.', 400)

    description = self.request.get('description', '')
    environment_string = self.request.get('environment_string', '')
    previous_custom_binary_revision = 0

    job = data_types.Job.query(data_types.Job.name == name).get()
    recreate_fuzzer_mappings = False
    if not job:
      job = data_types.Job()
    else:
      previous_custom_binary_revision = job.custom_binary_revision
      if previous_custom_binary_revision is None:
        previous_custom_binary_revision = 0
      if new_platform != job.platform:
        # The rare case of modifying a job's platform causes many problems with
        # task selection. If a job is leased from the old queue, the task will
        # be recreated in the correct queue at lease time. Fuzzer mappings must
        # be purged and recreated, since they depend on the job's platform.
        recreate_fuzzer_mappings = True

    job.name = name
    job.platform = new_platform
    job.description = description
    job.environment_string = environment_string
    job.templates = templates

    blob_info = self.get_upload()
    if blob_info:
      job.custom_binary_key = str(blob_info.key())
      job.custom_binary_filename = blob_info.filename
      job.custom_binary_revision = previous_custom_binary_revision + 1

    if job.custom_binary_key and 'CUSTOM_BINARY' not in job.environment_string:
      job.environment_string += '\nCUSTOM_BINARY = True'

    job.put()

    if recreate_fuzzer_mappings:
      fuzzer_selection.update_platform_for_job(name, new_platform)

    # pylint: disable=unexpected-keyword-arg
    _ = data_handler.get_all_job_type_names(__memoize_force__=True)

    helpers.log('Job created %s' % name, helpers.MODIFY_OPERATION)
    template_values = {
        'title':
            'Success',
        'message': ('Job %s is successfully updated. '
                    'Redirecting back to jobs page...') % name,
        'redirect_url':
            '/jobs',
    }
    self.render('message.html', template_values)


class UpdateJobTemplate(base_handler.Handler):
  """Update job template."""

  @handler.check_user_access(need_privileged_access=True)
  @handler.require_csrf_token
  @handler.post(handler.FORM, handler.HTML)
  def post(self):
    """Handle a post request."""
    name = self.request.get('name')
    if not name:
      raise helpers.EarlyExitException('Please give this template a name!', 400)

    if not data_types.Job.VALID_NAME_REGEX.match(name):
      raise helpers.EarlyExitException(
          'Template name can only contain letters, numbers, dashes and '
          'underscores.', 400)

    environment_string = self.request.get('environment_string')
    if not environment_string:
      raise helpers.EarlyExitException(
          'No environment string provided for job template.', 400)

    template = data_types.JobTemplate.query(
        data_types.JobTemplate.name == name).get()
    if not template:
      template = data_types.JobTemplate()

    template.name = name
    template.environment_string = environment_string
    template.put()

    helpers.log('Template created %s' % name, helpers.MODIFY_OPERATION)

    template_values = {
        'title':
            'Success',
        'message': ('Template %s is successfully updated. '
                    'Redirecting back to jobs page...') % name,
        'redirect_url':
            '/jobs',
    }
    self.render('message.html', template_values)
