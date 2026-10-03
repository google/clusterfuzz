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
"""Display information for revision ranges."""

from flask import request

from clusterfuzz._internal.build_management import revisions
from clusterfuzz._internal.datastore import data_types
from handlers import base_handler
from libs import access
from libs import handler
from libs import helpers


def get_component_revisions_list(job_type, revision, revision_range):
  """Resolve the component revision list for a job.

  The result is per-job data, so callers must be authorized for the job.
  """
  if not job_type:
    raise helpers.EarlyExitError('Job name cannot be empty.', 400)

  if not data_types.Job.VALID_NAME_REGEX.match(job_type):
    raise helpers.EarlyExitError('Invalid job name.', 400)

  # Component revisions are per-job data; gate on job access like the other
  # job-scoped handlers (e.g. coverage_report, fuzzer_stats). @handler.oauth
  # authenticates the caller but does not authorize access to an arbitrary job,
  # so without this any caller could disclose the component/repo/revision list
  # for a job (and project) they cannot otherwise access.
  if not access.has_access(job_type=job_type):
    raise helpers.AccessDeniedError()

  if revision:
    if not revision.isdigit():
      raise helpers.EarlyExitError('Revision is not an integer.', 400)
    start_revision = end_revision = revision
  elif revision_range:
    try:
      start_revision, end_revision = revision_range.split(':')
    except:
      raise helpers.EarlyExitError('Bad revision range.', 400)

    if not start_revision.isdigit():
      raise helpers.EarlyExitError('Start revision is not an integer.', 400)
    if not end_revision.isdigit():
      raise helpers.EarlyExitError('End revision is not an integer.', 400)
  else:
    raise helpers.EarlyExitError('No revision specified.', 400)

  component_revisions_list = revisions.get_component_range_list(
      start_revision, end_revision, job_type)
  if not component_revisions_list:
    raise helpers.EarlyExitError('Failed to get component revisions.', 400)

  return component_revisions_list


class Handler(base_handler.Handler):
  """Information on a revision range."""

  @handler.get(handler.HTML)
  @handler.oauth
  def get(self):
    """GET handler."""
    job_type = request.get('job')
    revision = request.get('revision')
    revision_range = request.get('range')

    component_revisions_list = get_component_revisions_list(
        job_type, revision, revision_range)

    return self.render(
        'revisions-info.html',
        {'info': {
            'componentRevisionsList': component_revisions_list
        }})
