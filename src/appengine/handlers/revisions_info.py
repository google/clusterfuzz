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

from build_management import revisions
from handlers import base_handler
from libs import handler
from libs import helpers


class Handler(base_handler.Handler):
  """Information on a revision range."""

  @handler.get(handler.HTML)
  def get(self):
    """GET handler."""
    revision_range = self.request.get('range')
    job_type = self.request.get('job')

    try:
      [start_revision, end_revision] = revision_range.split(':')
    except:
      raise helpers.EarlyExitException('Bad revision range.', 400)

    component_revisions_list = revisions.get_component_range_list(
        start_revision, end_revision, job_type)
    if not component_revisions_list:
      raise helpers.EarlyExitException('Failed to get component revisions.',
                                       400)

    self.render('revisions-info.html',
                {'info': {
                    'componentRevisionsList': component_revisions_list
                }})
