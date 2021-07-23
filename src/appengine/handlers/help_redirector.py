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
"""Help."""

from clusterfuzz._internal.config import db_config
from handlers import base_handler

DEFAULT_DOCUMENTATION_URL = 'https://google.github.io/clusterfuzz/'
DEFAULT_BUG_REPORT_URL = 'https://github.com/google/clusterfuzz/issues'


class DocumentationHandler(base_handler.Handler):
  """Redirect to documentation."""

  def get(self):
    """Get the HTML page."""
    documentation_url = db_config.get_value('documentation_url')
    if not documentation_url:
      documentation_url = DEFAULT_DOCUMENTATION_URL

    return self.redirect(documentation_url)


class ReportBugHandler(base_handler.Handler):
  """Redirect to issue tracker for reporting bug."""

  def get(self):
    """Get the HTML page."""
    bug_report_url = db_config.get_value('bug_report_url')
    if not bug_report_url:
      bug_report_url = DEFAULT_BUG_REPORT_URL

    return self.redirect(bug_report_url)
