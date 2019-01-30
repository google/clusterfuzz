# Copyright 2018 Google LLC
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

from config import db_config
from handlers import base_handler
from libs import helpers


class DocumentationHandler(base_handler.Handler):
  """Redirect to documentation."""

  def get(self):
    """Get the HTML page."""
    documentation_url = db_config.get_value('documentation_url')
    if not documentation_url:
      raise helpers.EarlyExitException(
          'Documentation url is not set in configuration.', 400)

    self.redirect(documentation_url)


class ReportBugHandler(base_handler.Handler):
  """Redirect to issue tracker for reporting bug."""

  def get(self):
    """Get the HTML page."""
    bug_report_url = db_config.get_value('bug_report_url')
    if not bug_report_url:
      raise helpers.EarlyExitException(
          'Bug report url is not set in configuration.', 400)

    self.redirect(bug_report_url)
