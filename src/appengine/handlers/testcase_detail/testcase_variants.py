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
"""Handler for getting testcase variants."""
from datastore import data_types
from handlers import base_handler
from libs import handler


class Handler(base_handler.Handler):
  """Handler that return testcase variants."""

  def get_variants(self, testcase):
    """Get testcase variants"""

    def _display_status(status):
      """Return status for display."""
      if status == data_types.TestcaseVariantStatus.PENDING:
        return 'Pending'
      elif status == data_types.TestcaseVariantStatus.REPRODUCIBLE:
        return 'Reproducible'
      elif status == data_types.TestcaseVariantStatus.FLAKY:
        return 'Flaky'
      elif status == data_types.TestcaseVariantStatus.UNREPRODUCIBLE:
        return 'Unreproducible'

      return 'Unknown'

    items = []
    variants = data_types.TestcaseVariant.query(
        data_types.TestcaseVariant.testcase_id == testcase.key.id()).order(
            data_types.TestcaseVariant.job_type)
    for variant in variants:
      if variant.status == data_types.TestcaseVariantStatus.UNREPRODUCIBLE:
        # Avoid showing these to keep table small and minimize confusion with
        # some unrelated job types in the same project.
        continue

      status = _display_status(variant.status)
      job = variant.job_type
      is_pending = variant.status == data_types.TestcaseVariantStatus.PENDING
      if is_pending:
        revision = None
        crash_type = None
        security_flag = None
        is_similar = None
        crash_state_lines = None
        reproducer_key = None
      else:
        revision = variant.revision
        crash_type = variant.crash_type
        crash_state_lines = variant.crash_state.strip().splitlines()
        security_flag = variant.security_flag
        is_similar = variant.is_similar
        reproducer_key = variant.reproducer_key

      items.append({
          'isPending': is_pending,
          'status': status,
          'job': job,
          'revision': revision,
          'crashType': crash_type,
          'crashStateLines': crash_state_lines,
          'securityFlag': security_flag,
          'isSimilar': is_similar,
          'reproducerKey': reproducer_key,
      })

    return items

  @handler.get(handler.JSON)
  @handler.check_testcase_access
  def get(self, testcase):
    """Return testcase variants."""
    response = {
        'items': self.get_variants(testcase),
    }
    self.render_json(response)
