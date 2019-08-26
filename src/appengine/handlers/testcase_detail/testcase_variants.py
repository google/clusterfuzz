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

      is_pending = variant.status == data_types.TestcaseVariantStatus.PENDING
      item = {
          'isPending': is_pending,
          'status': _display_status(variant.status),
          'job': variant.job_type,
      }
      if not is_pending:
        item.update({
            'revision': variant.revision,
            'crashType': variant.crash_type,
            'crashStateLines': variant.crash_state.strip().splitlines(),
            'securityFlag': variant.security_flag,
            'isSimilar': variant.is_similar,
            'reproducerKey': variant.reproducer_key,
        })
      items.append(item)

    return items

  @handler.get(handler.JSON)
  @handler.check_testcase_access
  def get(self, testcase):
    """Return testcase variants."""
    response = {
        'items': self.get_variants(testcase),
    }
    self.render_json(response)
