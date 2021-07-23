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
"""Handler that gets the testcase list page."""

from flask import request

from clusterfuzz._internal.base import errors
from clusterfuzz._internal.base import utils
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.google_cloud_utils import blobs
from handlers import base_handler
from libs import crash_access
from libs import filters
from libs import handler
from libs import helpers
from libs.query import datastore_query

PAGE_SIZE = 20
MORE_LIMIT = 100 - PAGE_SIZE  # exactly 5 pages
FIELDS = [
    'crash_type',
    'crash_state',
    'job_type',
    'open',
    'fixed',
    'regression',
    'one_time_crasher_flag',
    'security_flag',
    'bug_information',
    'group_bug_information',
    'group_id',
    'project_name',
    'platform',
    'impact_extended_stable_version',
    'impact_stable_version',
    'impact_beta_version',
    'impact_head_version',
    'is_impact_set_flag',
]


class GroupFilter(filters.Filter):
  """Filter for group."""

  def __init__(self):
    self.param_key = 'group'

  def add(self, query, params):
    """Add group filter."""
    value = params.get(self.param_key, '')
    if filters.is_empty(value):
      query.filter('is_leader', True)
      return
    query.filter('group_id', helpers.cast(value, int, "'group' must be int."))


KEYWORD_FILTERS = [
    GroupFilter(),
    filters.String('bug_indices', 'issue'),
    filters.String('platform', 'platform'),
    filters.String('impact_extended_stable_version_indices', 'extended_stable'),
    filters.String('impact_head_version_indices', 'head'),
    filters.String('impact_stable_version_indices', 'stable'),
    filters.String('impact_beta_version_indices', 'beta'),
    filters.String('fuzzer_name_indices', 'fuzzer'),
    filters.String('job_type', 'job'),
]

FILTERS = [
    filters.String('impact_version_indices', 'impact'),
    filters.Boolean('has_bug_flag', 'issue'),
    filters.Boolean('open', 'open'),
    filters.Boolean('security_flag', 'security'),
    filters.Keyword(KEYWORD_FILTERS, 'keywords', 'q'),
    filters.NegativeBoolean('one_time_crasher_flag', 'reproducible'),
    filters.String('job_type', 'job'),
    filters.String('fuzzer_name_indices', 'fuzzer'),
    filters.String('project_name', 'project'),
    filters.Int('crash_revision', 'revision_greater_than', operator='>')
]


def add_filters(query, params):
  """Add filters based on params."""
  if not filters.has_params(params, FILTERS) and not params.get('showall'):
    params['open'] = 'yes'

  query.filter('status', 'Processed')
  query.filter('is_a_duplicate_flag', False)

  # For queries that use inequality we need to order by that field. Otherwise,
  # use the timestamp.
  if 'revision_greater_than' in params:
    query.order('crash_revision', is_desc=True)
  else:
    query.order('timestamp', is_desc=True)

  filters.add(query, params, FILTERS)


def get_result():
  """Get the result for the testcase list page."""
  params = dict(request.iterparams())
  page = helpers.cast(request.get('page') or 1, int, "'page' is not an int.")

  query = datastore_query.Query(data_types.Testcase)
  crash_access.add_scope(query, params, 'security_flag', 'job_type',
                         'fuzzer_name_indices')
  add_filters(query, params)

  testcases, total_pages, total_items, has_more = query.fetch_page(
      page=page, page_size=PAGE_SIZE, projection=FIELDS, more_limit=MORE_LIMIT)

  items = []
  for testcase in testcases:
    regression_range = ''
    fixed_range = ''

    if testcase.regression and testcase.regression != 'NA':
      regression_range = testcase.regression
    if testcase.fixed and testcase.fixed != 'NA':
      fixed_range = testcase.fixed

    item = {
        'id': testcase.key.id(),
        'crashType': ' '.join(testcase.crash_type.splitlines()),
        'crashStateLines': testcase.crash_state.strip().splitlines(),
        'jobType': testcase.job_type,
        'isClosed': not testcase.open,
        'isFixed': testcase.fixed and testcase.fixed != 'NA',
        'isReproducible': not testcase.one_time_crasher_flag,
        'isSecurity': testcase.security_flag,
        'isImpactSet': testcase.is_impact_set_flag,
        'impacts': {
            'extendedStable': testcase.impact_extended_stable_version,
            'stable': testcase.impact_stable_version,
            'beta': testcase.impact_beta_version,
            'head': testcase.impact_head_version,
        },
        'regressionRange': regression_range,
        'fixedRange': fixed_range,
        'groupId': testcase.group_id,
        'projectName': testcase.project_name,
        'platform': testcase.platform,
        'issueId': testcase.bug_information or testcase.group_bug_information,
        'showImpacts': testcase.has_impacts(),
        'impactsProduction': testcase.impacts_production()
    }
    if testcase.timestamp:
      item['timestamp'] = utils.utc_datetime_to_timestamp(testcase.timestamp)

    items.append(item)

  helpers.log('Testcases', helpers.VIEW_OPERATION)

  result = {
      'hasMore': has_more,
      'items': items,
      'page': page,
      'pageSize': PAGE_SIZE,
      'totalItems': total_items,
      'totalPages': total_pages,
  }
  return result, params


class Handler(base_handler.Handler):
  """Handler that gets the testcase list when user first lands on the page."""

  @handler.get(handler.HTML)
  def get(self):
    """Get and render the testcase list in HTML."""
    result, params = get_result()
    field_values = {
        'projects':
            data_handler.get_all_project_names(),
        'fuzzers':
            data_handler.get_all_fuzzer_names_including_children(
                include_parents=True),
        'jobs':
            data_handler.get_all_job_type_names(),
        'shouldShowImpact':
            utils.is_chromium()
    }
    return self.render('testcase-list.html', {
        'fieldValues': field_values,
        'result': result,
        'params': params
    })


class CacheHandler(base_handler.Handler):
  """Handler for exercising cache."""

  @handler.cron()
  def get(self):
    """Handle a GET request."""
    # pylint: disable=unexpected-keyword-arg

    # Memoize all project and job names.
    _ = data_handler.get_all_project_names(__memoize_force__=True)
    _ = data_handler.get_all_job_type_names(__memoize_force__=True)

    # Memoize both variants of get_all_fuzzer_names_including_children.
    _ = data_handler.get_all_fuzzer_names_including_children(
        include_parents=True, __memoize_force__=True)
    _ = data_handler.get_all_fuzzer_names_including_children(
        __memoize_force__=True)

    # Memoize expensive testcase attribute calls.
    for testcase_id in data_handler.get_open_testcase_id_iterator():
      try:
        testcase = data_handler.get_testcase_by_id(testcase_id)
      except errors.InvalidTestcaseError:
        # Already deleted.
        continue

      blobs.get_blob_size(testcase.fuzzed_keys)
      blobs.get_blob_size(testcase.minimized_keys)


class JsonHandler(base_handler.Handler):
  """Handler that gets the testcase list when user clicks on next page."""

  @handler.post(handler.JSON, handler.JSON)
  @handler.oauth
  def post(self):
    """Get and render the testcase list in JSON."""
    result, _ = get_result()
    return self.render_json(result)
