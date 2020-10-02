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
"""Impact task.
   Determine whether or not a test case affects production branches."""

import six

from base import tasks
from base import utils
from bot import testcase_manager
from bot.tasks import setup
from build_management import build_manager
from build_management import revisions
from datastore import data_handler
from datastore import data_types
from system import environment


class BuildFailedException(Exception):
  """Represents the build failure."""


class AppFailedException(Exception):
  """Represents the app failure."""


class Impact(object):
  """Represents impact on a build type."""

  def __init__(self, version='', likely=False, extra_trace=''):
    self.version = str(version)
    self.likely = likely
    self.extra_trace = extra_trace

  def is_empty(self):
    """Return True if empty."""
    return not self.version

  def __eq__(self, other):
    return (self.version == other.version and self.likely == other.likely and
            self.extra_trace == other.extra_trace)


class Impacts(object):
  """Represents both stable and beta impacts."""

  def __init__(self, stable=None, beta=None):
    self.stable = stable or Impact()
    self.beta = beta or Impact()

  def is_empty(self):
    return self.stable.is_empty() and self.beta.is_empty()

  def get_extra_trace(self):
    return (self.stable.extra_trace + '\n' + self.beta.extra_trace).strip()

  def __eq__(self, other):
    return self.stable == other.stable and self.beta == other.beta


def get_chromium_component_start_and_end_revision(start_revision, end_revision,
                                                  job_type):
  """Get revisions from chromium component."""
  component_rev_list = revisions.get_component_range_list(
      start_revision, end_revision, job_type)

  for component_rev in component_rev_list:
    if component_rev['component'] == 'Chromium':
      start_revision, end_revision = (
          revisions.get_start_and_end_revision(component_rev['link_text']))

  return start_revision, end_revision


def get_start_and_end_revision(regression_range, job_type):
  """Get start and end revision."""
  start_revision, end_revision = revisions.get_start_and_end_revision(
      regression_range)

  # FIXME: Hack to use chromium revision for android builds.
  if environment.is_android():
    return get_chromium_component_start_and_end_revision(
        start_revision, end_revision, job_type)

  return start_revision, end_revision


def get_component_information_by_name(chromium_revision,
                                      component_display_name):
  """Returns a dictionary with information about a component at a revision."""
  lower_name = component_display_name.lower()
  component_revisions = revisions.get_component_revisions_dict(
      chromium_revision, None)
  if component_revisions is None:
    return None

  all_details = []
  for value in six.itervalues(component_revisions):
    if value and 'name' in value and value['name'].lower() == lower_name:
      all_details.append(value)
  # If we found several components with the same name, return nothing useful.
  if len(all_details) == 1:
    return all_details[0]
  return None


def get_component_impacts_from_url(component_name,
                                   regression_range,
                                   job_type,
                                   platform=None):
  """Gets component impact string using the build information url."""
  start_revision, end_revision = get_start_and_end_revision(
      regression_range, job_type)
  if not end_revision:
    return Impacts()

  found_impacts = dict()
  for build in ['stable', 'beta']:
    build_revision_mappings = revisions.get_build_to_revision_mappings(platform)
    if not build_revision_mappings:
      return Impacts()
    mapping = build_revision_mappings.get(build)
    if not mapping:
      return Impacts()
    chromium_revision = mapping['revision']
    component_revision = get_component_information_by_name(
        chromium_revision, component_name)
    if not component_revision:
      return Impacts()
    branched_from = revisions.revision_to_branched_from(
        component_revision['url'], component_revision['rev'])
    if not branched_from:
      return Impacts()
    impact = get_impact({
        'revision': branched_from,
        'version': mapping['version']
    }, start_revision, end_revision)
    found_impacts[build] = impact
  return Impacts(found_impacts['stable'], found_impacts['beta'])


def get_impacts_from_url(regression_range, job_type, platform=None):
  """Gets impact string using the build information url."""
  component_name = data_handler.get_component_name(job_type)
  if component_name:
    return get_component_impacts_from_url(component_name, regression_range,
                                          job_type, platform)

  start_revision, end_revision = get_start_and_end_revision(
      regression_range, job_type)
  if not end_revision:
    return Impacts()

  build_revision_mappings = revisions.get_build_to_revision_mappings(platform)
  if not build_revision_mappings:
    return Impacts()

  stable = get_impact(
      build_revision_mappings.get('stable'), start_revision, end_revision)
  beta = get_impact(
      build_revision_mappings.get('beta'), start_revision, end_revision)

  return Impacts(stable, beta)


def get_impact(build_revision, start_revision, end_revision):
  """Return a Impact object represents the impact on a given build_type. Or
    return None."""
  if not build_revision:
    return Impact()

  revision = build_revision['revision']
  if not revision.isdigit():
    return Impact()

  revision = int(revision)

  if start_revision > revision:
    return Impact()

  version = build_revision['version']
  if end_revision < revision:
    return Impact(version, likely=False)

  # We can't figure out the impact, but it is likely.
  return Impact(version, likely=True)


def get_impacts_on_prod_builds(testcase, testcase_file_path):
  """Get testcase impact on production builds, which are stable and beta."""
  impacts = Impacts()
  try:
    impacts.stable = get_impact_on_build(
        'stable', testcase.impact_stable_version, testcase, testcase_file_path)
  except AppFailedException:
    return get_impacts_from_url(testcase.regression, testcase.job_type)

  try:
    impacts.beta = get_impact_on_build('beta', testcase.impact_beta_version,
                                       testcase, testcase_file_path)
  except AppFailedException:
    # If beta fails to get the binary, we ignore. At least, we have stable.
    pass

  return impacts


def get_impact_on_build(build_type, current_version, testcase,
                        testcase_file_path):
  """Return impact and additional trace on a prod build given build_type."""
  build = build_manager.setup_production_build(build_type)
  if not build:
    raise BuildFailedException(
        'Build setup failed for %s' % build_type.capitalize())

  if not build_manager.check_app_path():
    raise AppFailedException()

  version = build.revision
  if version == current_version:
    return Impact(current_version, likely=False)

  app_path = environment.get_value('APP_PATH')
  command = testcase_manager.get_command_line_for_application(
      testcase_file_path, app_path=app_path, needs_http=testcase.http_flag)
  result = testcase_manager.test_for_crash_with_retries(
      testcase,
      testcase_file_path,
      environment.get_value('TEST_TIMEOUT'),
      http_flag=testcase.http_flag)

  if result.is_crash():
    symbolized_crash_stacktrace = result.get_stacktrace(symbolized=True)
    unsymbolized_crash_stacktrace = result.get_stacktrace(symbolized=False)
    stacktrace = utils.get_crash_stacktrace_output(
        command, symbolized_crash_stacktrace, unsymbolized_crash_stacktrace,
        build_type)
    return Impact(version, likely=False, extra_trace=stacktrace)

  return Impact()


def set_testcase_with_impacts(testcase, impacts):
  """Set testcase's impact-related fields given impacts."""
  testcase.impact_stable_version = impacts.stable.version
  testcase.impact_stable_version_likely = impacts.stable.likely
  testcase.impact_beta_version = impacts.beta.version
  testcase.impact_beta_version_likely = impacts.beta.likely
  testcase.is_impact_set_flag = True


def execute_task(testcase_id, job_type):
  """Attempt to find if the testcase affects release branches on Chromium."""
  # This shouldn't ever get scheduled, but check just in case.
  if not utils.is_chromium():
    return

  # Locate the testcase associated with the id.
  testcase = data_handler.get_testcase_by_id(testcase_id)

  # If this testcase is fixed, we should no longer be doing impact testing.
  if testcase.fixed and testcase.is_impact_set_flag:
    return

  # For testcases with status unreproducible, we just do impact analysis just
  # once.
  if testcase.is_status_unreproducible() and testcase.is_impact_set_flag:
    return

  # Update comments only after checking the above bailout conditions.
  data_handler.update_testcase_comment(testcase, data_types.TaskState.STARTED)

  # This task is not applicable to unreproducible testcases.
  if testcase.one_time_crasher_flag:
    data_handler.update_testcase_comment(
        testcase, data_types.TaskState.ERROR,
        'Not applicable for unreproducible testcases')
    return

  # This task is not applicable for custom binaries. We cannot remove the
  # creation of such tasks specifically for custom binary testcase in cron,
  # so exit gracefully.
  if build_manager.is_custom_binary():
    data_handler.update_testcase_comment(testcase,
                                         data_types.TaskState.FINISHED,
                                         'Not applicable for custom binaries')
    return

  # If we don't have a stable or beta build url pattern, we try to use build
  # information url to make a guess.
  if not build_manager.has_production_builds():
    if not testcase.regression:
      data_handler.update_testcase_comment(
          testcase, data_types.TaskState.FINISHED,
          'Cannot run without regression range, will re-run once regression '
          'task finishes')
      return

    impacts = get_impacts_from_url(testcase.regression, testcase.job_type)
    testcase = data_handler.get_testcase_by_id(testcase_id)
    set_testcase_with_impacts(testcase, impacts)
    data_handler.update_testcase_comment(testcase,
                                         data_types.TaskState.FINISHED)
    return

  # Setup testcase and its dependencies.
  file_list, _, testcase_file_path = setup.setup_testcase(testcase, job_type)
  if not file_list:
    return

  # Setup stable, beta builds and get impact and crash stacktrace.
  try:
    impacts = get_impacts_on_prod_builds(testcase, testcase_file_path)
  except BuildFailedException as error:
    testcase = data_handler.get_testcase_by_id(testcase_id)
    data_handler.update_testcase_comment(testcase, data_types.TaskState.ERROR,
                                         str(error))
    tasks.add_task(
        'impact',
        testcase_id,
        job_type,
        wait_time=environment.get_value('FAIL_WAIT'))
    return

  testcase = data_handler.get_testcase_by_id(testcase_id)
  set_testcase_with_impacts(testcase, impacts)

  # Set stacktrace in case we have a unreproducible crash on trunk,
  # but it crashes on one of the production builds.
  if testcase.is_status_unreproducible() and impacts.get_extra_trace():
    testcase.crash_stacktrace = data_handler.filter_stacktrace(
        '%s\n\n%s' % (data_handler.get_stacktrace(testcase),
                      impacts.get_extra_trace()))

  data_handler.update_testcase_comment(testcase, data_types.TaskState.FINISHED)
