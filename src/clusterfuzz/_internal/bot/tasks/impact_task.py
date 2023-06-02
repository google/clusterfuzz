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

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.build_management import build_manager
from clusterfuzz._internal.build_management import revisions
from clusterfuzz._internal.chrome import build_info
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment


class Impact(object):
  """Represents impact on a build type."""

  def __init__(self, version='', likely=False, extra_trace=''):
    self.version = str(version)
    self.likely = likely
    self.extra_trace = extra_trace

  def __str__(self):
    return (f'version: {self.version}, likely: {self.likely}, '
            f'extra_trace: {self.extra_trace}')

  def is_empty(self):
    """Return True if empty."""
    return not self.version

  def __eq__(self, other):
    return (self.version == other.version and self.likely == other.likely and
            self.extra_trace == other.extra_trace)


class Impacts(object):
  """Represents impacts on different release channels."""

  def __init__(self, stable=None, beta=None, extended_stable=None, head=None):
    self.stable = stable or Impact()
    self.beta = beta or Impact()
    self.extended_stable = extended_stable or Impact()
    self.head = head or Impact()

  def is_empty(self):
    return (self.extended_stable.is_empty() and self.stable.is_empty() and
            self.beta.is_empty() and self.head.is_empty())

  def get_extra_trace(self):
    return (
        self.extended_stable.extra_trace + '\n' + self.stable.extra_trace + '\n'
        + self.beta.extra_trace + '\n' + self.head.extra_trace).strip()

  def __eq__(self, other):
    return (self.extended_stable == other.extended_stable and
            self.stable == other.stable and self.beta == other.beta and
            self.head == other.head)


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


def is_valid_regression_range(regression_range, job_type):
  """Return whether we have a valid regression range."""
  start, end = get_start_and_end_revision(regression_range, job_type)
  return start != 0 or end != 0


def get_component_information_by_name(chromium_revision,
                                      component_display_name):
  """Returns a dictionary with information about a component at a revision."""
  lower_name = component_display_name.lower()
  component_revisions = revisions.get_component_revisions_dict(
      chromium_revision, None)
  if component_revisions is None:
    return None

  all_details = []
  for value in component_revisions.values():
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
  logs.log('Getting component impacts from URL. Component name %s, '
           'regression range %s, job type %s, platform %s.' %
           (component_name, regression_range, str(job_type), str(platform)))
  start_revision, end_revision = get_start_and_end_revision(
      regression_range, job_type)
  logs.log('Start and end revision %s, %s' % (start_revision, end_revision))
  if not end_revision:
    return Impacts()

  build_revision_mappings = build_info.get_build_to_revision_mappings(platform)
  if not build_revision_mappings:
    return Impacts()

  found_impacts = {}
  for build in ['extended_stable', 'stable', 'beta', 'canary']:
    mapping = build_revision_mappings.get(build)
    logs.log('Considering impacts for %s.' % (build))
    # TODO(yuanjunh): bypass for now but remove it after ES is enabled.
    if build == 'extended_stable' and not mapping:
      found_impacts[build] = Impact()
      continue
    # Some platforms don't have canary, so use dev to represent
    # the affected head version.
    if build == 'canary' and not mapping:
      mapping = build_revision_mappings.get('dev')
    if not mapping:
      return Impacts()
    chromium_revision = mapping['revision']
    logs.log('Chromium revision is %s.' % (chromium_revision))
    component_revision = get_component_information_by_name(
        chromium_revision, component_name)
    logs.log('Component revision is %s.' % (component_revision))
    if not component_revision:
      return Impacts()
    branched_from = revisions.revision_to_branched_from(
        component_revision['url'], component_revision['rev'])
    logs.log('Branched from revision is %s.' % (branched_from))
    if not branched_from:
      # This is a head revision, not branched.
      branched_from = component_revision['rev']
    impact = get_impact({
        'revision': branched_from,
        'version': mapping['version']
    }, start_revision, end_revision, build == 'canary')
    logs.log('Resulting impact is %s.' % (str(impact)))
    found_impacts[build] = impact
  return Impacts(found_impacts['stable'], found_impacts['beta'],
                 found_impacts['extended_stable'], found_impacts['canary'])


def get_impacts_from_url(regression_range, job_type, platform=None):
  """Gets impact string using the build information url."""
  logs.log('Get component impacts from URL: range %s, '
           'job type %s.' % (regression_range, str(job_type)))
  component_name = data_handler.get_component_name(job_type)
  if component_name:
    return get_component_impacts_from_url(component_name, regression_range,
                                          job_type, platform)

  start_revision, end_revision = get_start_and_end_revision(
      regression_range, job_type)
  logs.log('Proceeding to calculate impacts as non-component based on '
           'range %s-%s' % (str(start_revision), str(end_revision)))
  if not end_revision:
    return Impacts()

  logs.log(f'Gathering build to revision mappings for {platform}')
  build_revision_mappings = build_info.get_build_to_revision_mappings(platform)
  if not build_revision_mappings:
    return Impacts()

  logs.log('Calculating impacts from URL')
  extended_stable = get_impact(
      build_revision_mappings.get('extended_stable'), start_revision,
      end_revision)
  stable = get_impact(
      build_revision_mappings.get('stable'), start_revision, end_revision)
  beta = get_impact(
      build_revision_mappings.get('beta'), start_revision, end_revision)
  head = get_head_impact(build_revision_mappings, start_revision, end_revision)

  return Impacts(stable, beta, extended_stable, head)


def get_impact(build_revision,
               start_revision,
               end_revision,
               is_last_possible_build=False):
  """Return a Impact object represents the impact on a given build_type. Or
    return None."""
  if not build_revision:
    return Impact()

  revision = build_revision['revision']
  if not revision.isdigit():
    return Impact()

  revision = int(revision)

  version = build_revision['version']
  if start_revision > revision:
    if is_last_possible_build:
      # There are no further builds to be tested. We are probably testing
      # a revision of the code which hasn't yet made it into *any* build.
      # If that's the case, we'll say that this test case _probably_
      # impacts the milestone. We can't be sure, because the next build
      # might happen to gain a new milestone number, but it's unlikely.
      milestone = version.split('.')[0]
      return Impact(milestone, likely=True)
    return Impact()

  if end_revision < revision:
    return Impact(version, likely=False)

  # We can't figure out the impact, but it is likely.
  return Impact(version, likely=True)


def get_head_impact(build_revision_mappings, start_revision, end_revision):
  """Return the impact on 'head', i.e. the latest build we can find."""
  latest_build = build_revision_mappings.get('canary')
  if latest_build is None:
    latest_build = build_revision_mappings.get('dev')
  return get_impact(
      latest_build, start_revision, end_revision, is_last_possible_build=True)


def set_testcase_with_impacts(testcase, impacts):
  """Set testcase's impact-related fields given impacts."""
  testcase.impact_extended_stable_version = impacts.extended_stable.version
  testcase.impact_extended_stable_version_likely = \
    impacts.extended_stable.likely
  testcase.impact_stable_version = impacts.stable.version
  testcase.impact_stable_version_likely = impacts.stable.likely
  testcase.impact_beta_version = impacts.beta.version
  testcase.impact_beta_version_likely = impacts.beta.likely
  testcase.impact_head_version = impacts.head.version
  testcase.impact_head_version_likely = impacts.head.likely
  testcase.is_impact_set_flag = True


def execute_task(testcase_id, job_type):
  """Attempt to find if the testcase affects release branches on Chromium."""
  # We don't need job_type but it's supplied to all tasks.
  del job_type

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

  logs.log('Preparing to calculate impact.')
  # Formerly ClusterFuzz had buckets containing builds for stable,
  # beta and dev builds, and attempted reproduction on them. That had
  # the advantage that we would test against the exact thing shipped on each
  # channel, including any backported features. In practice, though, we
  # never noticed a difference from a bisection-based approach to determining
  # impacted builds, and those production build buckets disappered, so we have
  # switched to a purely bisection-based approach.
  if not is_valid_regression_range(testcase.regression, testcase.job_type):
    data_handler.update_testcase_comment(
        testcase, data_types.TaskState.FINISHED,
        'Cannot run without regression range, will re-run once regression '
        'task finishes')
    return

  logs.log('Calculating impact from URL.')
  impacts = get_impacts_from_url(testcase.regression, testcase.job_type)
  testcase = data_handler.get_testcase_by_id(testcase_id)
  set_testcase_with_impacts(testcase, impacts)
  data_handler.update_testcase_comment(testcase, data_types.TaskState.FINISHED)
