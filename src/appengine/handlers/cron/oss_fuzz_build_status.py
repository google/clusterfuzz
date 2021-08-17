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
"""Cron for checking OSS-Fuzz builds status."""

import datetime
import json
import re

from google.cloud import ndb
import requests

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.metrics import logs
from handlers import base_handler
from libs import handler
from libs import helpers
from libs.issue_management import issue_tracker_utils

BUCKET_URL = 'https://oss-fuzz-build-logs.storage.googleapis.com'
FUZZING_STATUS_URL = BUCKET_URL + '/status.json'
COVERAGE_STATUS_URL = BUCKET_URL + '/status-coverage.json'

FUZZING_BUILD_TYPE = 'fuzzing'
COVERAGE_BUILD_TYPE = 'coverage'
MAIN_BUILD_TYPE = FUZZING_BUILD_TYPE

# It's important not to use a dict, so that fuzzing builds get processed first.
BUILD_STATUS_MAPPINGS = [
    (FUZZING_BUILD_TYPE, FUZZING_STATUS_URL),
    (COVERAGE_BUILD_TYPE, COVERAGE_STATUS_URL),
]

TIMESTAMP_PATTERN = re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}')
TIMESTAMP_FORMAT = '%Y-%m-%dT%H:%M:%S'

# Consider something wrong if we don't see builds for this many days.
NO_BUILDS_THRESHOLD = datetime.timedelta(days=2)

# Minimum number of consecutive build failures before filing a bug.
MIN_CONSECUTIVE_BUILD_FAILURES = 2

# Number of failures after the last reminder/initial filing to send a reminder.
# This used to be 3 days, but now we may have up to two failures a day since
# https://github.com/google/oss-fuzz/pull/3585 was landed.
REMINDER_INTERVAL = 6


class OssFuzzBuildStatusException(Exception):
  """Exceptions for the build status cron."""


def _get_issue_body(project_name, build_id, build_type):
  """Return the issue body for filing new bugs."""
  template = ('The last {num_builds} builds for {project} have been failing.\n'
              '<b>Build log:</b> {log_link}\n'
              'Build type: {build_type}\n\n'
              'To reproduce locally, please see: '
              'https://google.github.io/oss-fuzz/advanced-topics/reproducing'
              '#reproducing-build-failures\n\n'
              '<b>This bug tracker is not being monitored by OSS-Fuzz team.</b>'
              ' If you have any questions, please create an issue at '
              'https://github.com/google/oss-fuzz/issues/new.\n\n'
              '**This bug will be automatically closed within a '
              'day once it is fixed.**')

  return template.format(
      num_builds=MIN_CONSECUTIVE_BUILD_FAILURES,
      project=project_name,
      log_link=_get_build_link(build_id),
      build_type=build_type)


def _get_oss_fuzz_project(project_name):
  """Return the OssFuzzProject entity for the given project."""
  return ndb.Key(data_types.OssFuzzProject, project_name).get()


def _get_build_link(build_id):
  """Return a link to the build log."""
  return BUCKET_URL + '/log-' + build_id + '.txt'


def _get_ndb_key(project_name, build_type):
  """Constructs a Key literal for build failure entities."""
  if build_type == MAIN_BUILD_TYPE:
    return project_name

  # Use build type suffix for the auxiliary build (e.g. coverage).
  return '%s-%s' % (project_name, build_type)


def create_build_failure(project_name, failure, build_type):
  """Create new build failure."""
  return data_types.OssFuzzBuildFailure(
      id=_get_ndb_key(project_name, build_type),
      project_name=project_name,
      last_checked_timestamp=get_build_time(failure),
      build_type=build_type)


def get_build_failure(project_name, build_type):
  """Return the last build failure for the project."""
  key = ndb.Key(data_types.OssFuzzBuildFailure,
                _get_ndb_key(project_name, build_type))
  return key.get()


def close_build_failure(build_failure):
  """Delete the build failure."""
  build_failure.key.delete()


def get_build_time(build):
  """Return a datetime for when the build was done."""
  # Strip the nanosecond precision from the timestamp, since it's not
  # supported by Python.
  stripped_timestamp = TIMESTAMP_PATTERN.match(build['finish_time'])
  if not stripped_timestamp:
    logs.log_error(
        'Invalid timestamp %s for %s.' % (build['finish_time'], build['name']))
    return None

  return datetime.datetime.strptime(
      stripped_timestamp.group(0), TIMESTAMP_FORMAT)


def file_bug(issue_tracker, project_name, build_id, ccs, build_type):
  """File a new bug for a build failure."""
  logs.log('Filing bug for new build failure (project=%s, build_type=%s, '
           'build_id=%s).' % (project_name, build_type, build_id))

  issue = issue_tracker.new_issue()
  issue.title = '{project_name}: {build_type} build failure'.format(
      project_name=project_name, build_type=build_type.capitalize())
  issue.body = _get_issue_body(project_name, build_id, build_type)
  issue.status = 'New'
  issue.labels.add('Type-Build-Failure')
  issue.labels.add('Proj-' + project_name)

  for cc in ccs:
    issue.ccs.add(cc)

  issue.save()
  return str(issue.id)


def close_bug(issue_tracker, issue_id, project_name):
  """Close a build failure bug."""
  logs.log('Closing build failure bug (project=%s, issue_id=%s).' %
           (project_name, issue_id))

  issue = issue_tracker.get_original_issue(issue_id)
  issue.status = 'Verified'
  issue.save(
      new_comment='The latest build has succeeded, closing this issue.',
      notify=True)


def send_reminder(issue_tracker, issue_id, build_id):
  """Send a reminder about the build still failing."""
  issue = issue_tracker.get_original_issue(issue_id)

  comment = ('Friendly reminder that the the build is still failing.\n'
             'Please try to fix this failure to ensure that fuzzing '
             'remains productive.\n'
             'Latest build log: {log_link}\n')
  comment = comment.format(log_link=_get_build_link(build_id))
  issue.save(new_comment=comment, notify=True)


class Handler(base_handler.Handler):
  """Build status checker."""

  def _close_fixed_builds(self, projects, build_type):
    """Close bugs for fixed builds."""
    issue_tracker = issue_tracker_utils.get_issue_tracker()
    if not issue_tracker:
      raise OssFuzzBuildStatusException('Failed to get issue tracker.')

    for project in projects:
      project_name = project['name']
      builds = project['history']
      if not builds:
        continue

      build_failure = get_build_failure(project_name, build_type)
      if not build_failure:
        continue

      build = builds[0]
      if not build['success']:
        continue

      if build_failure.last_checked_timestamp >= get_build_time(build):
        logs.log_error('Latest successful build time for %s in %s config is '
                       'older than or equal to last failure time.' %
                       (project_name, build_type))
        continue

      if build_failure.issue_id is not None:
        close_bug(issue_tracker, build_failure.issue_id, project_name)

      close_build_failure(build_failure)

  def _process_failures(self, projects, build_type):
    """Process failures."""
    issue_tracker = issue_tracker_utils.get_issue_tracker()
    if not issue_tracker:
      raise OssFuzzBuildStatusException('Failed to get issue tracker.')

    for project in projects:
      project_name = project['name']
      builds = project['history']
      if not builds:
        continue

      build = builds[0]
      if build['success']:
        continue

      project_name = project['name']

      # Do not file an issue for non-main build types, if there is a main build
      # failure for the same project, as the root cause might be the same.
      if build_type != MAIN_BUILD_TYPE:
        build_failure = get_build_failure(project_name, MAIN_BUILD_TYPE)
        if build_failure:
          continue

      build_failure = get_build_failure(project_name, build_type)

      build_time = get_build_time(build)
      if build_failure:
        if build_time <= build_failure.last_checked_timestamp:
          # No updates.
          continue
      else:
        build_failure = create_build_failure(project_name, build, build_type)

      build_failure.last_checked_timestamp = build_time
      build_failure.consecutive_failures += 1
      if build_failure.consecutive_failures >= MIN_CONSECUTIVE_BUILD_FAILURES:
        if build_failure.issue_id is None:
          oss_fuzz_project = _get_oss_fuzz_project(project_name)
          if not oss_fuzz_project:
            logs.log(
                'Project %s is disabled, skipping bug filing.' % project_name)
            continue

          build_failure.issue_id = file_bug(issue_tracker, project_name,
                                            build['build_id'],
                                            oss_fuzz_project.ccs, build_type)
        elif (build_failure.consecutive_failures -
              MIN_CONSECUTIVE_BUILD_FAILURES) % REMINDER_INTERVAL == 0:
          send_reminder(issue_tracker, build_failure.issue_id,
                        build['build_id'])

      build_failure.put()

  def _check_last_get_build_time(self, projects, build_type):
    """Check that builds are up to date."""
    for project in projects:
      project_name = project['name']
      builds = project['history']
      if not builds:
        continue

      build = builds[0]
      time_since_last_build = utils.utcnow() - get_build_time(build)
      if time_since_last_build >= NO_BUILDS_THRESHOLD:
        # Something likely went wrong with the build infrastructure, log errors.
        logs.log_error('%s has not been built in %s config for %d days.' %
                       (project_name, build_type, time_since_last_build.days))

  @handler.cron()
  def get(self):
    """Handles a get request."""
    for build_type, status_url in BUILD_STATUS_MAPPINGS:
      try:
        response = requests.get(status_url)
        response.raise_for_status()
        build_status = json.loads(response.text)
      except (requests.exceptions.RequestException, ValueError) as e:
        raise helpers.EarlyExitException(str(e), response.status_code)

      projects = build_status['projects']

      self._check_last_get_build_time(projects, build_type)
      self._close_fixed_builds(projects, build_type)
      self._process_failures(projects, build_type)
