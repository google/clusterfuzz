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
"""Tests for oss_fuzz_build_status."""

import datetime
import json
import mock
import unittest

import webapp2
import webtest

from datastore import data_types
from handlers.cron import oss_fuzz_build_status
from issue_management.issue import Issue
from tests.test_libs import helpers as test_helpers
from tests.test_libs import test_utils


class MockResponse(object):
  """Mock urlfetch response."""

  def __init__(self, content):
    self.content = content


class IssueTrackerManager(object):
  """Mock issue tracker manager."""

  def __init__(self, project_name):
    self.project_name = project_name
    self.issues = {}
    self.next_id = 1

  def get_original_issue(self, issue_id):
    """Get original issue."""
    return self.issues[issue_id]

  def save(self, issue, *args, **kwargs):  # pylint: disable=unused-argument
    """Save an issue."""
    if issue.new:
      issue.id = self.next_id
      self.next_id += 1

    self.issues[issue.id] = issue


@test_utils.with_cloud_emulators('datastore')
class OssFuzzBuildStatusTest(unittest.TestCase):
  """Tests for oss_fuzz_build_status."""

  def setUp(self):
    self.app = webtest.TestApp(
        webapp2.WSGIApplication([('/build-status',
                                  oss_fuzz_build_status.Handler)]))

    test_helpers.patch(self, [
        'metrics.logs.log_error',
        'base.utils.utcnow',
        'issue_management.issue_tracker_utils.get_issue_tracker_manager',
        'handlers.base_handler.Handler.is_cron',
        'handlers.cron.oss_fuzz_build_status.urlfetch.fetch',
    ])

    self.mock.utcnow.return_value = datetime.datetime(2018, 2, 1)
    self.mock.is_cron.return_value = True

    self.itm = IssueTrackerManager('oss-fuzz')
    self.mock.get_issue_tracker_manager.return_value = self.itm

    self.maxDiff = None  # pylint: disable=invalid-name

  def test_no_build_failures(self):
    """Test run with no build failures."""
    # Return the same status for all build types.
    self.mock.fetch.return_value = MockResponse(
        json.dumps({
            'successes': [
                {
                    'name': 'proj0',
                    'finish_time': '2018-02-01T00:00:00.000000Z',
                    'build_id': 'proj0-id',
                },
                {
                    'name': 'proj1',
                    'finish_time': '2018-02-01T00:00:00.000000Z',
                    'build_id': 'proj1-id',
                },
            ],
            'failures': [],
        }))

    self.app.get('/build-status')
    self.assertEqual(0, data_types.OssFuzzBuildFailure.query().count())
    self.assertEqual(0, len(self.itm.issues))

  def test_build_failures(self):
    """Test run with multiple build failures of different type."""

    def _mock_fetch(url):
      """Mock fetch."""
      if url == oss_fuzz_build_status.FUZZING_STATUS_URL:
        return MockResponse(
            json.dumps({
                'successes': [
                    # Both fuzzing and coverage build types are successful.
                    {
                        'name': 'proj0',
                        'finish_time': '2018-02-01T00:00:00.000000Z',
                        'build_id': 'proj0-id-f',
                    },

                    # Only coverage build type is broken for a while.
                    {
                        'name': 'proj5',
                        'finish_time': '2018-02-01T00:00:00.000000Z',
                        'build_id': 'proj5-id-f',
                    },

                    # Only coverage build type broken.
                    {
                        'name': 'proj6',
                        'finish_time': '2018-02-01T00:00:00.000000Z',
                        'build_id': 'proj6-id-f',
                    },
                ],
                'failures': [
                    # New failure (first 1).
                    {
                        'name': 'proj1',
                        'finish_time': '2018-02-01T00:00:00.000000000Z',
                        'build_id': 'proj1-id-f',
                    },

                    # Seen failure (second consecutive).
                    {
                        'name': 'proj2',
                        'finish_time': '2018-02-01T00:00:00.000000Z',
                        'build_id': 'proj2-id-f',
                    },

                    # Seen failure (not updated).
                    {
                        'name': 'proj3',
                        'finish_time': '2018-01-31T00:00:00.000000Z',
                        'build_id': 'proj3-id-f',
                    },

                    # Seen failure (third consecutive, bug already filed).
                    {
                        'name': 'proj4',
                        'finish_time': '2018-02-01T00:00:00.000000Z',
                        'build_id': 'proj4-id-f',
                    },
                ],
            }))

      assert url == oss_fuzz_build_status.COVERAGE_STATUS_URL
      return MockResponse(
          json.dumps({
              'successes': [
                  # Both fuzzing and coverage build types are successful.
                  {
                      'name': 'proj0',
                      'finish_time': '2018-02-01T00:00:00.000000Z',
                      'build_id': 'proj0-id-c',
                  },
              ],
              'failures': [
                  # New failure (first 1).
                  {
                      'name': 'proj1',
                      'finish_time': '2018-02-01T00:00:00.000000000Z',
                      'build_id': 'proj1-id-c',
                  },

                  # Seen failure (second consecutive).
                  {
                      'name': 'proj2',
                      'finish_time': '2018-02-01T00:00:00.000000Z',
                      'build_id': 'proj2-id-c',
                  },

                  # Seen failure (not updated).
                  {
                      'name': 'proj3',
                      'finish_time': '2018-01-31T00:00:00.000000Z',
                      'build_id': 'proj3-id-c',
                  },

                  # Seen failure (third consecutive, bug already filed).
                  {
                      'name': 'proj4',
                      'finish_time': '2018-02-01T00:00:00.000000Z',
                      'build_id': 'proj4-id-c',
                  },

                  # Coverage build type is broken for a while.
                  {
                      'name': 'proj5',
                      'finish_time': '2018-02-01T00:00:00.000000Z',
                      'build_id': 'proj5-id-c',
                  },

                  # Only coverage build type broken (second consecutive).
                  {
                      'name': 'proj6',
                      'finish_time': '2018-02-01T00:00:00.000000Z',
                      'build_id': 'proj6-id-c',
                  },
              ],
          }))

    self.mock.fetch.side_effect = _mock_fetch

    data_types.OssFuzzBuildFailure(
        id='proj2',
        project_name='proj2',
        last_checked_timestamp=datetime.datetime(2018, 1, 31),
        consecutive_failures=1,
        build_type='fuzzing').put()

    data_types.OssFuzzBuildFailure(
        id='proj3',
        project_name='proj3',
        last_checked_timestamp=datetime.datetime(2018, 1, 31),
        consecutive_failures=1,
        build_type='fuzzing').put()

    data_types.OssFuzzBuildFailure(
        id='proj4',
        project_name='proj4',
        last_checked_timestamp=datetime.datetime(2018, 1, 31),
        issue_id='1337',
        consecutive_failures=2,
        build_type='fuzzing').put()

    data_types.OssFuzzBuildFailure(
        id='proj5-coverage',
        project_name='proj5',
        last_checked_timestamp=datetime.datetime(2018, 1, 31),
        issue_id='31337',
        consecutive_failures=5,
        build_type='coverage').put()

    data_types.OssFuzzBuildFailure(
        id='proj6-coverage',
        project_name='proj6',
        last_checked_timestamp=datetime.datetime(2018, 1, 31),
        issue_id=None,
        consecutive_failures=1,
        build_type='coverage').put()

    data_types.OssFuzzProject(
        id='proj2', name='proj2', ccs=['a@user.com']).put()
    data_types.OssFuzzProject(
        id='proj6', name='proj7', ccs=['b@user.com']).put()

    self.app.get('/build-status')
    self.assertItemsEqual([
        {
            'build_type': 'fuzzing',
            'consecutive_failures': 1,
            'issue_id': None,
            'last_checked_timestamp': datetime.datetime(2018, 2, 1, 0, 0),
            'project_name': u'proj1'
        },
        {
            'build_type': 'fuzzing',
            'consecutive_failures': 2,
            'issue_id': '1',
            'last_checked_timestamp': datetime.datetime(2018, 2, 1, 0, 0),
            'project_name': u'proj2'
        },
        {
            'build_type': 'fuzzing',
            'consecutive_failures': 1,
            'issue_id': None,
            'last_checked_timestamp': datetime.datetime(2018, 1, 31, 0, 0),
            'project_name': u'proj3'
        },
        {
            'build_type': 'fuzzing',
            'consecutive_failures': 3,
            'issue_id': '1337',
            'last_checked_timestamp': datetime.datetime(2018, 2, 1, 0, 0),
            'project_name': u'proj4'
        },
        {
            'build_type': 'coverage',
            'consecutive_failures': 6,
            'issue_id': '31337',
            'last_checked_timestamp': datetime.datetime(2018, 2, 1, 0, 0),
            'project_name': u'proj5'
        },
        {
            'build_type': 'coverage',
            'consecutive_failures': 2,
            'issue_id': '2',
            'last_checked_timestamp': datetime.datetime(2018, 2, 1, 0, 0),
            'project_name': u'proj6'
        },
    ], [
        failure.to_dict() for failure in data_types.OssFuzzBuildFailure.query()
    ])

    self.assertEqual(2, len(self.itm.issues))
    issue = self.itm.issues[1]
    self.assertItemsEqual(['a@user.com'], issue.cc)
    self.assertEqual('New', issue.status)
    self.assertEqual('proj2: Build failure', issue.summary)
    self.assertEqual(
        'The last 2 builds for proj2 have been failing.\n'
        '<b>Build log:</b> '
        'https://oss-fuzz-build-logs.storage.googleapis.com/'
        'log-proj2-id-f.txt\n'
        'Build type: fuzzing\n\n'
        'To reproduce locally, please see: '
        'https://github.com/google/oss-fuzz/'
        'blob/master/docs/reproducing.md#reproducing-build-failures\n\n'
        'If you have any questions, please file a bug on '
        'https://github.com/google/oss-fuzz/issues/new.\n\n'
        '**This bug will be automatically closed within a '
        'day once it is fixed.**', issue.body)

    self.assertTrue(issue.has_label('Proj-proj2'))
    self.assertTrue(issue.has_label('Type-Build-Failure'))

    issue = self.itm.issues[2]
    self.assertItemsEqual(['b@user.com'], issue.cc)
    self.assertEqual('New', issue.status)
    self.assertEqual('proj6: Build failure', issue.summary)
    self.assertEqual(
        'The last 2 builds for proj6 have been failing.\n'
        '<b>Build log:</b> '
        'https://oss-fuzz-build-logs.storage.googleapis.com/'
        'log-proj6-id-c.txt\n'
        'Build type: coverage\n\n'
        'To reproduce locally, please see: '
        'https://github.com/google/oss-fuzz/'
        'blob/master/docs/reproducing.md#reproducing-build-failures\n\n'
        'If you have any questions, please file a bug on '
        'https://github.com/google/oss-fuzz/issues/new.\n\n'
        '**This bug will be automatically closed within a '
        'day once it is fixed.**', issue.body)

    self.assertTrue(issue.has_label('Proj-proj6'))
    self.assertTrue(issue.has_label('Type-Build-Failure'))

  def test_recovered_build_failure(self):
    """Test fixed build failures."""
    # Use the same status for all build types.
    self.mock.fetch.return_value = MockResponse(
        json.dumps({
            'successes': [{
                'name': 'proj0',
                'finish_time': '2018-02-01T00:00:00.000000Z',
                'build_id': 'proj0-id',
            },],
            'failures': [],
        }))

    data_types.OssFuzzBuildFailure(
        id='proj0',
        project_name='proj0',
        last_checked_timestamp=datetime.datetime(2018, 1, 31),
        issue_id='1',
        consecutive_failures=2,
        build_type='fuzzing').put()

    issue = Issue()
    issue.open = True
    issue.add_label('Type-Build-Failure')
    issue.add_label('Proj-proj2')
    issue.summary = 'Build failure in proj2'
    issue.body = 'Build failure'

    self.itm.issues[1] = issue

    self.app.get('/build-status')
    self.assertEqual(0, data_types.OssFuzzBuildFailure.query().count())

    issue = self.itm.issues[1]
    self.assertFalse(issue.open)
    self.assertEqual('Verified', issue.status)
    self.assertEqual('The latest build has succeeded, closing this issue.',
                     issue.comment)

  def test_missing_builds(self):
    """Test missing builds."""

    def _mock_fetch(url):
      """Mock fetch."""
      if url == oss_fuzz_build_status.FUZZING_STATUS_URL:
        return MockResponse(
            json.dumps({
                'successes': [
                    {
                        'name': 'proj0',
                        'finish_time': '2018-01-30T00:00:00.000000Z',
                        'build_id': 'proj0-id-f',
                    },
                    {
                        'name': 'proj1',
                        'finish_time': '2018-02-01T00:00:00.000000Z',
                        'build_id': 'proj0-id-f',
                    },
                ],
                'failures': [],
            }))

      assert url == oss_fuzz_build_status.COVERAGE_STATUS_URL
      return MockResponse(
          json.dumps({
              'successes': [
                  {
                      'name': 'proj0',
                      'finish_time': '2018-02-01T00:00:00.000000Z',
                      'build_id': 'proj0-id-c',
                  },
                  {
                      'name': 'proj1',
                      'finish_time': '2018-01-30T00:00:00.000000Z',
                      'build_id': 'proj1-id-c',
                  },
              ],
              'failures': [],
          }))

    self.mock.fetch.side_effect = _mock_fetch
    self.app.get('/build-status')
    self.mock.log_error.assert_has_calls([
        mock.call('proj0 has not been built in fuzzing config for 2 days.'),
        mock.call('proj1 has not been built in coverage config for 2 days.')
    ])

  def test_disabled_project(self):
    """Test disabled project."""
    # Return the same status for all build types.
    self.mock.fetch.return_value = MockResponse(
        json.dumps({
            'successes': [],
            'failures': [
                # Seen failure (second consecutive).
                {
                    'name': 'disabled_proj',
                    'finish_time': '2018-02-01T00:00:00.000000Z',
                    'build_id': 'proj2-id',
                },
            ],
        }))

    # Only fuzzing build type failure should be stored.
    data_types.OssFuzzBuildFailure(
        id='disabled_proj',
        project_name='disabled_proj',
        last_checked_timestamp=datetime.datetime(2018, 1, 31),
        consecutive_failures=1,
        build_type='fuzzing').put()

    self.app.get('/build-status')
    self.assertItemsEqual([
        {
            'build_type': 'fuzzing',
            'consecutive_failures': 1,
            'issue_id': None,
            'last_checked_timestamp': datetime.datetime(2018, 1, 31, 0, 0),
            'project_name': u'disabled_proj',
        },
    ], [
        failure.to_dict() for failure in data_types.OssFuzzBuildFailure.query()
    ])

    self.assertEqual(0, len(self.itm.issues))

  def test_reminder(self):
    """Test reminders."""
    # Return the same status for all build types.
    self.mock.fetch.return_value = MockResponse(
        json.dumps({
            'successes': [],
            'failures': [
                {
                    'name': 'proj0',
                    'finish_time': '2018-02-01T00:00:00.000000Z',
                    'build_id': 'proj0-id',
                },
                {
                    'name': 'proj1',
                    'finish_time': '2018-02-01T00:00:00.000000Z',
                    'build_id': 'proj0-id',
                },
            ],
        }))

    data_types.OssFuzzProject(
        id='proj0', name='proj0', ccs=['a@user.com']).put()
    data_types.OssFuzzBuildFailure(
        id='proj0',
        project_name='proj0',
        last_checked_timestamp=datetime.datetime(2018, 1, 31),
        issue_id='1',
        consecutive_failures=4,
        build_type='fuzzing').put()
    data_types.OssFuzzProject(
        id='proj1', name='proj1', ccs=['a@user.com']).put()
    data_types.OssFuzzBuildFailure(
        id='proj1',
        project_name='proj1',
        last_checked_timestamp=datetime.datetime(2018, 1, 31),
        issue_id='2',
        consecutive_failures=3,
        build_type='fuzzing').put()

    self.itm.issues[1] = Issue()
    self.itm.issues[2] = Issue()

    self.app.get('/build-status')
    self.assertEqual(
        'Friendly reminder that the the build is still failing.\n'
        'Please try to fix this failure to ensure that fuzzing remains '
        'productive.\n'
        'Latest build log: https://oss-fuzz-build-logs.storage.googleapis.com/'
        'log-proj0-id.txt\n', self.itm.issues[1].comment)
    self.assertEqual('', self.itm.issues[2].comment)
