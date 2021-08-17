# Copyright 2020 Google LLC
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
"""Tests for the fuzzer-coverage cron task."""

import datetime
import unittest

from google.cloud import ndb

from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from clusterfuzz._internal.tests.test_libs import test_utils
from handlers.cron import fuzzer_coverage

INTEGRATION_TEST_BUCKET = 'clusterfuzz-test-data'


@test_utils.integration
@test_utils.with_cloud_emulators('datastore')
class HandlerTest(unittest.TestCase):
  """Tests for the fuzzer coverage crom task Handler."""

  def setUp(self):
    test_helpers.patch(
        self, ['clusterfuzz._internal.base.utils.default_project_name'])

    # It's important to use chromium here to test they datastore key generation
    # logic which uses project qualified fuzz target names.
    self.mock.default_project_name.return_value = 'chromium'

  def assertCoverageInformation(
      self,
      actual,
      expected,
  ):
    """Assert that the actual entity is equal to the expected one."""
    self.assertEqual(actual.date, expected.date)
    self.assertEqual(actual.fuzzer, expected.fuzzer)
    self.assertEqual(actual.functions_covered, expected.functions_covered)
    self.assertEqual(actual.functions_total, expected.functions_total)
    self.assertEqual(actual.edges_covered, expected.edges_covered)
    self.assertEqual(actual.edges_total, expected.edges_total)
    self.assertEqual(actual.corpus_size_units, expected.corpus_size_units)
    self.assertEqual(actual.corpus_size_bytes, expected.corpus_size_bytes)
    self.assertEqual(actual.corpus_location, expected.corpus_location)
    self.assertEqual(actual.corpus_backup_location,
                     expected.corpus_backup_location)
    self.assertEqual(actual.quarantine_size_units,
                     expected.quarantine_size_units)
    self.assertEqual(actual.quarantine_size_bytes,
                     expected.quarantine_size_bytes)
    self.assertEqual(actual.quarantine_location, expected.quarantine_location)
    self.assertEqual(actual.html_report_url, expected.html_report_url)

  def test_fuzzer_coverage(self):
    """Test fuzzer coverage cron implementation."""
    # An old CoverageInformation for a fuzzer that should NOT be overwritten.
    cov_info_old = data_types.CoverageInformation(
        date=datetime.date(2018, 9, 1),
        fuzzer='boringssl_privkey',
        functions_covered=123,
        functions_total=555,
        edges_covered=1337,
        edges_total=31337,
        html_report_url=(
            'https://storage.googleapis.com/oss-fuzz-coverage/boringssl/'
            'reports/20180905/linux/index.html'))
    cov_info_old.put()

    # A recent CoverageInformation for a fuzzer that should be overwritten.
    cov_info_recent = data_types.CoverageInformation(
        date=datetime.date(2018, 9, 7),
        fuzzer='base64_decode_fuzzer',
        functions_covered=1,
        functions_total=5,
        edges_covered=3,
        edges_total=20,
        html_report_url='intentionally junk URL that must be overwritten')
    cov_info_recent.put()

    # A recent CoverageInformation for a project that should be overwritten.
    cov_info_project = data_types.CoverageInformation(
        date=datetime.date(2018, 9, 7),
        fuzzer='zlib',
        functions_covered=1,
        functions_total=2,
        edges_covered=3,
        edges_total=4,
        html_report_url='intentionally junk URL that must be overwritten')
    cov_info_project.put()

    fuzzer_coverage.collect_fuzzer_coverage(INTEGRATION_TEST_BUCKET)
    query = data_types.CoverageInformation.query()

    entities = {}
    for cov_info in query.fetch():
      entities[cov_info.key] = cov_info

    # Assert and delete entities one by one to make sure we verify each of them.
    key = ndb.Key('CoverageInformation', 'boringssl_bn_div-20180905')
    expected_entity = data_types.CoverageInformation(
        date=datetime.date(2018, 9, 5),
        fuzzer='boringssl_bn_div',
        functions_covered=82,
        functions_total=1079,
        edges_covered=1059,
        edges_total=12384,
        html_report_url=(
            'https://storage.googleapis.com/oss-fuzz-coverage/boringssl/'
            'reports/20180905/linux/index.html'))
    self.assertCoverageInformation(entities[key], expected_entity)
    del entities[key]

    # This is the "old" entity that should not be updated (|cov_info_old|).
    key = ndb.Key('CoverageInformation', 'boringssl_privkey-20180901')
    expected_entity = data_types.CoverageInformation(
        date=datetime.date(2018, 9, 1),
        fuzzer='boringssl_privkey',
        functions_covered=123,
        functions_total=555,
        edges_covered=1337,
        edges_total=31337,
        html_report_url=(
            'https://storage.googleapis.com/oss-fuzz-coverage/boringssl/'
            'reports/20180905/linux/index.html'))
    self.assertCoverageInformation(entities[key], expected_entity)
    del entities[key]

    key = ndb.Key('CoverageInformation', 'boringssl_privkey-20180905')
    expected_entity = data_types.CoverageInformation(
        date=datetime.date(2018, 9, 5),
        fuzzer='boringssl_privkey',
        functions_covered=374,
        functions_total=1510,
        edges_covered=3535,
        edges_total=16926,
        html_report_url=(
            'https://storage.googleapis.com/oss-fuzz-coverage/boringssl/'
            'reports/20180905/linux/index.html'))
    self.assertCoverageInformation(entities[key], expected_entity)
    del entities[key]

    # Entity for boringssl project, not for a single fuzz target.
    key = ndb.Key('CoverageInformation', 'boringssl-20180905')
    expected_entity = data_types.CoverageInformation(
        date=datetime.date(2018, 9, 5),
        fuzzer='boringssl',
        functions_covered=1872,
        functions_total=4137,
        edges_covered=21303,
        edges_total=51251,
        html_report_url=(
            'https://storage.googleapis.com/oss-fuzz-coverage/boringssl/'
            'reports/20180905/linux/index.html'))
    self.assertCoverageInformation(entities[key], expected_entity)
    del entities[key]

    # The "recent" entity that should be updated (|cov_info_recent|).
    key = ndb.Key('CoverageInformation', 'base64_decode_fuzzer-20180907')
    expected_entity = data_types.CoverageInformation(
        date=datetime.date(2018, 9, 7),
        fuzzer='base64_decode_fuzzer',
        functions_covered=252,
        functions_total=5646,
        edges_covered=1111,
        edges_total=38748,
        html_report_url=(
            'https://chromium-coverage.appspot.com/reports/589371_fuzzers_only/'
            'linux/index.html'))
    self.assertCoverageInformation(entities[key], expected_entity)
    del entities[key]

    key = ndb.Key('CoverageInformation', 'zucchini_raw_gen_fuzzer-20180907')
    expected_entity = data_types.CoverageInformation(
        date=datetime.date(2018, 9, 7),
        fuzzer='zucchini_raw_gen_fuzzer',
        functions_covered=440,
        functions_total=6439,
        edges_covered=1791,
        edges_total=45121,
        html_report_url=(
            'https://chromium-coverage.appspot.com/reports/589371_fuzzers_only/'
            'linux/index.html'))
    self.assertCoverageInformation(entities[key], expected_entity)
    del entities[key]

    # Entity for chromium project.
    key = ndb.Key('CoverageInformation', 'chromium-20180907')
    expected_entity = data_types.CoverageInformation(
        date=datetime.date(2018, 9, 7),
        fuzzer='chromium',
        functions_covered=79960,
        functions_total=467023,
        edges_covered=682323,
        edges_total=3953229,
        html_report_url=(
            'https://chromium-coverage.appspot.com/reports/589371_fuzzers_only/'
            'linux/index.html'))
    self.assertCoverageInformation(entities[key], expected_entity)
    del entities[key]

    key = ndb.Key('CoverageInformation', 'zlib_uncompress_fuzzer-20180907')
    expected_entity = data_types.CoverageInformation(
        date=datetime.date(2018, 9, 7),
        fuzzer='zlib_uncompress_fuzzer',
        functions_covered=19,
        functions_total=47,
        edges_covered=987,
        edges_total=1687,
        html_report_url=(
            'https://storage.googleapis.com/oss-fuzz-coverage/zlib/reports/'
            '20180907/linux/index.html'))
    self.assertCoverageInformation(entities[key], expected_entity)
    del entities[key]

    # The recent project entity that should be updated (|cov_info_project|).
    key = ndb.Key('CoverageInformation', 'zlib-20180907')
    expected_entity = data_types.CoverageInformation(
        date=datetime.date(2018, 9, 7),
        fuzzer='zlib',
        functions_covered=19,
        functions_total=47,
        edges_covered=987,
        edges_total=1687,
        html_report_url=(
            'https://storage.googleapis.com/oss-fuzz-coverage/zlib/reports/'
            '20180907/linux/index.html'))
    self.assertCoverageInformation(entities[key], expected_entity)
    del entities[key]

    # Should not have any entities left unverified. Ensures collect logic of
    # not creating duplicated entities if there is an existing one. In practice,
    # an existing entity could either be created by an earlier execution of
    # the cron task, or by the corpus pruning task.
    self.assertEqual(len(entities), 0)
