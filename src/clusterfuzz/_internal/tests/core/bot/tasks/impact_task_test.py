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
"""impact_task tests."""
import unittest

import mock

from clusterfuzz._internal.bot.tasks import impact_task
from clusterfuzz._internal.build_management import build_manager
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.tests.core.bot.tasks.component_revision_patching_test import \
    ComponentRevisionPatchingTest
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils


@test_utils.with_cloud_emulators('datastore')
class ExecuteTaskTest(unittest.TestCase):
  """Test execute_task."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.base.utils.is_chromium',
        'clusterfuzz._internal.bot.tasks.impact_task.get_impacts_from_url',
        'clusterfuzz._internal.bot.tasks.impact_task.get_impacts_on_prod_builds',
        'clusterfuzz._internal.bot.tasks.setup.setup_testcase',
        'clusterfuzz._internal.build_management.build_manager.is_custom_binary',
        'clusterfuzz._internal.build_management.build_manager.has_production_builds',
        'clusterfuzz._internal.bot.testcase_manager.get_command_line_for_application',
        'clusterfuzz._internal.base.tasks.add_task',
    ])
    impacts = impact_task.Impacts(
        stable=impact_task.Impact('stable', False, 'trace-stable'),
        beta=impact_task.Impact('beta', True, 'trace-beta'),
        extended_stable=impact_task.Impact('extended stable', False,
                                           'trace-extended-stable'),
        head=impact_task.Impact('head', False, 'trace-head'))
    self.mock.is_chromium.return_value = True
    self.mock.is_custom_binary.return_value = False
    self.mock.has_production_builds.return_value = True
    self.mock.get_impacts_from_url.return_value = impacts
    self.mock.setup_testcase.return_value = (['a'], None, 'path')
    self.mock.get_impacts_on_prod_builds.return_value = impacts

    self.testcase = data_types.Testcase()
    self.testcase.is_impact_set_flag = False
    self.testcase.status = 'Processed'
    self.testcase.crash_stacktrace = 'trace'
    self.testcase.regression = '123:456'
    self.testcase.job_type = 'job2'
    self.testcase.project_name = 'chromium'
    self.testcase.put()

  def reload(self):
    """Reload testcase."""
    self.testcase = self.testcase.key.get()

  def expect_unchanged(self):
    """Expect testcase's impacts to be unchanged."""
    self.reload()
    self.assertIsNone(self.testcase.impact_stable_version)
    self.assertIsNone(self.testcase.impact_beta_version)
    self.assertIsNone(self.testcase.impact_head_version)

  def expect_changed(self):
    """Expect testcase's impacts to be changed."""
    self.reload()
    self.assertTrue(self.testcase.is_impact_set_flag)
    self.assertEqual('extended stable',
                     self.testcase.impact_extended_stable_version)
    self.assertFalse(self.testcase.impact_stable_version_likely)
    self.assertEqual('stable', self.testcase.impact_stable_version)
    self.assertFalse(self.testcase.impact_stable_version_likely)
    self.assertEqual('beta', self.testcase.impact_beta_version)
    self.assertTrue(self.testcase.impact_beta_version_likely)
    self.assertEqual('head', self.testcase.impact_head_version)
    self.assertFalse(self.testcase.impact_head_version_likely)

  def test_bail_out_non_chromium(self):
    """Test bailing out for non chromium projects."""
    self.mock.is_chromium.return_value = False
    impact_task.execute_task(self.testcase.key.id(), 'job')
    self.expect_unchanged()

  def test_bail_out_fixed(self):
    """Test bailing out when the testcase is fixed."""
    self.testcase.fixed = 'Yes'
    self.testcase.is_impact_set_flag = True
    self.testcase.put()
    impact_task.execute_task(self.testcase.key.id(), 'job')
    self.expect_unchanged()

  def test_bail_out_status_unreproducible(self):
    """Test bailing out when the testcase status is unreproducible (never
    reproduced)."""
    self.testcase.status = 'Unreproducible'
    self.testcase.is_impact_set_flag = True
    self.testcase.put()
    impact_task.execute_task(self.testcase.key.id(), 'job')
    self.expect_unchanged()

  def test_bail_out_custom_binary(self):
    """Test bailing out for custom binary."""
    self.mock.is_custom_binary.return_value = True
    impact_task.execute_task(self.testcase.key.id(), 'job')
    self.expect_unchanged()

  def test_bail_out_unreproducible(self):
    """Test bailing out when the testcase is unreproducible (reproduced once,
    but flaky)."""
    self.testcase.one_time_crasher_flag = True
    self.testcase.put()
    impact_task.execute_task(self.testcase.key.id(), 'job')
    self.expect_unchanged()

  def test_bail_out_non_prod_build_and_no_regression_range(self):
    """Test bailing out when reproducible testcase does not have a regression
    range yet and we dont have production builds to test."""
    self.testcase.one_time_crasher_flag = False
    self.testcase.regression = ''
    self.testcase.put()
    self.mock.has_production_builds.return_value = False
    impact_task.execute_task(self.testcase.key.id(), 'job')
    self.expect_unchanged()

  def test_non_prod_build(self):
    """Test getting impact for non-prod build."""
    self.mock.has_production_builds.return_value = False
    impact_task.execute_task(self.testcase.key.id(), 'job')
    self.expect_changed()
    self.mock.get_impacts_from_url.assert_has_calls(
        [mock.call(self.testcase.regression, self.testcase.job_type)])

  def test_bail_out_setup_testcase(self):
    """Test bailing out when setting up testcase fails."""
    self.mock.has_production_builds.return_value = True
    self.mock.setup_testcase.return_value = ([], None, 'path')
    impact_task.execute_task(self.testcase.key.id(), 'job')
    self.expect_unchanged()

  def test_build_failed_exception(self):
    """Test when BuildFailedException occurs."""
    self.mock.get_impacts_on_prod_builds.side_effect = (
        impact_task.BuildFailedException('error-from-build'))
    impact_task.execute_task(self.testcase.key.id(), 'job')

    self.expect_unchanged()
    self.assertIn('error-from-build', self.testcase.comments)
    self.assertIn(data_types.TaskState.ERROR, self.testcase.comments)
    self.mock.add_task.assert_has_calls(
        [mock.call('impact', self.testcase.key.id(), 'job', wait_time=None)])

  def test_prod_build(self):
    """Test getting impact for prod build."""
    impact_task.execute_task(self.testcase.key.id(), 'job')
    self.expect_changed()
    self.assertIn(data_types.TaskState.FINISHED, self.testcase.comments)
    self.assertNotIn('trace-stable', self.testcase.crash_stacktrace)
    self.assertNotIn('trace-beta', self.testcase.crash_stacktrace)
    self.mock.get_impacts_on_prod_builds.assert_has_calls(
        [mock.call(mock.ANY, 'path')])

  def test_prod_build_unreproducible(self):
    """Test getting impact for prod build (unreproducible)."""
    self.testcase.status = 'Unreproducible'
    self.testcase.put()
    impact_task.execute_task(self.testcase.key.id(), 'job')

    self.expect_changed()
    self.assertIn(data_types.TaskState.FINISHED, self.testcase.comments)
    self.assertIn('trace-stable', self.testcase.crash_stacktrace)
    self.assertIn('trace-beta', self.testcase.crash_stacktrace)
    self.mock.get_impacts_on_prod_builds.assert_has_calls(
        [mock.call(mock.ANY, 'path')])


class GetImpactsFromUrlTest(ComponentRevisionPatchingTest):
  """Test get_impacts_from_url."""

  def setUp(self):
    """Setup for get impacts from url test."""
    super().setUp()
    helpers.patch(self, [
        'clusterfuzz._internal.bot.tasks.impact_task.get_start_and_end_revision',
        'clusterfuzz._internal.bot.tasks.impact_task.get_impact',
        'clusterfuzz._internal.chrome.build_info.get_build_to_revision_mappings',
        'clusterfuzz._internal.build_management.revisions.revision_to_branched_from',
        'clusterfuzz._internal.datastore.data_handler.get_component_name',
    ])
    self.mock.get_component_name.return_value = None
    self.mock.revision_to_branched_from.side_effect = (
        self.mock_revision_to_branched_from)
    self.mock.get_start_and_end_revision.return_value = (1, 100)
    self.mock.get_build_to_revision_mappings.return_value = {
        'stable': {
            'revision': '398287',
            'version': '74.0.1345.34'
        },
        'beta': {
            'revision': '399171',
            'version': '75.0.1353.43'
        },
        'canary': {
            'revision': '400000',
            'version': '76.0.1234.43'
        }
    }
    self.mock.get_impact.side_effect = [
        impact_task.Impact(),
        impact_task.Impact('s', False),
        impact_task.Impact('b', True),
        impact_task.Impact('c', False)
    ]

  @staticmethod
  def mock_revision_to_branched_from(uri, rev):
    if uri == 'fish':
      return None
    if rev == 'cba1fdd4d72e7c5b874f9eeb07901792f26c871a':
      return '666666'
    if rev == '3a590058de9b3640f73741b1e95f815f5c089988':
      return '888888'
    return '777777'

  def test_bail_out_unknown_component(self):
    """Test bailing out when having an unknown component."""
    self.mock.get_component_name.return_value = 'com'
    self.assertTrue(
        impact_task.get_impacts_from_url('123:456', 'job').is_empty())
    self.mock.get_start_and_end_revision.assert_has_calls([])
    self.mock.get_build_to_revision_mappings.assert_has_calls([])
    self.mock.get_impact.assert_has_calls([])

  def test_bail_out_end_revision(self):
    """Test bailing out when there's no end_revision."""
    self.mock.get_start_and_end_revision.return_value = (1, None)
    self.assertTrue(
        impact_task.get_impacts_from_url('123:456', 'job').is_empty())
    self.mock.get_start_and_end_revision.assert_has_calls(
        [mock.call('123:456', 'job')])
    self.mock.get_build_to_revision_mappings.assert_has_calls([])
    self.mock.get_impact.assert_has_calls([])

  def test_bail_out_build_revision_mappings(self):
    """Test bailing out when there's no mapping."""
    self.mock.get_build_to_revision_mappings.return_value = {}
    self.assertTrue(
        impact_task.get_impacts_from_url('123:456', 'job',
                                         'windows').is_empty())
    self.mock.get_start_and_end_revision.assert_has_calls(
        [mock.call('123:456', 'job')])
    self.mock.get_build_to_revision_mappings.assert_has_calls(
        [mock.call('windows')])
    self.mock.get_impact.assert_has_calls([])

  def test_bail_out_no_build_to_revision_mapping(self):
    """Test bailing out when get_build_to_revision_mapping is empty"""
    self.mock.get_build_to_revision_mappings.return_value = None
    self.assertTrue(
        impact_task.get_impacts_from_url('123:456', 'job',
                                         'windows').is_empty())
    self.mock.get_start_and_end_revision.assert_has_calls(
        [mock.call('123:456', 'job')])
    self.mock.get_build_to_revision_mappings.assert_has_calls(
        [mock.call('windows')])
    self.mock.get_impact.assert_has_calls([])

  def test_bail_out_no_component_branched_from(self):
    """Test bailing out when there's no Cr-Branched-From."""
    self.mock.get_component_name.return_value = 'fish'
    self.assertTrue(
        impact_task.get_impacts_from_url('123:456', 'job',
                                         'windows').is_empty())
    self.mock.get_start_and_end_revision.assert_has_calls(
        [mock.call('123:456', 'job')])
    self.mock.get_build_to_revision_mappings.assert_has_calls(
        [mock.call('windows')])

  def test_bail_if_two_identically_named_components(self):
    """Tests we bail if a comp is given twice in the component deps."""
    self.mock.get_build_to_revision_mappings.return_value = {
        'stable': {
            'revision': '398287',
            'version': '74.0.1345.34'
        },
        'beta': {
            'revision': '400000',
            'version': '76.0.1353.43'
        }
    }
    self.mock.get_component_name.return_value = 'skia'
    self.assertTrue(
        impact_task.get_impacts_from_url('123:456', 'job',
                                         'windows').is_empty())
    self.mock.get_start_and_end_revision.assert_has_calls(
        [mock.call('123:456', 'job')])
    self.mock.get_build_to_revision_mappings.assert_has_calls(
        [mock.call('windows')])

  def test_get_impacts_es_not_exists(self):
    """Test getting impacts when extended stable doesn't exist."""
    impacts = impact_task.get_impacts_from_url('123:456', 'job', 'windows')

    self.assertEqual('', impacts.extended_stable.version)
    self.assertFalse(impacts.extended_stable.likely)
    self.assertEqual('s', impacts.stable.version)
    self.assertFalse(impacts.stable.likely)
    self.assertEqual('b', impacts.beta.version)
    self.assertTrue(impacts.beta.likely)
    self.assertEqual('c', impacts.head.version)
    self.assertFalse(impacts.head.likely)

    self.mock.get_start_and_end_revision.assert_has_calls(
        [mock.call('123:456', 'job')])
    self.mock.get_build_to_revision_mappings.assert_has_calls(
        [mock.call('windows')])
    self.mock.get_impact.assert_has_calls([
        mock.call(None, 1, 100),
        mock.call({
            'version': '74.0.1345.34',
            'revision': '398287'
        }, 1, 100),
        mock.call({
            'version': '75.0.1353.43',
            'revision': '399171'
        }, 1, 100)
    ])

  def test_get_impacts_es_exists(self):
    """Test getting impacts when extended stable exists."""
    self.mock.get_build_to_revision_mappings.return_value = {
        'extended_stable': {
            'revision': '398287',
            'version': '74.0.1345.34'
        },
        'stable': {
            'revision': '398287',
            'version': '74.0.1345.34'
        },
        'beta': {
            'revision': '399171',
            'version': '75.0.1353.43'
        },
        'canary': {
            'revision': '400000',
            'version': '76.0.1234.43'
        }
    }
    self.mock.get_impact.side_effect = [
        impact_task.Impact('es', False),
        impact_task.Impact('s', False),
        impact_task.Impact('b', True),
        impact_task.Impact('c', False)
    ]

    impacts = impact_task.get_impacts_from_url('123:456', 'job', 'windows')

    self.assertEqual('es', impacts.extended_stable.version)
    self.assertFalse(impacts.extended_stable.likely)
    self.assertEqual('s', impacts.stable.version)
    self.assertFalse(impacts.stable.likely)
    self.assertEqual('b', impacts.beta.version)
    self.assertTrue(impacts.beta.likely)
    self.assertEqual('c', impacts.head.version)
    self.assertFalse(impacts.head.likely)

    self.mock.get_start_and_end_revision.assert_has_calls(
        [mock.call('123:456', 'job')])
    self.mock.get_build_to_revision_mappings.assert_has_calls(
        [mock.call('windows')])
    self.mock.get_impact.assert_has_calls([
        mock.call({
            'version': '74.0.1345.34',
            'revision': '398287'
        }, 1, 100),
        mock.call({
            'version': '74.0.1345.34',
            'revision': '398287'
        }, 1, 100),
        mock.call({
            'version': '75.0.1353.43',
            'revision': '399171'
        }, 1, 100),
        mock.call({
            'version': '76.0.1234.43',
            'revision': '400000'
        }, 1, 100, True)
    ])

  def test_get_impacts_canary_not_exists(self):
    """Test getting impacts when extended stable exists."""
    self.mock.get_build_to_revision_mappings.return_value = {
        'extended_stable': {
            'revision': '398287',
            'version': '74.0.1345.34'
        },
        'stable': {
            'revision': '398287',
            'version': '74.0.1345.34'
        },
        'beta': {
            'revision': '399171',
            'version': '75.0.1353.43'
        },
        'dev': {
            'revision': '400000',
            'version': '76.0.1234.43'
        }
    }
    self.mock.get_impact.side_effect = [
        impact_task.Impact('es', False),
        impact_task.Impact('s', False),
        impact_task.Impact('b', True),
        impact_task.Impact('d', False)
    ]

    impacts = impact_task.get_impacts_from_url('123:456', 'job', 'windows')

    self.assertEqual('es', impacts.extended_stable.version)
    self.assertFalse(impacts.extended_stable.likely)
    self.assertEqual('s', impacts.stable.version)
    self.assertFalse(impacts.stable.likely)
    self.assertEqual('b', impacts.beta.version)
    self.assertTrue(impacts.beta.likely)
    self.assertEqual('d', impacts.head.version)
    self.assertFalse(impacts.head.likely)

    self.mock.get_start_and_end_revision.assert_has_calls(
        [mock.call('123:456', 'job')])
    self.mock.get_build_to_revision_mappings.assert_has_calls(
        [mock.call('windows')])
    self.mock.get_impact.assert_has_calls([
        mock.call({
            'version': '74.0.1345.34',
            'revision': '398287'
        }, 1, 100),
        mock.call({
            'version': '74.0.1345.34',
            'revision': '398287'
        }, 1, 100),
        mock.call({
            'version': '75.0.1353.43',
            'revision': '399171'
        }, 1, 100),
        mock.call({
            'version': '76.0.1234.43',
            'revision': '400000'
        }, 1, 100, True)
    ])

  def test_get_impacts_known_component_es_not_exists(self):
    """Test getting impacts for a known component
    when extended stable doesn't exists."""
    self.mock.get_component_name.return_value = 'v8'
    self.mock.get_impact.side_effect = [
        impact_task.Impact('s', False),
        impact_task.Impact('b', True),
        impact_task.Impact('c', False)
    ]
    impacts = impact_task.get_impacts_from_url('123:456', 'job', 'windows')

    self.assertEqual('', impacts.extended_stable.version)
    self.assertFalse(impacts.extended_stable.likely)
    self.assertEqual('s', impacts.stable.version)
    self.assertFalse(impacts.stable.likely)
    self.assertEqual('b', impacts.beta.version)
    self.assertTrue(impacts.beta.likely)

    self.mock.get_start_and_end_revision.assert_has_calls(
        [mock.call('123:456', 'job')])
    self.mock.get_build_to_revision_mappings.assert_has_calls(
        [mock.call('windows')])
    self.mock.get_impact.assert_has_calls([
        mock.call({
            'version': '74.0.1345.34',
            'revision': '666666'
        }, 1, 100, False),
        mock.call({
            'version': '75.0.1353.43',
            'revision': '888888'
        }, 1, 100, False),
        mock.call({
            'version': '76.0.1234.43',
            'revision': '888888'
        }, 1, 100, True)
    ])

  def test_get_impacts_known_component_es_exists(self):
    """Test getting impacts for a known component
    when extended stable exists."""
    self.mock.get_component_name.return_value = 'v8'
    self.mock.get_build_to_revision_mappings.return_value = {
        'extended_stable': {
            'revision': '398287',
            'version': '74.0.1345.34'
        },
        'stable': {
            'revision': '398287',
            'version': '74.0.1345.34'
        },
        'beta': {
            'revision': '399171',
            'version': '75.0.1353.43'
        },
        'canary': {
            'revision': '400000',
            'version': '76.0.1234.43'
        }
    }
    self.mock.get_impact.side_effect = [
        impact_task.Impact('es', False),
        impact_task.Impact('s', False),
        impact_task.Impact('b', True),
        impact_task.Impact('c', True)
    ]
    impacts = impact_task.get_impacts_from_url('123:456', 'job', 'windows')

    self.assertEqual('es', impacts.extended_stable.version)
    self.assertFalse(impacts.extended_stable.likely)
    self.assertEqual('s', impacts.stable.version)
    self.assertFalse(impacts.stable.likely)
    self.assertEqual('b', impacts.beta.version)
    self.assertTrue(impacts.beta.likely)
    self.assertEqual('c', impacts.head.version)
    self.assertTrue(impacts.head.likely)

    self.mock.get_start_and_end_revision.assert_has_calls(
        [mock.call('123:456', 'job')])
    self.mock.get_build_to_revision_mappings.assert_has_calls(
        [mock.call('windows')])
    self.mock.get_impact.assert_has_calls([
        mock.call({
            'version': '74.0.1345.34',
            'revision': '666666'
        }, 1, 100, False),
        mock.call({
            'version': '75.0.1353.43',
            'revision': '888888'
        }, 1, 100, False),
        mock.call({
            'version': '76.0.1234.43',
            'revision': '888888'
        }, 1, 100, True)
    ])

  def test_get_impacts_known_component_es_exists_canary_not_exists(self):
    """Test getting impacts for a known component
    when extended stable exists and canary doesn't."""
    self.mock.get_component_name.return_value = 'v8'
    self.mock.get_build_to_revision_mappings.return_value = {
        'extended_stable': {
            'revision': '398287',
            'version': '74.0.1345.34'
        },
        'stable': {
            'revision': '398287',
            'version': '74.0.1345.34'
        },
        'beta': {
            'revision': '399171',
            'version': '75.0.1353.43'
        },
        'dev': {
            'revision': '400000',
            'version': '76.0.1234.43'
        }
    }
    self.mock.get_impact.side_effect = [
        impact_task.Impact('es', False),
        impact_task.Impact('s', False),
        impact_task.Impact('b', True),
        impact_task.Impact('c', True)
    ]
    impacts = impact_task.get_impacts_from_url('123:456', 'job', 'windows')

    self.assertEqual('es', impacts.extended_stable.version)
    self.assertFalse(impacts.extended_stable.likely)
    self.assertEqual('s', impacts.stable.version)
    self.assertFalse(impacts.stable.likely)
    self.assertEqual('b', impacts.beta.version)
    self.assertTrue(impacts.beta.likely)
    self.assertEqual('c', impacts.head.version)
    self.assertTrue(impacts.head.likely)

    self.mock.get_start_and_end_revision.assert_has_calls(
        [mock.call('123:456', 'job')])
    self.mock.get_build_to_revision_mappings.assert_has_calls(
        [mock.call('windows')])
    self.mock.get_impact.assert_has_calls([
        mock.call({
            'version': '74.0.1345.34',
            'revision': '666666'
        }, 1, 100, False),
        mock.call({
            'version': '75.0.1353.43',
            'revision': '888888'
        }, 1, 100, False),
        mock.call({
            'version': '76.0.1234.43',
            'revision': '888888'
        }, 1, 100, True)
    ])


class GetImpactTest(unittest.TestCase):
  """Test get_impact."""

  def test_bail_out_build_revision(self):
    """Test bailing out when there's no build_revision."""
    self.assertTrue(impact_task.get_impact({}, 1, 100).is_empty())

  def test_bail_out_non_digit(self):
    """Test bailing out when revision is not a number."""
    self.assertTrue(
        impact_task.get_impact({
            'revision': 'aa'
        }, 1, 100).is_empty())

  def test_empty_impact(self):
    """Test returning empty impact when start_revision is greater than the build
      revision."""
    self.assertTrue(
        impact_task.get_impact({
            'revision': '10',
            'version': '50'
        }, 20, 100).is_empty())

  def test_get_impact(self):
    """Test getting version."""
    impact = impact_task.get_impact({'revision': '30', 'version': '50'}, 20, 25)
    self.assertEqual('50', impact.version)
    self.assertFalse(impact.likely)
    self.assertEqual('', impact.extra_trace)

  def test_get_likely_impact(self):
    """Test getting likely version."""
    impact = impact_task.get_impact({'revision': '30', 'version': '50'}, 20, 31)
    self.assertEqual('50', impact.version)
    self.assertTrue(impact.likely)
    self.assertEqual('', impact.extra_trace)

  def test_get_beyond_build(self):
    """Test if the regression range is beyond the version."""
    impact = impact_task.get_impact({'revision': '30', 'version': '50'}, 31, 32)
    self.assertTrue(impact.is_empty())

  def test_get_beyond_build_if_final(self):
    """Test getting likely version."""
    impact = impact_task.get_impact({
        'revision': '30',
        'version': '50.1.2.3'
    }, 31, 32, True)
    self.assertEqual('50', impact.version)
    self.assertTrue(impact.likely)
    self.assertEqual('', impact.extra_trace)


class GetImpactsOnProdBuilds(unittest.TestCase):
  """Test get_impacts_on_prod_builds."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.bot.tasks.impact_task.get_impact_on_build',
        'clusterfuzz._internal.bot.tasks.impact_task.get_impacts_from_url',
        'clusterfuzz._internal.bot.testcase_manager.get_command_line_for_application',
        'clusterfuzz._internal.chrome.build_info.get_build_to_revision_mappings',
    ])
    self.mock.get_build_to_revision_mappings.return_value = {
        'stable': {
            'revision': '398287',
            'version': '74.0.1345.34'
        },
        'beta': {
            'revision': '399171',
            'version': '75.0.1353.43'
        },
        'canary': {
            'revision': '400000',
            'version': '76.0.1234.43'
        }
    }
    self.impacts = impact_task.Impacts(
        stable=impact_task.Impact('s', False),
        beta=impact_task.Impact('b', True),
        extended_stable=impact_task.Impact('es', False),
        head=impact_task.Impact('76.0.1234.43', False))

    self.testcase = data_types.Testcase()
    self.testcase.job_type = 'job'
    self.testcase.impact_extended_stable_version = 'es-ver'
    self.testcase.impact_stable_version = 's-ver'
    self.testcase.impact_beta_version = 'b-ver'
    self.testcase.regression = '123:456'

  def test_app_failed_on_stable(self):
    """Test raising AppFailedException when getting stable impact."""
    self.mock.get_impact_on_build.side_effect = impact_task.AppFailedException()
    self.mock.get_impacts_from_url.return_value = self.impacts

    self.assertEqual(
        self.impacts,
        impact_task.get_impacts_on_prod_builds(self.testcase, 'path'))
    self.mock.get_impact_on_build.assert_has_calls([
        mock.call('stable', self.testcase.impact_stable_version, self.testcase,
                  'path')
    ])
    self.mock.get_impacts_from_url.assert_has_calls(
        [mock.call(self.testcase.regression, self.testcase.job_type)])

  def test_app_failed_on_beta(self):
    """Test app fail on beta."""
    self.mock.get_impact_on_build.side_effect = [
        self.impacts.stable,
        impact_task.AppFailedException(),
        self.impacts.extended_stable,
    ]

    self.assertEqual(
        impact_task.Impacts(
            self.impacts.stable,
            impact_task.Impact(),
            self.impacts.extended_stable,
            head=self.impacts.head),
        impact_task.get_impacts_on_prod_builds(self.testcase, 'path'))
    self.mock.get_impact_on_build.assert_has_calls([
        mock.call('stable', self.testcase.impact_stable_version, self.testcase,
                  'path'),
        mock.call('beta', self.testcase.impact_beta_version, self.testcase,
                  'path'),
        mock.call('extended_stable',
                  self.testcase.impact_extended_stable_version, self.testcase,
                  'path'),
    ])
    self.mock.get_impacts_from_url.assert_has_calls([])

  def test_app_failed_on_extended_stable(self):
    """Test app fail on extended stable."""
    self.mock.get_impact_on_build.side_effect = [
        self.impacts.stable,
        self.impacts.beta,
        impact_task.AppFailedException(),
    ]
    self.mock.get_impacts_from_url.return_value = self.impacts

    self.assertEqual(
        self.impacts,
        impact_task.get_impacts_on_prod_builds(self.testcase, 'path'))
    self.mock.get_impact_on_build.assert_has_calls([
        mock.call('stable', self.testcase.impact_stable_version, self.testcase,
                  'path'),
        mock.call('beta', self.testcase.impact_beta_version, self.testcase,
                  'path'),
        mock.call('extended_stable',
                  self.testcase.impact_extended_stable_version, self.testcase,
                  'path'),
    ])
    self.mock.get_impacts_from_url.assert_has_calls(
        [mock.call(self.testcase.regression, self.testcase.job_type)])

  def test_get_impacts(self):
    """Test getting impacts."""
    self.mock.get_impact_on_build.side_effect = [
        self.impacts.stable, self.impacts.beta, self.impacts.extended_stable
    ]

    self.assertEqual(
        self.impacts,
        impact_task.get_impacts_on_prod_builds(self.testcase, 'path'))
    self.mock.get_impact_on_build.assert_has_calls([
        mock.call('stable', self.testcase.impact_stable_version, self.testcase,
                  'path'),
        mock.call('beta', self.testcase.impact_beta_version, self.testcase,
                  'path'),
        mock.call('extended_stable',
                  self.testcase.impact_extended_stable_version, self.testcase,
                  'path'),
    ])
    self.mock.get_impacts_from_url.assert_has_calls([])

  def test_get_impacts_canary_not_exists(self):
    """Test getting impacts if there's no Canary build, only dev."""
    self.mock.get_impact_on_build.side_effect = [
        self.impacts.stable, self.impacts.beta, self.impacts.extended_stable
    ]
    self.mock.get_build_to_revision_mappings.return_value = {
        'stable': {
            'revision': '398287',
            'version': '74.0.1345.34'
        },
        'beta': {
            'revision': '399171',
            'version': '75.0.1353.43'
        },
        'dev': {
            'revision': '400000',
            'version': '76.0.1234.43'
        }
    }

    self.assertEqual(
        self.impacts,
        impact_task.get_impacts_on_prod_builds(self.testcase, 'path'))
    self.mock.get_impact_on_build.assert_has_calls([
        mock.call('stable', self.testcase.impact_stable_version, self.testcase,
                  'path'),
        mock.call('beta', self.testcase.impact_beta_version, self.testcase,
                  'path'),
        mock.call('extended_stable',
                  self.testcase.impact_extended_stable_version, self.testcase,
                  'path'),
    ])
    self.mock.get_impacts_from_url.assert_has_calls([])


class GetImpactOnBuild(unittest.TestCase):
  """Test get_impact_on_build."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.build_management.build_manager.setup_production_build',
        'clusterfuzz._internal.system.environment.get_value',
        'clusterfuzz._internal.bot.testcase_manager.get_command_line_for_application',
        'clusterfuzz._internal.bot.testcase_manager.test_for_crash_with_retries',
    ])
    self.env = {
        'APP_PATH': 'app',
        'TEST_TIMEOUT': '9',
        'JOB_NAME': 'linux_asan_chrome',
        'TOOL_NAME': 'ASAN'
    }
    self.result = mock.Mock()
    self.result.is_crash = mock.Mock()
    self.result.get_stacktrace = mock.Mock()

    self.mock.setup_production_build.return_value = (
        build_manager.ProductionBuild('/base', '52', None, 'stable'))
    self.mock.get_value.side_effect = self.env.get
    self.mock.test_for_crash_with_retries.return_value = self.result
    self.result.is_crash.return_value = True
    self.result.get_stacktrace.return_value = 'crashed-trace'

    self.testcase = data_types.Testcase()

  def test_build_failed(self):
    """Test raising BuildFailedException."""
    self.mock.setup_production_build.return_value = None
    with self.assertRaises(impact_task.BuildFailedException) as cm:
      impact_task.get_impact_on_build('stable', '52', self.testcase, 'path')

    self.assertEqual('Build setup failed for Stable', str(cm.exception))

  def test_app_failed(self):
    """Test raising AppFailedException."""
    self.env['APP_PATH'] = ''
    self.env['APP_NAME'] = 'app_name'
    with self.assertRaises(impact_task.AppFailedException):
      impact_task.get_impact_on_build('stable', '52', self.testcase, 'path')

  def test_same_version(self):
    """Test same version."""
    impact = impact_task.get_impact_on_build('stable', '52', self.testcase,
                                             'path')
    self.assertEqual('52', impact.version)
    self.assertFalse(impact.likely)
    self.assertEqual('', impact.extra_trace)

  def test_crash(self):
    """Test crashing."""
    impact = impact_task.get_impact_on_build('stable', '53', self.testcase,
                                             'path')
    self.assertEqual('52', impact.version)
    self.assertFalse(impact.likely)
    self.assertIn('crashed-trace', impact.extra_trace)

  def test_not_crash(self):
    """Test not crashing and returning empty impact."""
    self.result.is_crash.return_value = False
    self.assertEqual(
        impact_task.Impact(),
        impact_task.get_impact_on_build('stable', '53', self.testcase, 'path'))


class GetStartAndEndRevisionTest(unittest.TestCase):
  """Test get_start_and_end_revision."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.build_management.revisions.get_start_and_end_revision',
        'clusterfuzz._internal.build_management.revisions.get_component_range_list',
        'clusterfuzz._internal.bot.testcase_manager.get_command_line_for_application',
        'clusterfuzz._internal.system.environment.is_android',
    ])

  def test_normal(self):
    """Test when there's no end revision."""
    self.mock.is_android.return_value = False
    self.mock.get_start_and_end_revision.return_value = (1, 100)
    start, end = impact_task.get_start_and_end_revision('123:456', 'job')

    self.assertEqual(1, start)
    self.assertEqual(100, end)
    self.mock.get_start_and_end_revision.assert_has_calls(
        [mock.call('123:456')])
    self.mock.get_component_range_list.assert_has_calls([])

  def test_android(self):
    """Test android."""
    self.mock.is_android.return_value = True
    self.mock.get_start_and_end_revision.side_effect = [(1, 100), (9, 90)]
    self.mock.get_component_range_list.return_value = [{
        'component': 'test'
    }, {
        'component': 'Chromium',
        'link_text': 'somelink'
    }, {
        'component': 'test'
    }]
    start, end = impact_task.get_start_and_end_revision('123:456',
                                                        'android_job')

    self.assertEqual(9, start)
    self.assertEqual(90, end)
    self.mock.get_start_and_end_revision.assert_has_calls(
        [mock.call('123:456'), mock.call('somelink')])
    self.mock.get_component_range_list.assert_has_calls(
        [mock.call(1, 100, 'android_job')])
