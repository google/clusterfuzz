# Copyright 2024 Google LLC
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
"""FeatureFlag tests."""
import unittest

from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import feature_flags
from clusterfuzz._internal.tests.test_libs import test_utils


@test_utils.with_cloud_emulators('datastore')
class FeatureFlagTest(unittest.TestCase):
  """Test FeatureFlag."""

  def test_get_and_set(self):
    """Test getting and setting feature flags."""
    # Create a boolean feature flag.
    flag = data_types.FeatureFlag(id=feature_flags.FeatureFlags.TEST_FLAG.value)
    flag.description = 'A test boolean flag'
    flag.enabled = True
    flag.put()

    # Create a float feature flag.
    flag_float = data_types.FeatureFlag(
        id=feature_flags.FeatureFlags.TEST_FLOAT_FLAG.value)
    flag_float.description = 'A test float flag'
    flag_float.enabled = True
    flag_float.value = 1.23
    flag_float.put()

    # Retrieve and verify.
    self.assertIsNotNone(feature_flags.FeatureFlags.TEST_FLAG.flag)
    self.assertTrue(feature_flags.FeatureFlags.TEST_FLAG.enabled)
    self.assertEqual(feature_flags.FeatureFlags.TEST_FLAG.description,
                     'A test boolean flag')
    self.assertIsNone(feature_flags.FeatureFlags.TEST_FLAG.content)

    retrieved_flag_float = feature_flags.FeatureFlags.TEST_FLOAT_FLAG.flag
    self.assertIsNotNone(retrieved_flag_float)
    self.assertTrue(feature_flags.FeatureFlags.TEST_FLOAT_FLAG.enabled)
    self.assertEqual(feature_flags.FeatureFlags.TEST_FLOAT_FLAG.content, 1.23)
