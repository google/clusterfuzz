# Copyright 2025 Google LLC
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
"""Datastore test utils."""

from functools import wraps

from google.cloud import ndb

from clusterfuzz._internal.datastore import data_types


def with_flags(**kwargs):
  """Sets feature flags for the duration of a test."""

  def decorator(test_func):

    @wraps(test_func)
    def wrapper(self):
      for key, value in kwargs.items():
        if isinstance(value, float):
          data_types.FeatureFlag(id=key, enabled=True, value=value).put()
        elif isinstance(value, bool):
          data_types.FeatureFlag(id=key, enabled=value).put()
      test_func(self)
      for key in kwargs:
        ndb.Key(data_types.FeatureFlag, key).delete()

    return wrapper

  return decorator
