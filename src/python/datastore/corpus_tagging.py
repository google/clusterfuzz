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
"""Helper functions for managing corpus tags."""

from datastore import data_types


def get_fuzz_target_tag(fuzz_target_name):
  """Get all the tag of a given fuzz target."""
  query = data_types.CorpusTag().query()
  query = query.filter(
      data_types.CorpusTag.fuzz_target_name == fuzz_target_name)
  return list(query)


def get_targets_with_tag(tag):
  """Get all fuzz targets with a given tag."""
  query = data_types.CorpusTag().query()
  query = query.filter(data_types.CorpusTag.tag == tag)
  return list(query)
