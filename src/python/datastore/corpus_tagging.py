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


def get_fuzz_target_tag(fully_qualified_fuzz_target_name):
  """Get all the tags of a given fuzz target."""
  query = data_types.CorpusTag().query()
  query = query.filter(data_types.CorpusTag.fully_qualified_fuzz_target_name ==
                       fully_qualified_fuzz_target_name)
  return query.fetch()


def get_targets_with_tag(tag):
  """Get all fuzz targets with a given tag."""
  query = data_types.CorpusTag().query()
  query = query.filter(data_types.CorpusTag.tag == tag)
  return query.fetch()

def get_similarly_tagged_fuzzers(current_fully_qualified_fuzzer_name):
  similarly_tagged_targets = []
  for tag in get_fuzz_target_tag(current_fully_qualified_fuzzer_name):
    similarly_tagged_targets += get_targets_with_tag(tag)

  return similarly_tagged_targets

