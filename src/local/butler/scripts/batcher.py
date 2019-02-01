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
"""batcher.py queries in batches and allow users to perform operation on
  each entity."""


def iterate(query, batch_size):
  """Query in batches."""
  count = 0
  batch = []

  for item in query:
    batch.append(item)
    count += 1

    if len(batch) >= batch_size:
      yield batch
      batch = []

  if batch:
    yield batch
