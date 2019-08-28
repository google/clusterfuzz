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
"""Helper functions related to fuzz target entities."""

from datastore import data_types
from datastore import ndb
from datastore import ndb_utils
from metrics import logs


def get_fuzz_targets_for_target_jobs(target_jobs):
  """Return corresponding FuzzTargets for the given FuzzTargetJobs."""
  target_keys = [
      ndb.Key(data_types.FuzzTarget, t.fuzz_target_name) for t in target_jobs
  ]
  fuzz_targets = ndb.get_multi(target_keys)

  for fuzz_target, target_job in zip(fuzz_targets, target_jobs):
    # ndb.get_multi returns None for a non-existent key, log missing FuzzTarget.
    if not fuzz_target:
      logs.log_error('FuzzTarget entity for %s does not exist.' %
                     target_job.fuzz_target_name)

  return fuzz_targets


def get_fuzz_target_jobs(fuzz_target_name=None,
                         engine=None,
                         job=None,
                         limit=None):
  """Return a Datastore query for fuzz target to job mappings."""
  query = data_types.FuzzTargetJob.query()

  if fuzz_target_name:
    query = query.filter(
        data_types.FuzzTargetJob.fuzz_target_name == fuzz_target_name)

  if job:
    query = query.filter(data_types.FuzzTargetJob.job == job)

  if engine:
    query = query.filter(data_types.FuzzTargetJob.engine == engine)

  if limit is not None:
    return query.iter(limit=limit)

  return ndb_utils.get_all_from_query(query)
