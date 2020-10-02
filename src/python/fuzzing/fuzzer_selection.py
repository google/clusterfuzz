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
"""Helper functions to update fuzzer-job mappings, and select fuzzers to run."""

import collections

from base import utils
from datastore import data_types
from datastore import fuzz_target_utils
from datastore import ndb_utils
from google.cloud import ndb
from metrics import logs
from system import environment

# Used to prepare targets to be passed to utils.random_weighted_choice.
WeightedTarget = collections.namedtuple('WeightedTarget', ['target', 'weight'])


def update_mappings_for_fuzzer(fuzzer, mappings=None):
  """Clear existing mappings for a fuzzer, and replace them."""
  if mappings is None:
    mappings = fuzzer.jobs

  query = data_types.FuzzerJob.query()
  query = query.filter(data_types.FuzzerJob.fuzzer == fuzzer.name)
  entities = ndb_utils.get_all_from_query(query)
  old_mappings = {}
  for entity in entities:
    old_mappings[entity.job] = entity

  new_mappings = []
  for job_name in mappings:
    mapping = old_mappings.pop(job_name, None)
    if mapping:
      continue

    job = data_types.Job.query(data_types.Job.name == job_name).get()
    if not job:
      logs.log_error('An unknown job %s was selected for fuzzer %s.' %
                     (job_name, fuzzer.name))
      continue

    mapping = data_types.FuzzerJob()
    mapping.fuzzer = fuzzer.name
    mapping.job = job_name
    mapping.platform = job.platform
    new_mappings.append(mapping)

  ndb_utils.put_multi(new_mappings)
  ndb_utils.delete_multi([m.key for m in list(old_mappings.values())])


def update_mappings_for_job(job, mappings):
  """Clear existing mappings for a job, and replace them."""
  existing_fuzzers_query = data_types.Fuzzer.query(
      data_types.Fuzzer.jobs == job.name)
  existing_fuzzers = {fuzzer.name: fuzzer for fuzzer in existing_fuzzers_query}
  modified_fuzzers = []

  for fuzzer_name in mappings:
    fuzzer = existing_fuzzers.pop(fuzzer_name, None)
    if fuzzer:
      continue

    fuzzer = data_types.Fuzzer.query(
        data_types.Fuzzer.name == fuzzer_name).get()
    if not fuzzer:
      logs.log_error('An unknown fuzzer %s was selected for job %s.' %
                     (fuzzer_name, job.name))
      continue

    fuzzer.jobs.append(job.name)
    modified_fuzzers.append(fuzzer)
    update_mappings_for_fuzzer(fuzzer)

  # Removing the remaining values in exisiting_fuzzers as
  # they are no longer mapped.
  for fuzzer in existing_fuzzers.values():
    fuzzer.jobs.remove(job.name)
    modified_fuzzers.append(fuzzer)
    update_mappings_for_fuzzer(fuzzer)
  ndb.put_multi(modified_fuzzers)


def update_platform_for_job(job_name, new_platform):
  """Update platform for all mappings for a particular job."""
  query = data_types.FuzzerJob.query()
  query = query.filter(data_types.FuzzerJob.job == job_name)
  mappings = ndb_utils.get_all_from_query(query)
  new_mappings = []
  for mapping in mappings:
    mapping.platform = new_platform
    new_mappings.append(mapping)
  ndb_utils.put_multi(new_mappings)


def get_fuzz_task_payload(platform=None):
  """Select a fuzzer that can run on this platform."""
  if not platform:
    queue_override = environment.get_value('QUEUE_OVERRIDE')
    platform = queue_override if queue_override else environment.platform()

  if environment.is_local_development():
    query = data_types.FuzzerJob.query()
    query = query.filter(data_types.FuzzerJobs.platform == platform)
    mappings = list(ndb_utils.get_all_from_query(query))
  else:
    query = data_types.FuzzerJobs.query()
    query = query.filter(data_types.FuzzerJobs.platform == platform)

    mappings = []
    for entity in query:
      mappings.extend(entity.fuzzer_jobs)

  if not mappings:
    return None, None

  selection = utils.random_weighted_choice(
      mappings, weight_attribute='actual_weight')
  return selection.fuzzer, selection.job


def select_fuzz_target(targets, target_weights):
  """Select a fuzz target from a list of potential targets."""
  assert targets

  weighted_targets = []
  for target in targets:
    weight = target_weights.get(target, 1.0)
    weighted_targets.append(WeightedTarget(target, weight))

  return utils.random_weighted_choice(weighted_targets).target


def get_fuzz_target_weights():
  """Get a list of fuzz target weights based on the current fuzzer."""
  job_type = environment.get_value('JOB_NAME')

  target_jobs = list(fuzz_target_utils.get_fuzz_target_jobs(job=job_type))
  fuzz_targets = fuzz_target_utils.get_fuzz_targets_for_target_jobs(target_jobs)

  weights = {}
  for fuzz_target, target_job in zip(fuzz_targets, target_jobs):
    if not fuzz_target:
      logs.log_error('Skipping weight assignment for fuzz target %s.' %
                     target_job.fuzz_target_name)
      continue

    weights[fuzz_target.binary] = target_job.weight

  return weights
