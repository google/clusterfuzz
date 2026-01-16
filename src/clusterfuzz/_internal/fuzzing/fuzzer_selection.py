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

from google.cloud import ndb

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import fuzz_target_utils
from clusterfuzz._internal.datastore import ndb_utils
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.platforms.android import constants
from clusterfuzz._internal.system import environment

# Used to prepare targets to be passed to utils.random_weighted_choice.
WeightedTarget = collections.namedtuple('WeightedTarget', ['target', 'weight'])


def update_mappings_for_fuzzer(fuzzer, mappings=None):
  """Clear existing mappings for a fuzzer, and replace them."""
  if mappings is None:
    # Make a copy in case we need to modify it.
    mappings = fuzzer.jobs.copy()

  query = data_types.FuzzerJob.query()
  query = query.filter(data_types.FuzzerJob.fuzzer == fuzzer.name)
  fuzzer_job_entities = ndb_utils.get_all_from_query(query)
  old_mappings = {}
  for fuzzer_job in fuzzer_job_entities:
    old_mappings[fuzzer_job.job] = fuzzer_job

  new_mappings = []
  if mappings:
    jobs = ndb_utils.get_all_from_query(data_types.Job.query().filter(
        data_types.Job.name.IN(mappings)))
    jobs = {job.name: job for job in jobs}
  else:
    jobs = {}

  fuzzer_modified = False

  for job_name in mappings:
    if job_name not in jobs:
      # Job references a deleted job, clean it up.
      try:
        fuzzer.jobs.remove(job_name)
        fuzzer_modified = True
      except ValueError:
        # If `mappings` was provided via an argument, it's possible it won't
        # exist in `fuzzer.jobs`.
        pass

      continue

    mapping = old_mappings.pop(job_name, None)
    if not mapping:
      mapping = data_types.FuzzerJob()
    mapping.fuzzer = fuzzer.name
    mapping.job = job_name
    mapping.platform = jobs[job_name].platform
    new_mappings.append(mapping)

  ndb_utils.put_multi(new_mappings)
  ndb_utils.delete_multi([m.key for m in list(old_mappings.values())])

  if fuzzer_modified:
    fuzzer.put()


def update_mappings_for_job(job, mappings):
  """Clear existing mappings for a job, and replace them."""
  existing_fuzzers = {
      fuzzer.name: fuzzer
      for fuzzer in data_types.Fuzzer.query()
      if job.name in fuzzer.jobs
  }
  modified_fuzzers = []

  for fuzzer_name in mappings:
    fuzzer = existing_fuzzers.pop(fuzzer_name, None)
    if fuzzer:
      continue

    fuzzer = data_types.Fuzzer.query(
        data_types.Fuzzer.name == fuzzer_name).get()
    if not fuzzer:
      logs.error('An unknown fuzzer %s was selected for job %s.' % (fuzzer_name,
                                                                    job.name))
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

  platforms = [platform]
  base_platform = platform.split(':')[0]

  # Conditionally append the base platform (e.g. ANDROID) as a job filter,
  # unless the platform is restricted or is the base platform itself.
  if platform != base_platform:
    if platform not in constants.DEVICES_WITH_NO_FALLBACK_QUEUE_LIST:
      platforms.append(base_platform)
    else:
      logs.info(f'{platform} is part of devices with no fallback list. '
                f'Hence skipping inclusion of the generic platform '
                f'({base_platform}) while querying.')

  if environment.is_production():
    query = data_types.FuzzerJobs.query()
    query = query.filter(data_types.FuzzerJobs.platform.IN(platforms))

    mappings = []
    for entity in query:
      mappings.extend(entity.fuzzer_jobs)
  else:
    # 'FuzzerJobs' may not exist locally because they are created by
    # the 'batch_fuzzer_jobs' cron job
    query = data_types.FuzzerJob.query()
    query = query.filter(data_types.FuzzerJob.platform.IN(platforms))
    mappings = list(ndb_utils.get_all_from_query(query))[:1]

  if not mappings:
    return None, None

  selected_mappings = mappings
  # The environment variable containing a list of comma-separated jobs.
  # E.g: "libfuzzer_asan_android_host,afl_asan_android_host,..."
  jobs_selection = environment.get_value('HOST_JOB_SELECTION')
  if jobs_selection:
    jobs = get_job_list(jobs_selection)
    selected_mappings = [entity for entity in mappings if entity.job in jobs]

  if not selected_mappings:
    return None, None

  selection = utils.random_weighted_choice(
      selected_mappings, weight_attribute='actual_weight')
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
      logs.error('Skipping weight assignment for fuzz target '
                 f'{target_job.fuzz_target_name}.')
      continue

    weights[fuzz_target.binary] = target_job.weight

  return weights


def get_job_list(jobs_str):
  if jobs_str:
    return [job.strip() for job in jobs_str.split(',')]

  return []
