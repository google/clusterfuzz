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
"""Script to interact with fuzzer weights in the database.

Usage:

  python butler.py weights -c CONFIG_DIR [-p PLATFORM]

"""

import os
from typing import Optional
from typing import Sequence

from src.clusterfuzz._internal.config import local_config
from src.clusterfuzz._internal.datastore import data_types
from src.clusterfuzz._internal.datastore import ndb_init
from src.clusterfuzz._internal.datastore import ndb_utils


def list_platforms() -> None:
  platforms = [
      item.platform for item in data_types.FuzzerJob.query(
          projection=[data_types.FuzzerJob.platform], distinct=True)
  ]
  for platform in platforms:
    print(platform)


def _query_fuzzer_jobs_batches(platforms: Optional[Sequence[str]] = None,
                              ) -> Sequence[data_types.FuzzerJobs]:
  query = data_types.FuzzerJobs.query()

  if platforms:
    query = query.filter(data_types.FuzzerJobs.platform.IN(platforms))

  return query


def _query_fuzzer_jobs(
    platforms: Optional[Sequence[str]] = None,
    fuzzers: Optional[Sequence[str]] = None,
    jobs: Optional[Sequence[str]] = None,
) -> Sequence[data_types.FuzzerJob]:
  query = data_types.FuzzerJob.query()

  if platforms:
    query = query.filter(data_types.FuzzerJob.platform.IN(platforms))
  if fuzzers:
    query = query.filter(data_types.FuzzerJob.fuzzer.IN(fuzzers))
  if jobs:
    query = query.filter(data_types.FuzzerJob.job.IN(jobs))

  return query


def flatten_fuzzer_jobs_batches(
    batches: Sequence[data_types.FuzzerJobs]) -> Sequence[data_types.FuzzerJob]:
  for batch in batches:
    for item in batch.fuzzer_jobs:
      yield item


def list_fuzzer_jobs(fuzzer_jobs: Sequence[data_types.FuzzerJob]) -> None:
  fuzzer_jobs = list(fuzzer_jobs)
  fuzzer_jobs.sort(key=lambda fj: fj.actual_weight, reverse=True)

  total_weight = sum(fj.actual_weight for fj in fuzzer_jobs)

  for fuzzer_job in fuzzer_jobs:
    probability = fuzzer_job.actual_weight / total_weight

    print("FuzzerJob:")
    print(f'  Fuzzer: {fuzzer_job.fuzzer}')
    print(f'  Job: {fuzzer_job.job}')
    print(f'  Platform: {fuzzer_job.platform}')
    print(f'  Weight: {fuzzer_job.actual_weight} = ' +
          f'{fuzzer_job.weight} * {fuzzer_job.multiplier}')
    print(f'  Probability: {probability} = {probability * 100:0.02f}%')

  print(f'Count: {len(fuzzer_jobs)}')
  print(f'Total weight (for this query): {total_weight}')


def print_fuzzer_jobs_stats(
    platforms: Sequence[str],
    fuzzers: Sequence[str],
    jobs: Sequence[str],
) -> None:
  fuzzer_jobs = query_fuzzer_jobs(platforms, fuzzers, jobs)
  total_weight = sum(fj.actual_weight for fj in fuzzer_jobs)
  print("Total weight: {}")


def execute(args) -> None:
  os.environ['CONFIG_DIR_OVERRIDE'] = args.config_dir
  local_config.ProjectConfig().set_environment()

  with ndb_init.context():
    if args.weights_command == 'platforms':
      list_platforms()
    elif args.weights_command == 'list':
      list_fuzzer_jobs(
          _query_fuzzer_jobs(
              platforms=args.platforms, fuzzers=args.fuzzers, jobs=args.jobs))
    elif args.weights_command == 'stats':
      print_fuzzer_jobs_stats(args.platforms, args.fuzzers, args.jobs)
    else:
      raise TypeError(f'weights command {repr(command)} unrecognized')
