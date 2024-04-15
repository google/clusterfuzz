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

import csv
import enum
import os
import statistics
import sys
from typing import Dict
from typing import List
from typing import Optional
from typing import Sequence
from typing import Union

from src.clusterfuzz._internal.config import local_config
from src.clusterfuzz._internal.datastore import data_types
from src.clusterfuzz._internal.datastore import ndb_init


class EntryType(enum.Enum):
  FUZZER_JOB = 'fuzzer_job'
  FUZZER_JOBS = 'fuzzer_jobs'


def _iter_weights(
    fuzzer_jobs: Sequence[data_types.FuzzerJob]) -> Sequence[float]:
  for fj in fuzzer_jobs:
    yield fj.actual_weight


def _sum_weights(fuzzer_jobs: Sequence[data_types.FuzzerJob]) -> float:
  return sum(_iter_weights(fuzzer_jobs))


def _display_prob(probability: float) -> str:
  return f'{probability:0.04f} = {probability * 100:0.02f}%'


def list_platforms() -> None:
  # Query only distinct platform values from the database.
  fuzzer_jobs = data_types.FuzzerJob.query(
      projection=[data_types.FuzzerJob.platform], distinct=True)
  for fuzzer_job in fuzzer_jobs:
    print(fuzzer_job.platform)


def _query_fuzzer_jobs_batches(platforms: Optional[Sequence[str]] = None
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
  """Queries Datastore for matching FuzzerJob entries."""
  query = data_types.FuzzerJob.query()

  if platforms:
    query = query.filter(data_types.FuzzerJob.platform.IN(platforms))
  if fuzzers:
    query = query.filter(data_types.FuzzerJob.fuzzer.IN(fuzzers))
  if jobs:
    query = query.filter(data_types.FuzzerJob.job.IN(jobs))

  return query


def _list_fuzzer_jobs(fuzzer_jobs: Sequence[data_types.FuzzerJob]) -> None:
  """Lists the given FuzzerJob entries on stdout."""
  fuzzer_jobs = list(fuzzer_jobs)
  fuzzer_jobs.sort(key=lambda fj: fj.actual_weight, reverse=True)

  total_weight = _sum_weights(fuzzer_jobs)

  for fuzzer_job in fuzzer_jobs:
    probability = fuzzer_job.actual_weight / total_weight

    print("FuzzerJob:")
    print(f'  Fuzzer: {fuzzer_job.fuzzer}')
    print(f'  Job: {fuzzer_job.job}')
    print(f'  Platform: {fuzzer_job.platform}')
    print(f'  Weight: {fuzzer_job.actual_weight} = ' +
          f'{fuzzer_job.weight} * {fuzzer_job.multiplier}')
    print(f'  Probability: {_display_prob(probability)}')

  print(f'Count: {len(fuzzer_jobs)}')
  print(f'Total weight (for this query): {total_weight}')


_FUZZER_JOB_FIELDS = [
    'fuzzer',
    'job',
    'platform',
    'weight',
    'multiplier',
    'actual_weight',
]


def _fuzzer_job_to_dict(
    fuzzer_job: data_types.FuzzerJob) -> Dict[str, Union[str, float]]:
  """Converts the given FuzzerJob to a dictionary of CSV column values."""
  return {
      'fuzzer': fuzzer_job.fuzzer,
      'job': fuzzer_job.job,
      'platform': fuzzer_job.platform,
      'weight': fuzzer_job.weight,
      'multiplier': fuzzer_job.multiplier,
      'actual_weight': fuzzer_job.actual_weight,
  }


def _dump_fuzzer_jobs() -> None:
  """Dumps FuzzerJob entries from the database to stdout in CSV format."""
  fuzzer_jobs = _query_fuzzer_jobs()

  writer = csv.DictWriter(sys.stdout, fieldnames=_FUZZER_JOB_FIELDS)
  writer.writeheader()

  for fuzzer_job in fuzzer_jobs:
    writer.writerow(_fuzzer_job_to_dict(fuzzer_job))


def _dump_fuzzer_jobs_batches() -> None:
  """Dumps FuzzerJobs entries from the database to stdout in CSV format."""
  batches = _query_fuzzer_jobs_batches()

  writer = csv.DictWriter(sys.stdout, fieldnames=['batch'] + _FUZZER_JOB_FIELDS)
  writer.writeheader()

  for batch in batches:
    for fuzzer_job in batch.fuzzer_jobs:
      fields = _fuzzer_job_to_dict(fuzzer_job)
      fields['batch'] = batch.key.id()
      writer.writerow(fields)


def _dump_entries(entry_type: EntryType) -> None:
  """Dumps entries of the given type from the database to stdout."""
  if entry_type == EntryType.FUZZER_JOB:
    _dump_fuzzer_jobs()
  elif entry_type == EntryType.FUZZER_JOBS:
    _dump_fuzzer_jobs_batches()


def _fuzzer_job_matches(
    fuzzer_job: data_types.FuzzerJob,
    fuzzers: Optional[Sequence[str]],
    jobs: Optional[Sequence[str]],
) -> bool:
  """Returns whether the given FuzzerJob matches the given optional filters."""
  if fuzzers and fuzzer_job.fuzzer not in fuzzers:
    return False

  if jobs and fuzzer_job.job not in jobs:
    return False

  return True


def _print_stats(fuzzer_jobs: List[data_types.FuzzerJob],
                 total_weight: float) -> None:
  """Helper for `_aggregate_fuzzer_jobs()`."""
  weight = _sum_weights(fuzzer_jobs)
  probability = weight / total_weight

  print(f'  Count: {len(fuzzer_jobs)}')
  print(f'  Total weight: {weight}')
  print(f'  Total probability: {_display_prob(probability)}')

  # New in Python 3.8. We appease the linter by disabling `no-member` below.
  if not hasattr(statistics, 'quantiles'):
    return

  # `quantiles()` returns n-1 cut points between n quantiles.
  # `weight_deciles[0]` separates the first from the second decile, i.e. it is
  # the 10% percentile value. `weight_deciles[i]` is the (i+1)*10-th.
  weight_deciles = statistics.quantiles(_iter_weights(fuzzer_jobs), n=10)  # pylint: disable=no-member
  weight_median = weight_deciles[4]
  weight_90p = weight_deciles[8]

  prob_median = weight_median / total_weight
  prob_90p = weight_90p / total_weight

  print(f'  Median weight: {weight_median}')
  print(f'  Median probability: {_display_prob(prob_median)}')
  print(f'  90th percentile weight: {weight_90p}')
  print(f'  90th percentile probability: {_display_prob(prob_90p)}')


def _aggregate_fuzzer_jobs(
    platform: str,
    fuzzers: Optional[Sequence[str]] = None,
    jobs: Optional[Sequence[str]] = None,
) -> None:
  """Aggregates statistics for matching and non-matching FuzzerJob entries."""
  fuzzer_jobs = list(_query_fuzzer_jobs(platforms=[platform]))
  total_weight = _sum_weights(fuzzer_jobs)

  matches = []
  others = []
  for fuzzer_job in fuzzer_jobs:
    if _fuzzer_job_matches(fuzzer_job, fuzzers, jobs):
      matches.append(fuzzer_job)
    else:
      others.append(fuzzer_job)

  print('Matching FuzzerJob entries:')
  _print_stats(matches, total_weight)
  print('Other FuzzerJob entries:')
  _print_stats(others, total_weight)


def execute(args) -> None:
  """Entrypoint from butler.py."""
  os.environ['CONFIG_DIR_OVERRIDE'] = args.config_dir
  local_config.ProjectConfig().set_environment()

  with ndb_init.context():
    cmd = args.weights_command
    if cmd == 'platforms':
      list_platforms()
    elif cmd == 'dump':
      _dump_entries(EntryType(args.type))
    elif cmd == 'list':
      _list_fuzzer_jobs(
          _query_fuzzer_jobs(
              platforms=args.platforms, fuzzers=args.fuzzers, jobs=args.jobs))
    elif cmd == 'aggregate':
      _aggregate_fuzzer_jobs(
          args.platform, fuzzers=args.fuzzers, jobs=args.jobs)
    else:
      raise TypeError(f'weights command {repr(cmd)} unrecognized')
