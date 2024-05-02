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
"""Script to interact with fuzzer weights in the database.

Usage:

  python butler.py weights --help

"""

import csv
import os
import statistics
import sys
from typing import Callable
from typing import Dict
from typing import List
from typing import Optional
from typing import Sequence
from typing import Union

from google.cloud import ndb

from src.clusterfuzz._internal.config import local_config
from src.clusterfuzz._internal.datastore import data_types
from src.clusterfuzz._internal.datastore import ndb_init


def _iter_weights(
    fuzzer_jobs: Sequence[data_types.FuzzerJob]) -> Sequence[float]:
  for fj in fuzzer_jobs:
    yield fj.actual_weight


def _sum_weights(fuzzer_jobs: Sequence[data_types.FuzzerJob]) -> float:
  return sum(_iter_weights(fuzzer_jobs))


def _display_prob(probability: float) -> str:
  return f'{probability:0.04f} = {probability * 100:0.02f}%'


def _display_platforms() -> None:
  # Query only distinct platform values from the database.
  fuzzer_jobs = data_types.FuzzerJob.query(
      projection=[data_types.FuzzerJob.platform], distinct=True)
  for fuzzer_job in fuzzer_jobs:
    print(fuzzer_job.platform)


def _query_fuzzer_jobs_batches(platforms: Optional[Sequence[str]] = None
                              ) -> Sequence[data_types.FuzzerJobs]:
  query = data_types.FuzzerJobs.query()

  if platforms:
    query = query.filter(
        data_types.FuzzerJobs.platform.IN([p.upper() for p in platforms]))

  return query


def _query_fuzzer_jobs(
    platforms: Optional[Sequence[str]] = None,
    fuzzers: Optional[Sequence[str]] = None,
    jobs: Optional[Sequence[str]] = None,
) -> Sequence[data_types.FuzzerJob]:
  """Queries Datastore for matching FuzzerJob entries."""
  query = data_types.FuzzerJob.query()

  if platforms:
    query = query.filter(
        data_types.FuzzerJob.platform.IN([p.upper() for p in platforms]))
  if fuzzers:
    query = query.filter(data_types.FuzzerJob.fuzzer.IN(fuzzers))
  if jobs:
    query = query.filter(data_types.FuzzerJob.job.IN(jobs))

  return query


def _query_fuzz_target_jobs(
    targets: Optional[Sequence[str]] = None,
    jobs: Optional[Sequence[str]] = None,
    engines: Optional[Sequence[str]] = None,
) -> Sequence[data_types.FuzzTargetJob]:
  """Queries Datastore for matching FuzzTargetJob entries."""
  query = data_types.FuzzTargetJob.query()

  if targets:
    query = query.filter(data_types.FuzzTargetJob.fuzz_target_name.IN(targets))
  if jobs:
    query = query.filter(data_types.FuzzTargetJob.job.IN(jobs))
  if engines:
    query = query.filter(data_types.FuzzTargetJob.engine.IN(engines))

  return query


def _print_with_prefix(prefix: str) -> Callable[[str], None]:
  if not prefix:
    return print

  def _print(s: str) -> None:
    print(prefix + s)

  return _print


def _display_fuzzer_jobs(fuzzer_jobs: Sequence[data_types.FuzzerJob],
                         prefix='') -> None:
  """Lists the given FuzzerJob entries on stdout."""
  printer = _print_with_prefix(prefix)

  fuzzer_jobs = list(fuzzer_jobs)
  fuzzer_jobs.sort(key=lambda fj: fj.actual_weight, reverse=True)

  total_weight = _sum_weights(fuzzer_jobs)

  for fuzzer_job in fuzzer_jobs:
    probability = fuzzer_job.actual_weight / total_weight

    printer('FuzzerJob:')
    printer(f'  Fuzzer: {fuzzer_job.fuzzer}')
    printer(f'  Job: {fuzzer_job.job}')
    printer(f'  Platform: {fuzzer_job.platform}')
    printer(f'  Weight: {fuzzer_job.actual_weight} = ' +
            f'{fuzzer_job.weight} * {fuzzer_job.multiplier}')
    printer(f'  Probability: {_display_prob(probability)}')

  printer(f'Count: {len(fuzzer_jobs)}')
  printer(f'Total weight: {total_weight}')


def _display_fuzzer_jobs_batches(
    batches: Sequence[data_types.FuzzerJobs]) -> None:
  """Lists the given FuzzerJobs entries on stdout."""
  count = 0
  for batch in batches:
    count += 1

    print('FuzzerJobs:')
    print(f'  ID: {batch.key.id()}')
    print(f'  Platform: {batch.platform}')
    _display_fuzzer_jobs(batch.fuzzer_jobs, prefix='  ')

  print(f'Count: {count}')


def _display_fuzz_target_jobs(
    fuzz_target_jobs: Sequence[data_types.FuzzTargetJob]) -> None:
  """Lists the given FuzzTargetJob entries on stdout."""
  fuzz_target_jobs = list(fuzz_target_jobs)
  fuzz_target_jobs.sort(key=lambda ftj: ftj.weight, reverse=True)

  total_weight = sum(ftj.weight for ftj in fuzz_target_jobs)

  for ftj in fuzz_target_jobs:
    probability = ftj.weight / total_weight

    print('FuzzTargetJob:')
    print(f'  Fuzz target name: {ftj.fuzz_target_name}')
    print(f'  Job: {ftj.job}')
    print(f'  Engine: {ftj.engine}')
    print(f'  Weight: {ftj.weight}')
    print(f'  Relative probability: {_display_prob(probability)}')
    print(f'  Last run: {ftj.last_run}')

  print(f'Count: {len(fuzz_target_jobs)}')
  print(f'Total weight: {total_weight}')


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


def _dump_fuzzer_jobs(fuzzer_jobs: Sequence[data_types.FuzzerJob]) -> None:
  """Dumps the provided FuzzerJob entries to stdout in CSV format."""
  writer = csv.DictWriter(sys.stdout, fieldnames=_FUZZER_JOB_FIELDS)
  writer.writeheader()

  for fuzzer_job in fuzzer_jobs:
    writer.writerow(_fuzzer_job_to_dict(fuzzer_job))


def _dump_fuzzer_jobs_batches(batches: Sequence[data_types.FuzzerJobs]) -> None:
  """Dumps the provided FuzzerJobs entries to stdout in CSV format."""
  writer = csv.DictWriter(sys.stdout, fieldnames=['batch'] + _FUZZER_JOB_FIELDS)
  writer.writeheader()

  for batch in batches:
    for fuzzer_job in batch.fuzzer_jobs:
      fields = _fuzzer_job_to_dict(fuzzer_job)
      fields['batch'] = batch.key.id()
      writer.writerow(fields)


def _dump_fuzz_target_jobs(
    fuzz_target_jobs: Sequence[data_types.FuzzTargetJob]) -> None:
  """Dumps the provided FuzzTargetJob entries to stdout in CSV format."""
  writer = csv.DictWriter(
      sys.stdout,
      fieldnames=[
          'fuzz_target_name',
          'job',
          'engine',
          'weight',
          'last_run',
      ])
  writer.writeheader()

  for entry in fuzz_target_jobs:
    writer.writerow({
        'fuzz_target_name': entry.fuzz_target_name,
        'job': entry.job,
        'engine': entry.engine,
        'weight': entry.weight,
        'last_run': entry.last_run,
    })


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
  if len(fuzzer_jobs) < 2 or not hasattr(statistics, 'quantiles'):
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
  fuzzer_jobs = list(_query_fuzzer_jobs(platforms=[platform.upper()]))
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


def _set_fuzz_target_job_weight(
    fuzz_target_name: str,
    job: str,
    weight: float,
) -> None:
  """Sets the matching FuzzTargetJob's weight to the given value."""
  key = ndb.Key(data_types.FuzzTargetJob,
                data_types.fuzz_target_job_key(fuzz_target_name, job))
  ftj = key.get()
  if ftj is None:
    print(f'No FuzzTargetJob entry found for key {key.id()}.')
    return

  print(f'Fuzz target name: {ftj.fuzz_target_name}')
  print(f'Job: {ftj.job}')
  print(f'Engine: {ftj.engine}')
  print(f'Last run: {ftj.last_run}')
  print(f'Old weight: {ftj.weight}')
  print(f'-> New weight: {weight}')

  answer = input('Do you want to apply this mutation? [y,n] ')
  if answer.lower() != 'y':
    print('Not applying mutation.')
    return

  ftj.weight = weight
  ftj.put()
  print('Mutation applied.')


def _execute_fuzzer_command(args) -> None:
  """Executes the `fuzzer` command."""
  cmd = args.fuzzer_command
  if cmd == 'platforms':
    _display_platforms()
  elif cmd == 'list':
    fuzzer_jobs = _query_fuzzer_jobs(
        platforms=args.platforms, fuzzers=args.fuzzers, jobs=args.jobs)
    if args.format == 'text':
      _display_fuzzer_jobs(fuzzer_jobs)
    elif args.format == 'csv':
      _dump_fuzzer_jobs(fuzzer_jobs)
    else:
      raise TypeError(f'--format {repr(args.format)} unrecognized')
  elif cmd == 'aggregate':
    _aggregate_fuzzer_jobs(args.platform, fuzzers=args.fuzzers, jobs=args.jobs)
  else:
    raise TypeError(f'weights fuzzer command {repr(cmd)} unrecognized')


def _execute_fuzzer_batch_command(args) -> None:
  """Executes the `fuzzer-batch` command."""
  cmd = args.fuzzer_batch_command
  if cmd == 'list':
    batches = _query_fuzzer_jobs_batches(platforms=args.platforms)
    if args.format == 'text':
      _display_fuzzer_jobs_batches(batches)
    elif args.format == 'csv':
      _dump_fuzzer_jobs_batches(batches)
    else:
      raise TypeError(f'--format {repr(args.format)} unrecognized')
  else:
    raise TypeError(f'weights fuzzer-batch command {repr(cmd)} unrecognized')


def _execute_fuzz_target_command(args) -> None:
  """Executes the `fuzz-target` command."""
  cmd = args.fuzz_target_command
  if cmd == 'list':
    fuzz_target_jobs = _query_fuzz_target_jobs(
        targets=args.targets, jobs=args.jobs, engines=args.engines)
    if args.format == 'text':
      _display_fuzz_target_jobs(fuzz_target_jobs)
    elif args.format == 'csv':
      _dump_fuzz_target_jobs(fuzz_target_jobs)
    else:
      raise TypeError(f'--format {repr(args.format)} unrecognized')
  elif cmd == 'set':
    _set_fuzz_target_job_weight(args.target, args.job, args.weight)
  else:
    raise TypeError(f'weights fuzz-target command {repr(cmd)} unrecognized')


def _execute_command(args) -> None:
  """Executes the `weights` command."""
  cmd = args.weights_command
  if cmd == 'fuzzer':
    _execute_fuzzer_command(args)
  elif cmd == 'fuzzer-batch':
    _execute_fuzzer_batch_command(args)
  elif cmd == 'fuzz-target':
    _execute_fuzz_target_command(args)
  else:
    raise TypeError(f'weights command {repr(cmd)} unrecognized')


def execute(args) -> None:
  """Entrypoint from butler.py."""
  os.environ['CONFIG_DIR_OVERRIDE'] = args.config_dir
  local_config.ProjectConfig().set_environment()

  with ndb_init.context():
    _execute_command(args)
