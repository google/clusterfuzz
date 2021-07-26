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
"""Manage automatic weight adjustments."""

import collections
import datetime

from google.cloud import ndb
import six

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import ndb_utils
from clusterfuzz._internal.google_cloud_utils import big_query
from clusterfuzz._internal.metrics import fuzzer_stats
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment
from handlers import base_handler
from libs import handler

QuerySpecification = collections.namedtuple(
    'QuerySpecification', ['query_format', 'formatter', 'reason'])

SpecificationMatch = collections.namedtuple('SpecificationMatch',
                                            ['new_weight', 'reason'])

DEFAULT_MULTIPLIER = 30.0  # Used for blackbox and jobs that are not yet run.
DEFAULT_SANITIZER_WEIGHT = 0.1
DEFAULT_ENGINE_WEIGHT = 1.0
TARGET_COUNT_WEIGHT_CAP = 100.0

SANITIZER_BASE_WEIGHT = 0.1

# TODO(ochang): architecture weights.
SANITIZER_WEIGHTS = {
    'ASAN': 5 * SANITIZER_BASE_WEIGHT,
    'CFI': 1 * SANITIZER_BASE_WEIGHT,
    'MSAN': 2 * SANITIZER_BASE_WEIGHT,
    'TSAN': 1 * SANITIZER_BASE_WEIGHT,
    'UBSAN': 1 * SANITIZER_BASE_WEIGHT,
}

ENGINE_WEIGHTS = {
    'libFuzzer': 1.0,
    'afl': 1.0,
    'honggfuzz': 0.2,
}


# Formatters for query specifications.
def _past_day_formatter(query_format, dataset):
  """Simple formatter to get stats for the past day."""
  end_time = utils.utcnow().date()
  start_time = end_time - datetime.timedelta(days=1)
  return query_format.format(
      dataset=dataset, start_time=start_time, end_time=end_time)


def _new_fuzzer_formatter(query_format, dataset):
  """Prepare a query to check for new fuzzers from the past week."""
  now = utils.utcnow().date()
  cutoff_time = now - datetime.timedelta(days=7)
  return query_format.format(dataset=dataset, cutoff_time=cutoff_time)


def _coverage_formatter(query_format, dataset):
  """Prepare a query to check for changes in coverage week over week."""
  end_date = utils.utcnow().date() - datetime.timedelta(days=1)
  middle_date = end_date - datetime.timedelta(days=7)
  start_date = end_date - datetime.timedelta(days=14)
  return query_format.format(
      dataset=dataset,
      start_date=start_date,
      middle_date=middle_date,
      end_date=end_date)


# Most of our queries should simply average a field name to get a ratio showing
# how often some behavior occurs.
GENERIC_QUERY_FORMAT = """
SELECT
  fuzzer,
  job,
  1.0 - (1.0 - {min_weight}) * AVG({field_name}) AS new_weight
FROM
  {{dataset}}.TestcaseRun
WHERE
  _PARTITIONTIME BETWEEN TIMESTAMP('{{start_time}}')
  AND TIMESTAMP('{{end_time}}')
GROUP BY
  fuzzer,
  job
"""

# Heavily reduce the weight for fuzzers which frequently crash on startup. This
# is indicitave of a very serious problem that makes it highly unlikely that
# we'll find anything during fuzzing.
STARTUP_CRASH_SPECIFICATION = QuerySpecification(
    query_format=GENERIC_QUERY_FORMAT.format(
        field_name='startup_crash_count', min_weight=0.10),
    formatter=_past_day_formatter,
    reason='frequent startup crashes')

# Reduce weight somewhat for fuzzers with many slow units. If a particular unit
# runs for so long that we detect it as a slow unit, it usually means that the
# fuzzer is not making good use of its cycles while running or needs a fix.
SLOW_UNIT_SPECIFICATION = QuerySpecification(
    query_format=GENERIC_QUERY_FORMAT.format(
        field_name='slow_unit_count', min_weight=0.25),
    formatter=_past_day_formatter,
    reason='frequent slow units')

# This should end up being very similar to the slow unit specification, and is
# included for the same reason.
TIMEOUT_SPECIFICATION = QuerySpecification(
    query_format=GENERIC_QUERY_FORMAT.format(
        field_name='timeout_count', min_weight=0.25),
    formatter=_past_day_formatter,
    reason='frequent timeouts')

# Fuzzers with extremely frequent OOMs may contain leaks or other issues that
# signal that they need some improvement. Run with a slightly reduced weight
# until the issues are fixed.
OOM_SPECIFICATION = QuerySpecification(
    query_format=GENERIC_QUERY_FORMAT.format(
        field_name='oom_count', min_weight=0.25),
    formatter=_past_day_formatter,
    reason='frequent OOMs')

# Fuzzers which are crashing frequently may not be making full use of their
# allotted time for fuzzing, and may end up being more effective once the known
# issues are fixed. This rule is more lenient than some of the others as even
# healthy fuzzers are expected to have some crashes.
CRASH_SPECIFICATION = QuerySpecification(
    query_format=GENERIC_QUERY_FORMAT.format(
        field_name='crash_count', min_weight=0.50),
    formatter=_past_day_formatter,
    reason='frequent crashes')

# New fuzzers/jobs should run much more frequently than others. In this case, we
# test the fraction of days for which we have no stats for this fuzzer/job pair
# and increase if it's nonzero.
NEW_FUZZER_FORMAT = """
SELECT
  fuzzer,
  job,
  5.0 as new_weight,
  MIN(_PARTITIONTIME) as first_time
FROM
  {dataset}.TestcaseRun
GROUP BY
  fuzzer,
  job
HAVING
  first_time >= TIMESTAMP('{cutoff_time}')
"""

NEW_FUZZER_SPECIFICATION = QuerySpecification(
    query_format=NEW_FUZZER_FORMAT,
    formatter=_new_fuzzer_formatter,
    reason='new fuzzer')

# Format to query for fuzzers with minimal change in week to week coverage.
COVERAGE_UNCHANGED_FORMAT = """
SELECT
  recent.fuzzer AS fuzzer,
  recent.job AS job,
  0.75 as new_weight
FROM (
  SELECT
    fuzzer,
    job,
    MAX(edge_coverage / edges_total) AS coverage
  FROM
    {dataset}.TestcaseRun
  WHERE
    _PARTITIONTIME BETWEEN TIMESTAMP('{middle_date}')
    AND TIMESTAMP('{end_date}')
    AND edges_total > 0
    AND edge_coverage > 0
  GROUP BY
    fuzzer,
    job
  HAVING
    coverage <= 1.0) AS recent
JOIN (
  SELECT
    fuzzer,
    job,
    MAX(edge_coverage / edges_total) AS coverage
  FROM
    {dataset}.TestcaseRun
  WHERE
    _PARTITIONTIME BETWEEN TIMESTAMP('{start_date}')
    AND TIMESTAMP('{middle_date}')
    AND edges_total > 0
    AND edge_coverage > 0
  GROUP BY
    fuzzer,
    job
  HAVING
    coverage <= 1.0) AS older
ON
  recent.fuzzer = older.fuzzer
  AND recent.job = older.job
WHERE
  ABS((recent.coverage - older.coverage) / recent.coverage) < 0.01
"""

COVERAGE_UNCHANGED_SPECIFICATION = QuerySpecification(
    query_format=COVERAGE_UNCHANGED_FORMAT,
    formatter=_coverage_formatter,
    reason='coverage flat over past 2 weeks')

# Mappings for which specifications to use for which
LIBFUZZER_SPECIFICATIONS = [
    COVERAGE_UNCHANGED_SPECIFICATION,
    CRASH_SPECIFICATION,
    NEW_FUZZER_SPECIFICATION,
    OOM_SPECIFICATION,
    SLOW_UNIT_SPECIFICATION,
    STARTUP_CRASH_SPECIFICATION,
    TIMEOUT_SPECIFICATION,
]

AFL_SPECIFICATIONS = [
    CRASH_SPECIFICATION,
    NEW_FUZZER_SPECIFICATION,
    STARTUP_CRASH_SPECIFICATION,
]

RESTORE_DEFAULT_MATCH = SpecificationMatch(
    new_weight=1.0, reason='no longer matches any weight adjustment rules')


def _query_helper(client, query):
  """Helper function to get fuzzer stats."""
  return client.query(query=query).rows


def _update_match(matches, fuzzer, job, match):
  """Update the weight for a fuzzer/job."""
  key = (fuzzer, job)
  old_match = matches.get(key, RESTORE_DEFAULT_MATCH)

  new_weight = match.new_weight
  old_weight = old_match.new_weight

  # Rules that increase weights are expected to take precedence over any that
  # lower the weight. Issues with new fuzzers may be fixed intraday and other
  # issues like crashes shouldn't be penalized for them.
  if old_weight > 1.0:
    return

  # Always update the weight if the previous value is the default. This is
  # required to deal with specifications that are meant to set the weight above
  # 1.0. Otherwise, prioritize only the most penalizing match for this pairing.
  if old_match == RESTORE_DEFAULT_MATCH or new_weight < old_weight:
    matches[key] = match


def update_weight_for_target(fuzz_target_name, job, match):
  """Set the weight for a particular target."""
  target_job = data_handler.get_fuzz_target_job(fuzz_target_name, job)

  if not target_job:
    # Bail out. This is expected if any fuzzer/job combinations become outdated.
    return

  weight = match.new_weight
  logs.log('Adjusted weight to %f for target %s and job %s (%s).' %
           (weight, fuzz_target_name, job, match.reason))

  target_job.weight = weight
  target_job.put()


def update_matches_for_specification(specification, client, engine, matches,
                                     run_set):
  """Run a query and adjust weights based on a given query specification."""
  query = specification.formatter(specification.query_format,
                                  fuzzer_stats.dataset_name(engine))
  results = _query_helper(client, query)
  for result in results:
    fuzzer = result['fuzzer']
    job = result['job']
    new_weight = result['new_weight']

    if new_weight is None:
      continue

    run_set.add((fuzzer, job))
    if new_weight != 1.0:
      match = SpecificationMatch(
          new_weight=new_weight, reason=specification.reason)
      _update_match(matches, fuzzer, job, match)


def update_target_weights_for_engine(client, engine, specifications):
  """Update all fuzz target weights for the specified engine."""
  matches = {}
  run_set = set()

  # All fuzzers with non-default weights must be tracked with a special
  # specification. This ensures that they will be restored to normal weight
  # once conditions causing adjustments are no longer met.
  target_jobs = data_types.FuzzTargetJob.query(
      data_types.FuzzTarget.engine == engine).filter(
          data_types.FuzzTargetJob.weight != 1.0)

  for target_job in target_jobs:
    matches[(target_job.fuzz_target_name,
             target_job.job)] = RESTORE_DEFAULT_MATCH

  for match in specifications:
    update_matches_for_specification(match, client, engine, matches, run_set)

  for (fuzzer, job), match in six.iteritems(matches):
    if (fuzzer, job) not in run_set:
      # This ensures that we don't reset weights for fuzzers with problems if
      # they didn't run in the time covered by our queries.
      continue

    update_weight_for_target(fuzzer, job, match)

  logs.log('Weight adjustments complete for engine %s.' % engine)


def store_current_weights_in_bigquery():
  """Update a bigquery table containing the daily stats."""
  rows = []
  target_jobs = ndb_utils.get_all_from_model(data_types.FuzzTargetJob)
  for target_job in target_jobs:
    row = {
        'fuzzer': target_job.fuzz_target_name,
        'job': target_job.job,
        'weight': target_job.weight
    }
    rows.append(big_query.Insert(row=row, insert_id=None))

  client = big_query.Client(dataset_id='main', table_id='fuzzer_weights')
  client.insert(rows)


def update_job_weight(job_name, multiplier):
  """Update a job weight."""
  tool_name = environment.get_memory_tool_name(job_name)
  multiplier *= SANITIZER_WEIGHTS.get(tool_name, DEFAULT_SANITIZER_WEIGHT)

  engine = environment.get_engine_for_job(job_name)
  multiplier *= ENGINE_WEIGHTS.get(engine, DEFAULT_ENGINE_WEIGHT)

  query = data_types.FuzzerJob.query(data_types.FuzzerJob.job == job_name)
  changed_weights = []
  for fuzzer_job in query:
    if fuzzer_job.multiplier != multiplier:
      fuzzer_job.multiplier = multiplier
      changed_weights.append(fuzzer_job)

  if changed_weights:
    ndb_utils.put_multi(changed_weights)


def update_job_weights():
  """Update job weights."""
  for job in data_types.Job.query():
    multiplier = DEFAULT_MULTIPLIER
    if environment.is_engine_fuzzer_job(job.name):
      targets_count = ndb.Key(data_types.FuzzTargetsCount, job.name).get()
      # If the count is 0, it may be due to a bad build or some other issue. Use
      # the default weight in that case to allow for recovery.
      if targets_count and targets_count.count:
        multiplier = targets_count.count
        multiplier = min(multiplier, TARGET_COUNT_WEIGHT_CAP)

    update_job_weight(job.name, multiplier)


class Handler(base_handler.Handler):
  """Handler to periodically update fuzz target weights based on performance."""

  @handler.cron()
  def get(self):
    """Process all fuzz targets and update FuzzTargetJob weights."""
    client = big_query.Client()
    update_target_weights_for_engine(client, 'libFuzzer',
                                     LIBFUZZER_SPECIFICATIONS)
    update_target_weights_for_engine(client, 'afl', AFL_SPECIFICATIONS)
    update_job_weights()

    store_current_weights_in_bigquery()
