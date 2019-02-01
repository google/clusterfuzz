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

from base import utils
from datastore import data_handler
from datastore import data_types
from google_cloud_utils import big_query
from handlers import base_handler
from libs import handler
from metrics import fuzzer_stats
from metrics import logs
from metrics import monitoring_metrics

QuerySpecification = collections.namedtuple(
    'QuerySpecification',
    ['adjusted_weight', 'threshold', 'query_format', 'formatter', 'reason'])


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
  AVG({field_name}) AS ratio
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
    adjusted_weight=0.10,
    threshold=0.80,
    query_format=GENERIC_QUERY_FORMAT.format(field_name='startup_crash_count'),
    formatter=_past_day_formatter,
    reason='frequent startup crashes')

# Reduce weight somewhat for fuzzers with many slow units. If a particular unit
# runs for so long that we detect it as a slow unit, it usually means that the
# fuzzer is not making good use of its cycles while running or needs a fix.
SLOW_UNIT_SPECIFICATION = QuerySpecification(
    adjusted_weight=0.50,
    threshold=0.80,
    query_format=GENERIC_QUERY_FORMAT.format(field_name='slow_unit_count'),
    formatter=_past_day_formatter,
    reason='frequent slow units')

# This should end up being very similar to the slow unit specification, and is
# included for the same reason.
TIMEOUT_SPECIFICATION = QuerySpecification(
    adjusted_weight=0.50,
    threshold=0.80,
    query_format=GENERIC_QUERY_FORMAT.format(field_name='timeout_count'),
    formatter=_past_day_formatter,
    reason='frequent timeouts')

# Fuzzers which are crashing frequently may not be making full use of their
# allotted time for fuzzing, and may end up being more effective once the known
# issues are fixed.
CRASH_SPECIFICATION = QuerySpecification(
    adjusted_weight=0.50,
    threshold=0.90,
    query_format=GENERIC_QUERY_FORMAT.format(field_name='crash_count'),
    formatter=_past_day_formatter,
    reason='frequent crashes')

# Fuzzers with extremely frequent OOMs may contain leaks or other issues that
# signal that they need some improvement. Run with a slightly reduced weight
# until the issues are fixed.
OOM_SPECIFICATION = QuerySpecification(
    adjusted_weight=0.50,
    threshold=0.90,
    query_format=GENERIC_QUERY_FORMAT.format(field_name='oom_count'),
    formatter=_past_day_formatter,
    reason='frequent OOMs')

# New fuzzers/jobs should run much more frequently than others. In this case, we
# test the fraction of days for which we have no stats for this fuzzer/job pair
# and increase if it's nonzero.
NEW_FUZZER_FORMAT = """
SELECT
  fuzzer,
  job,
  1 as ratio,
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
    adjusted_weight=5.0,
    threshold=1.0,
    query_format=NEW_FUZZER_FORMAT,
    formatter=_new_fuzzer_formatter,
    reason='new fuzzer')

# Format to query for fuzzers with minimal change in week to week coverage.
COVERAGE_UNCHANGED_FORMAT = """
SELECT
  recent.fuzzer AS fuzzer,
  recent.job AS job,
  1 as ratio
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
    adjusted_weight=0.5,
    threshold=1.0,
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

# Special specification used to modify previously altered weights to their
# default values when they no longer match any other specifications.
RESTORE_DEFAULT_SPECIFICATION = QuerySpecification(
    adjusted_weight=1.0,
    threshold=None,
    query_format=None,
    formatter=None,
    reason='no longer matches any weight adjustment specifications')


def _query_helper(client, query):
  """Helper function to get fuzzer stats."""
  return client.query(query=query).rows


def _update_match(matched_specifications, fuzzer, job, specification):
  """Update the weight for a fuzzer/job."""
  key = (fuzzer, job)
  old_match = matched_specifications.get(key, RESTORE_DEFAULT_SPECIFICATION)

  new_weight = specification.adjusted_weight
  old_weight = old_match.adjusted_weight

  # Always update the weight if the previous value is the default. This is
  # required to deal with specifications that are meant to set the weight above
  # 1.0. Otherwise, prioritize only the most penalizing match for this pairing.
  if old_match == RESTORE_DEFAULT_SPECIFICATION or new_weight < old_weight:
    matched_specifications[key] = specification


def update_weight_for_target(fuzz_target_name, job, specification):
  """Set the weight for a paritcular target."""
  target_job = data_handler.get_fuzz_target_job(fuzz_target_name, job)

  if not target_job:
    logs.log_error('FuzzTargetJob for target %s and job %s does not exist.' %
                   (fuzz_target_name, job))
    return

  weight = specification.adjusted_weight
  logs.log('Adjusted weight to %f for target %s and job %s (%s).' %
           (weight, fuzz_target_name, job, specification.reason))
  monitoring_metrics.WEIGHT_ADJUSTMENT.increment({
      'reason': specification.reason
  })
  target_job.weight = weight
  target_job.put()


def update_matches_for_specification(specification, client, engine,
                                     matched_specifications, run_set):
  """Run a query and adjust weights based on a given query specification."""
  query = specification.formatter(specification.query_format,
                                  fuzzer_stats.dataset_name(engine))
  results = _query_helper(client, query)
  for result in results:
    fuzzer = result['fuzzer']
    job = result['job']
    ratio = result['ratio']

    run_set.add((fuzzer, job))
    if ratio >= specification.threshold:
      _update_match(matched_specifications, fuzzer, job, specification)


def update_target_weights_for_engine(client, engine, specifications):
  """Update all fuzz target weights for the specified engine."""
  matched_specifications = {}
  run_set = set()

  # All fuzzers with non-default weights must be tracked with a special
  # specification. This ensures that they will be restored to normal weight
  # once conditions causing adjustments are no longer met.
  target_jobs = data_types.FuzzTargetJob.query(
      data_types.FuzzTarget.engine == engine).filter(
          data_types.FuzzTargetJob.weight != 1.0)

  for target_job in target_jobs:
    matched_specifications[(target_job.fuzz_target_name,
                            target_job.job)] = RESTORE_DEFAULT_SPECIFICATION

  for specification in specifications:
    update_matches_for_specification(specification, client, engine,
                                     matched_specifications, run_set)

  for (fuzzer, job), specification in matched_specifications.iteritems():
    if (fuzzer, job) not in run_set:
      # This ensures that we don't reset weights for fuzzers with problems if
      # they didn't run in the time covered by our queries.
      continue

    update_weight_for_target(fuzzer, job, specification)

  logs.log('Weight adjustments complete for engine %s.' % engine)


class Handler(base_handler.Handler):
  """Handler to periodically update fuzz target weights based on performance."""

  @handler.check_cron()
  def get(self):
    """Process all fuzz targets and update FuzzTargetJob weights."""
    client = big_query.Client()
    update_target_weights_for_engine(client, 'libFuzzer',
                                     LIBFUZZER_SPECIFICATIONS)
    update_target_weights_for_engine(client, 'afl', AFL_SPECIFICATIONS)
