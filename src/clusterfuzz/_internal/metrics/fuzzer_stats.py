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
"""Classes for dealing with FuzzerStats."""

import datetime
import functools
import itertools
import json
import os
import random
import re

from clusterfuzz._internal.base import memoize
from clusterfuzz._internal.base import utils
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import fuzz_target_utils
from clusterfuzz._internal.google_cloud_utils import big_query
from clusterfuzz._internal.google_cloud_utils import storage
from clusterfuzz._internal.metrics import fuzzer_logs
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.system import shell

STATS_FILE_EXTENSION = '.stats2'

PERFORMANCE_REPORT_VIEWER_PATH = '/performance-report/{fuzzer}/{job}/{date}'

JOB_RUN_SCHEMA = {
    'fields': [{
        'name': 'testcases_executed',
        'type': 'INTEGER',
        'mode': 'NULLABLE'
    }, {
        'name': 'build_revision',
        'type': 'INTEGER',
        'mode': 'NULLABLE'
    }, {
        'name': 'new_crashes',
        'type': 'INTEGER',
        'mode': 'NULLABLE'
    }, {
        'name': 'job',
        'type': 'STRING',
        'mode': 'NULLABLE'
    }, {
        'name': 'timestamp',
        'type': 'FLOAT',
        'mode': 'NULLABLE'
    }, {
        'name':
            'crashes',
        'type':
            'RECORD',
        'mode':
            'REPEATED',
        'fields': [{
            'name': 'crash_type',
            'type': 'STRING',
            'mode': 'NULLABLE'
        }, {
            'name': 'is_new',
            'type': 'BOOLEAN',
            'mode': 'NULLABLE'
        }, {
            'name': 'crash_state',
            'type': 'STRING',
            'mode': 'NULLABLE'
        }, {
            'name': 'security_flag',
            'type': 'BOOLEAN',
            'mode': 'NULLABLE'
        }, {
            'name': 'count',
            'type': 'INTEGER',
            'mode': 'NULLABLE'
        }]
    }, {
        'name': 'known_crashes',
        'type': 'INTEGER',
        'mode': 'NULLABLE'
    }, {
        'name': 'fuzzer',
        'type': 'STRING',
        'mode': 'NULLABLE'
    }, {
        'name': 'kind',
        'type': 'STRING',
        'mode': 'NULLABLE'
    }]
}


class FuzzerStatsException(Exception):
  """Fuzzer stats exception."""


class BaseRun(object):
  """Base run."""

  VALID_FIELDNAME_PATTERN = re.compile(r'[a-zA-Z][a-zA-Z0-9_]*')

  def __init__(self, fuzzer, job, build_revision, timestamp):
    self._stats_data = {
        'fuzzer': fuzzer,
        'job': job,
        'build_revision': build_revision,
        'timestamp': timestamp,
    }

  def __getitem__(self, key):
    return self._stats_data.__getitem__(key)

  def __setitem__(self, key, value):
    if not re.compile(self.VALID_FIELDNAME_PATTERN):
      raise ValueError('Invalid key name.')

    return self._stats_data.__setitem__(key, value)

  def __delitem__(self, key):
    return self._stats_data.__delitem__(key)

  def __contains__(self, key):
    return self._stats_data.__contains__(key)

  def to_json(self):
    """Return JSON representation of the stats."""
    return json.dumps(self._stats_data)

  def update(self, other):
    """Update stats with a dict."""
    self._stats_data.update(other)

  @property
  def data(self):
    return self._stats_data

  @property
  def kind(self):
    return self._stats_data['kind']

  @property
  def fuzzer(self):
    return self._stats_data['fuzzer']

  @property
  def job(self):
    return self._stats_data['job']

  @property
  def build_revision(self):
    return self._stats_data['build_revision']

  @property
  def timestamp(self):
    return self._stats_data['timestamp']

  @staticmethod
  def from_json(json_data):
    """Convert json to the run."""
    try:
      data = json.loads(json_data)
    except (ValueError, TypeError):
      return None

    if not isinstance(data, dict):
      return None

    result = None
    try:
      kind = data['kind']
      if kind == 'TestcaseRun':
        result = TestcaseRun(data['fuzzer'], data['job'],
                             data['build_revision'], data['timestamp'])
      elif kind == 'JobRun':
        result = JobRun(data['fuzzer'], data['job'], data['build_revision'],
                        data['timestamp'], data['testcases_executed'],
                        data['new_crashes'], data['known_crashes'],
                        data.get('crashes'))
    except KeyError:
      return None

    if result:
      result.update(data)
    return result


class JobRun(BaseRun):
  """Represents stats for a particular job run."""

  SCHEMA = JOB_RUN_SCHEMA

  # `crashes` is a new field that will replace `new_crashes` and `old_crashes`.
  def __init__(self, fuzzer, job, build_revision, timestamp,
               number_of_testcases, new_crashes, known_crashes, crashes):
    super(JobRun, self).__init__(fuzzer, job, build_revision, timestamp)
    self._stats_data.update({
        'kind': 'JobRun',
        'testcases_executed': number_of_testcases,
        'new_crashes': new_crashes,
        'known_crashes': known_crashes,
        'crashes': crashes
    })


class TestcaseRun(BaseRun):
  """Represents stats for a particular testcase run."""

  SCHEMA = None

  def __init__(self, fuzzer, job, build_revision, timestamp):
    super(TestcaseRun, self).__init__(fuzzer, job, build_revision, timestamp)
    self._stats_data.update({
        'kind': 'TestcaseRun',
    })

    source = environment.get_value('STATS_SOURCE')
    if source:
      self._stats_data['source'] = source

  @staticmethod
  def get_stats_filename(testcase_file_path):
    """Get stats filename for the given testcase."""
    return testcase_file_path + STATS_FILE_EXTENSION

  @staticmethod
  def read_from_disk(testcase_file_path, delete=False):
    """Read the TestcaseRun for the given testcase."""
    stats_file_path = TestcaseRun.get_stats_filename(testcase_file_path)
    if not os.path.exists(stats_file_path):
      return None

    fuzzer_run = None
    with open(stats_file_path) as f:
      fuzzer_run = BaseRun.from_json(f.read())

    if delete:
      shell.remove_file(stats_file_path)

    return fuzzer_run

  @staticmethod
  def write_to_disk(testcase_run, testcase_file_path):
    """Write the given TestcaseRun for |testcase_file_path| to disk."""
    if not testcase_run:
      return

    stats_file_path = TestcaseRun.get_stats_filename(testcase_file_path)
    with open(stats_file_path, 'w') as f:
      f.write(testcase_run.to_json())


class QueryGroupBy(object):
  """GroupBy enum."""

  GROUP_BY_NONE = 0
  GROUP_BY_REVISION = 1
  GROUP_BY_DAY = 2
  GROUP_BY_TIME = 3
  GROUP_BY_JOB = 4
  GROUP_BY_FUZZER = 5


def group_by_to_field_name(group_by):
  """Convert QueryGroupBy value to its corresponding field name."""
  if group_by == QueryGroupBy.GROUP_BY_REVISION:
    return 'build_revision'

  if group_by == QueryGroupBy.GROUP_BY_DAY:
    return 'date'

  if group_by == QueryGroupBy.GROUP_BY_TIME:
    return 'time'

  if group_by == QueryGroupBy.GROUP_BY_JOB:
    return 'job'

  if group_by == QueryGroupBy.GROUP_BY_FUZZER:
    return 'fuzzer'

  return None


class BuiltinFieldData(object):
  """Represents a cell value for a builtin field."""

  def __init__(self, value, sort_key=None, link=None):
    self.value = value
    self.sort_key = sort_key
    self.link = link


class BuiltinFieldSpecifier(object):
  """Represents a builtin field."""

  def __init__(self, name, alias=None):
    self.name = name
    self.alias = alias

  def create(self, ctx=None):
    """Create the actual BuiltinField."""
    constructor = BUILTIN_FIELD_CONSTRUCTORS.get(self.name)
    if not constructor:
      return None

    return constructor(ctx)

  def field_class(self):
    """Return the class for the field."""
    constructor = BUILTIN_FIELD_CONSTRUCTORS.get(self.name)
    if not constructor:
      return None

    if isinstance(constructor, functools.partial):
      return constructor.func

    return constructor


class BuiltinField(object):
  """Base Builtin field."""

  def __init__(self, ctx=None):
    self.ctx = ctx

  def get(self, group_by, group_by_value):  # pylint: disable=unused-argument
    """Return BuiltinFieldData."""
    return None


class BuiltinFieldContext(object):
  """Context for builtin fields."""

  def __init__(self, fuzzer=None, jobs=None):
    self.fuzzer = fuzzer
    self.jobs = jobs

  def single_job_or_none(self):
    """Return the job if only 1 is specified, or None."""
    if self.jobs and len(self.jobs) == 1:
      return self.jobs[0]

    return None


class CoverageFieldContext(BuiltinFieldContext):
  """Coverage field context. Acts as a cache."""

  def __init__(self, fuzzer=None, jobs=None):
    super(CoverageFieldContext, self).__init__(fuzzer=fuzzer, jobs=jobs)

  @memoize.wrap(memoize.FifoInMemory(256))
  def get_coverage_info(self, fuzzer, date=None):
    """Return coverage info of child fuzzers."""
    if fuzzer in data_types.BUILTIN_FUZZERS:
      # Get coverage info for a job (i.e. a project).
      job = self.single_job_or_none()
      project = data_handler.get_project_name(job)
      return get_coverage_info(project, date)

    fuzz_target = data_handler.get_fuzz_target(fuzzer)
    if fuzz_target:
      fuzzer = fuzz_target.project_qualified_name()

    return get_coverage_info(fuzzer, date)


class BaseCoverageField(object):
  """Base builtin field class for coverage related fields."""

  CONTEXT_CLASS = CoverageFieldContext

  def __init__(self, ctx):
    self.ctx = ctx

  def get_coverage_info(self, group_by, group_by_value):
    """Return coverage information."""
    coverage_info = None
    if group_by == QueryGroupBy.GROUP_BY_DAY:
      # Return coverage data for the fuzzer and the day.
      coverage_info = self.ctx.get_coverage_info(self.ctx.fuzzer,
                                                 group_by_value)

    elif group_by == QueryGroupBy.GROUP_BY_FUZZER:
      # Return latest coverage data for each fuzzer.
      coverage_info = self.ctx.get_coverage_info(group_by_value)

    elif group_by == QueryGroupBy.GROUP_BY_JOB:
      # Return the latest coverage data for the fuzzer. Even though we group by
      # job here, coverage information does not differ across jobs. As of now,
      # it only depends on the fuzzer name and the date.
      coverage_info = self.ctx.get_coverage_info(self.ctx.fuzzer)

    return coverage_info


class CoverageField(BaseCoverageField):
  """Coverage field."""

  EDGE = 0
  FUNCTION = 1
  VALUE_TYPE = float

  def __init__(self, coverage_type, ctx=None):
    super(CoverageField, self).__init__(ctx)
    self.coverage_type = coverage_type

  def get(self, group_by, group_by_value):
    """Return data."""
    coverage_info = self.get_coverage_info(group_by, group_by_value)
    if not coverage_info:
      return None

    if self.coverage_type == self.EDGE:
      covered = coverage_info.edges_covered
      total = coverage_info.edges_total
    else:
      covered = coverage_info.functions_covered
      total = coverage_info.functions_total

    if covered is None or total is None:
      return None

    if not total:
      logs.log_error(
          'Invalid coverage info: total equals 0 for "%s".' % self.ctx.fuzzer)
      return BuiltinFieldData('No coverage', sort_key=0.0)

    percentage = 100.0 * float(covered) / total
    display_value = '%.2f%% (%d/%d)' % (percentage, covered, total)
    return BuiltinFieldData(display_value, sort_key=percentage)


class CorpusBackupField(BaseCoverageField):
  """Link to the latest corpus backup archive."""
  VALUE_TYPE = str

  def __init__(self, ctx=None):
    super(CorpusBackupField, self).__init__(ctx)

  def get(self, group_by, group_by_value):
    """Return data."""
    coverage_info = self.get_coverage_info(group_by, group_by_value)
    if not coverage_info:
      return None

    if not coverage_info.corpus_backup_location:
      return None

    # Google Cloud console does not support linking to a specific file, so we
    # link to the directory instead.
    corpus_backup_location = os.path.dirname(
        coverage_info.corpus_backup_location)

    display_value = 'Download'
    return BuiltinFieldData(display_value, link=corpus_backup_location)


class CorpusSizeField(BaseCoverageField):
  """Corpus size field."""

  CORPUS = 0
  QUARANTINE = 1
  VALUE_TYPE = int

  def __init__(self, corpus_type, ctx=None):
    super(CorpusSizeField, self).__init__(ctx)
    self.corpus_type = corpus_type

  def get(self, group_by, group_by_value):
    """Return data."""
    if (self.ctx.fuzzer in data_types.BUILTIN_FUZZERS and
        group_by == QueryGroupBy.GROUP_BY_DAY):
      # Explicitly return None here, as coverage_info below might exist and have
      # default corpus size of 0, which might look confusing on the stats page.
      return None

    coverage_info = self.get_coverage_info(group_by, group_by_value)
    if not coverage_info:
      return None

    if self.corpus_type == self.CORPUS:
      corpus_size_units = coverage_info.corpus_size_units
      corpus_size_bytes = coverage_info.corpus_size_bytes
      corpus_location = coverage_info.corpus_location
    else:
      corpus_size_units = coverage_info.quarantine_size_units
      corpus_size_bytes = coverage_info.quarantine_size_bytes
      corpus_location = coverage_info.quarantine_location

    # If the values aren't specified, return None to show the default '--' text.
    if corpus_size_units is None or corpus_size_bytes is None:
      return None

    display_value = '%d (%s)' % (corpus_size_units,
                                 utils.get_size_string(corpus_size_bytes))

    return BuiltinFieldData(
        display_value, sort_key=corpus_size_units, link=corpus_location)


class CoverageReportField(BaseCoverageField):
  """Coverage report field."""

  VALUE_TYPE = str

  def __init__(self, ctx=None):
    super(CoverageReportField, self).__init__(ctx)

  def get(self, group_by, group_by_value):
    """Return data."""
    coverage_info = self.get_coverage_info(group_by, group_by_value)
    if not coverage_info or not coverage_info.html_report_url:
      return None

    display_value = 'Coverage'
    return BuiltinFieldData(display_value, link=coverage_info.html_report_url)


def _logs_bucket_key_fn(func, args, kwargs):  # pylint: disable=unused-argument
  return 'fuzzer_logs_bucket:' + args[1]


class FuzzerRunLogsContext(BuiltinFieldContext):
  """Fuzzer logs context."""

  MEMCACHE_TTL = 30 * 60

  def __init__(self, fuzzer=None, jobs=None):
    super(FuzzerRunLogsContext, self).__init__(fuzzer=fuzzer, jobs=jobs)

  @memoize.wrap(memoize.FifoInMemory(1024))
  def _get_logs_bucket_from_job(self, job_type):
    """Get logs bucket from job."""
    return data_handler.get_value_from_job_definition_or_environment(
        job_type, 'FUZZ_LOGS_BUCKET')

  @memoize.wrap(memoize.Memcache(MEMCACHE_TTL, key_fn=_logs_bucket_key_fn))
  def _get_logs_bucket_from_fuzzer(self, fuzzer_name):
    """Get logs bucket from fuzzer (child fuzzers only)."""
    jobs = [
        mapping.job for mapping in fuzz_target_utils.get_fuzz_target_jobs(
            fuzz_target_name=fuzzer_name)
    ]
    if not jobs:
      return None

    # Check that the logs bucket is same for all of them.
    bucket = self._get_logs_bucket_from_job(jobs[0])
    if all(bucket == self._get_logs_bucket_from_job(job) for job in jobs[1:]):
      return bucket

    return None

  def get_logs_bucket(self, fuzzer_name=None, job_type=None):
    """Return logs bucket for the job."""
    if job_type:
      return self._get_logs_bucket_from_job(job_type)

    if fuzzer_name:
      return self._get_logs_bucket_from_fuzzer(fuzzer_name)

    return None


class FuzzerRunLogsField(BuiltinField):
  """Fuzzer logs field."""

  CONTEXT_CLASS = FuzzerRunLogsContext
  VALUE_TYPE = str

  def _get_logs_bucket_path(self, group_by, group_by_value):
    """Return logs bucket path."""
    fuzzer = self.ctx.fuzzer
    job = self.ctx.single_job_or_none()
    date = None

    if group_by == QueryGroupBy.GROUP_BY_FUZZER:
      fuzzer = group_by_value
    elif group_by == QueryGroupBy.GROUP_BY_DAY:
      if not fuzzer:
        return None
      if not job:
        # If job isn't specified, we'll ignore the date and show the link to the
        # GCS directory containing all jobs for a given fuzz target, because job
        # name comes before the date in the GCS path.
        date = None
      else:
        date = group_by_value
    elif group_by == QueryGroupBy.GROUP_BY_JOB:
      job = group_by_value
    else:
      return None

    if not fuzzer:
      # Fuzzer always needs to be specified (first component in GCS path).
      return None

    logs_bucket = self.ctx.get_logs_bucket(fuzzer_name=fuzzer, job_type=job)
    if not logs_bucket:
      return None

    return 'gs:/' + fuzzer_logs.get_logs_directory(logs_bucket, fuzzer, job,
                                                   date)

  def get(self, group_by, group_by_value):
    """Return data."""
    logs_path = self._get_logs_bucket_path(group_by, group_by_value)
    if not logs_path:
      return None

    return BuiltinFieldData('Logs', link=logs_path)


class PerformanceReportField(BuiltinField):
  """Performance report field."""

  CONTEXT_CLASS = FuzzerRunLogsContext
  VALUE_TYPE = str

  def _get_performance_report_path(self, group_by, group_by_value):
    """Return performance analysis report path."""
    fuzzer = self.ctx.fuzzer
    job = self.ctx.single_job_or_none()
    date = 'latest'

    if group_by == QueryGroupBy.GROUP_BY_FUZZER:
      fuzzer = group_by_value
    elif group_by == QueryGroupBy.GROUP_BY_JOB:
      job = group_by_value
    elif group_by == QueryGroupBy.GROUP_BY_DAY:
      date = group_by_value
    else:
      return None

    if not fuzzer or not job:
      return None

    return PERFORMANCE_REPORT_VIEWER_PATH.format(
        fuzzer=fuzzer, job=job, date=date)

  def get(self, group_by, group_by_value):
    """Return data."""
    report_path = self._get_performance_report_path(group_by, group_by_value)
    if not report_path:
      return None

    return BuiltinFieldData('Performance', link=report_path)


class QueryField(object):
  """Represents a query field."""

  def __init__(self,
               table_alias,
               field_name,
               aggregate_function,
               select_alias=None):
    self.table_alias = table_alias
    self.name = field_name
    self.aggregate_function = aggregate_function
    self.select_alias = select_alias or field_name

  def is_custom(self):
    """Return true if this field uses complex query. This field won't appear
      in the SELECT's fields automatically. We will need to define how to get
      the data."""
    return (self.aggregate_function and
            self.aggregate_function.lower() == 'custom')

  def __str__(self):
    if self.aggregate_function:
      result = '%s(%s.%s)' % (self.aggregate_function, self.table_alias,
                              self.name)
    else:
      result = '%s.%s' % (self.table_alias, self.name)

    if self.select_alias:
      result += ' as ' + self.select_alias

    return result


class Query(object):
  """Represents a stats query."""

  def _ensure_valid_name(self, name, regex):
    """Ensure that the given name is valid for fuzzer/jobs."""
    if name and not regex.match(name):
      raise FuzzerStatsException('Invalid fuzzer or job name.')

  def __init__(self, fuzzer_name, job_types, query_fields, group_by, date_start,
               date_end, base_table, alias):
    assert group_by is not None

    self._ensure_valid_name(fuzzer_name, data_types.Fuzzer.VALID_NAME_REGEX)

    if job_types:
      for job_type in job_types:
        self._ensure_valid_name(job_type, data_types.Job.VALID_NAME_REGEX)

    self.fuzzer_name = fuzzer_name
    self.job_types = job_types
    self.query_fields = query_fields
    self.group_by = group_by
    self.date_start = date_start
    self.date_end = date_end
    self.base_table = base_table
    self.alias = alias

    self.fuzzer_or_engine_name = get_fuzzer_or_engine_name(fuzzer_name)

  def _group_by_select(self):
    """Return a group by field."""
    if self.group_by == QueryGroupBy.GROUP_BY_DAY:
      return ('TIMESTAMP_TRUNC(TIMESTAMP_SECONDS(CAST('
              'timestamp AS INT64)), DAY, "UTC") as date')

    if self.group_by == QueryGroupBy.GROUP_BY_TIME:
      return 'TIMESTAMP_SECONDS(CAST(timestamp AS INT64)) as time'

    return group_by_to_field_name(self.group_by)

  def _group_by(self):
    """Return the group by part of the query."""
    return group_by_to_field_name(self.group_by)

  def _select_fields(self):
    """Return fields for the query."""
    group_by_select = self._group_by_select()
    fields = [group_by_select] if group_by_select else []

    for field in self.query_fields:
      if field.is_custom():
        continue
      if field.aggregate_function:
        fields.append('%s(%s) as %s' % (field.aggregate_function, field.name,
                                        field.select_alias))
      else:
        fields.append('%s as %s' % (field.name, field.select_alias))

    return ', '.join(fields)

  def _table_name(self):
    """Return the table name for the query."""
    app_id = utils.get_application_id()

    dataset = dataset_name(self.fuzzer_or_engine_name)

    return '`%s`.%s.%s' % (app_id, dataset, self.base_table)

  def _where(self):
    """Return the where part of the query."""
    result = []
    result.extend(self._partition_selector())
    result.extend(self._job_and_fuzzer_selector())

    result = ' AND '.join(result)
    if result:
      return 'WHERE ' + result

    return ''

  def _job_and_fuzzer_selector(self):
    """Return the job filter condition."""
    result = []
    if self.job_types:
      result.append('(%s)' % ' OR '.join(
          ['job = \'%s\'' % job_type for job_type in self.job_types]))

    if self.fuzzer_name != self.fuzzer_or_engine_name:
      result.append('fuzzer = \'%s\'' % self.fuzzer_name)

    return result

  def _partition_selector(self):
    """Return the partition filter condition."""
    result = ('(_PARTITIONTIME BETWEEN TIMESTAMP_SECONDS(%d) '
              'AND TIMESTAMP_SECONDS(%d))')

    return [
        result % (int(utils.utc_date_to_timestamp(self.date_start)),
                  int(utils.utc_date_to_timestamp(self.date_end)))
    ]

  def build(self):
    """Return query."""
    query_parts = [
        'SELECT',
        self._select_fields(),
        'FROM',
        self._table_name(),
        self._where(),
    ]

    if self._group_by():
      query_parts += ['GROUP BY', self._group_by()]

    return ' '.join(query_parts)


class TestcaseQuery(Query):
  """The query class for TestcaseRun Query."""

  ALIAS = 't'

  def __init__(self, fuzzer_name, job_types, query_fields, group_by, date_start,
               date_end):
    super(TestcaseQuery, self).__init__(
        fuzzer_name=fuzzer_name,
        job_types=job_types,
        query_fields=query_fields,
        group_by=group_by,
        date_start=date_start,
        date_end=date_end,
        base_table='TestcaseRun',
        alias=TestcaseQuery.ALIAS)


class JobQuery(Query):
  """The query class for JobRun Query."""

  DEFAULT_FIELDS = """
    sum(j.testcases_executed) as testcases_executed,
    custom(j.total_crashes) as total_crashes,
    custom(j.new_crashes) as new_crashes,
    custom(j.known_crashes) as known_crashes
  """
  SQL = """
    WITH
      JobRunWithConcatedCrashes AS (
        SELECT
          {select_fields},
          ARRAY_CONCAT_AGG(crashes) AS crashes
        FROM
          {table_name}
        {where}
        GROUP BY
          {group_by}
      ),
      JobRunWithUniqueCrashes AS (
        SELECT
          * EXCEPT(crashes),
          ARRAY(
            SELECT AS STRUCT
              crash.crash_type,
              crash.crash_state,
              crash.security_flag,
              SUM(count) AS count,
              MAX(crash.is_new) AS is_new
            FROM
              UNNEST(crashes) AS crash
            GROUP BY
              crash.crash_type,
              crash.crash_state,
              crash.security_flag
          ) AS crashes
        FROM
          JobRunWithConcatedCrashes
      ),
      JobRunWithSummary AS (
        SELECT
          * EXCEPT(crashes),
          (
            SELECT AS STRUCT
              IFNULL(SUM(crash.count), 0) AS total,
              COUNTIF(crash.is_new) AS unique_new,
              COUNT(crash) AS unique
            FROM
              UNNEST(crashes) AS crash
          ) AS crash_count
        FROM
          JobRunWithUniqueCrashes
      )

    SELECT
      * EXCEPT(crash_count),
      crash_count.total AS total_crashes,
      crash_count.unique_new AS new_crashes,
      (crash_count.unique - crash_count.unique_new) AS known_crashes
    FROM
      JobRunWithSummary
  """
  ALIAS = 'j'

  def __init__(self, fuzzer_name, job_types, query_fields, group_by, date_start,
               date_end):

    super(JobQuery, self).__init__(
        fuzzer_name=fuzzer_name,
        job_types=job_types,
        query_fields=query_fields,
        group_by=group_by,
        date_start=date_start,
        date_end=date_end,
        base_table='JobRun',
        alias=JobQuery.ALIAS)

  def build(self):
    """Return query."""
    sql = JobQuery.SQL.format(
        table_name=self._table_name(),
        select_fields=self._select_fields(),
        group_by=self._group_by(),
        where=self._where())

    return sql


class TableQuery(object):
  """Query for generating results in a table."""

  def __init__(self, fuzzer_name, job_types, stats_columns, group_by,
               date_start, date_end):
    assert group_by

    self.fuzzer_name = fuzzer_name
    self.job_types = job_types
    self.group_by = group_by
    self.date_start = date_start
    self.date_end = date_end
    self.job_run_query = None
    self.testcase_run_query = None

    job_run_fields = []
    testcase_run_fields = []
    fields = parse_stats_column_fields(stats_columns)

    for field in fields:
      # Split up fields by table.
      if not isinstance(field, QueryField):
        continue

      if field.table_alias == JobQuery.ALIAS:
        job_run_fields.append(field)
      elif field.table_alias == TestcaseQuery.ALIAS:
        testcase_run_fields.append(field)

    #  subqueries.

    # For query by time, we can't correlate the time of testcase run with a job
    # run since they are set at different times. So, use only the results from
    # testcase run and don't join them with job run, see build(). Also, the job
    # parameters like: known crashes, new crashes are aggregate numbers from job
    # that are not applicable to show per testcase run (a point on graph).
    if job_run_fields and self.group_by != QueryGroupBy.GROUP_BY_TIME:
      self.job_run_query = JobQuery(fuzzer_name, job_types, job_run_fields,
                                    group_by, date_start, date_end)

    if testcase_run_fields:
      self.testcase_run_query = TestcaseQuery(fuzzer_name, job_types,
                                              testcase_run_fields, group_by,
                                              date_start, date_end)

    assert self.job_run_query or self.testcase_run_query, (
        'Unable to create query.')

  def _join_subqueries(self):
    """Create an inner join for subqueries."""
    result = [
        '(%s) as %s' % (self.job_run_query.build(), self.job_run_query.alias),
        'INNER JOIN',
        '(%s) as %s' % (self.testcase_run_query.build(),
                        self.testcase_run_query.alias), 'ON',
        '{job_alias}.{group_by} = {testcase_alias}.{group_by}'.format(
            job_alias=self.job_run_query.alias,
            testcase_alias=self.testcase_run_query.alias,
            group_by=group_by_to_field_name(self.group_by))
    ]
    return ' '.join(result)

  def _single_subquery(self):
    """Create a single subquery."""
    query = self.job_run_query or self.testcase_run_query
    return '(%s) as %s' % (query.build(), query.alias)

  def build(self):
    """Build the table query."""
    valid_run_query = self.job_run_query or self.testcase_run_query
    result = [
        # We need to do the below to avoid the duplicate column name error.
        'SELECT {0}.{1}, * EXCEPT({1}) FROM'.format(
            valid_run_query.alias,
            group_by_to_field_name(valid_run_query.group_by))
    ]

    if self.job_run_query and self.testcase_run_query:
      result.append(self._join_subqueries())
    else:
      result.append(self._single_subquery())

    return ' '.join(result)


def get_coverage_info(fuzzer, date=None):
  """Returns a CoverageInformation entity for a given fuzzer and date. If date
  is not specified, returns the latest entity available."""
  query = data_types.CoverageInformation.query(
      data_types.CoverageInformation.fuzzer == fuzzer)
  if date:
    # Return info for specific date.
    query = query.filter(data_types.CoverageInformation.date == date)
  else:
    # Return latest.
    query = query.order(-data_types.CoverageInformation.date)

  return query.get()


def get_gcs_stats_path(kind, fuzzer, timestamp):
  """Return gcs path in the format "/bucket/path/to/containing_dir/" for the
  given fuzzer, job, and timestamp or revision."""
  bucket_name = big_query.get_bucket()
  if not bucket_name:
    return None

  datetime_value = datetime.datetime.utcfromtimestamp(timestamp)
  dir_name = data_types.coverage_information_date_to_string(datetime_value)

  path = '/%s/%s/%s/date/%s/' % (bucket_name, fuzzer, kind, dir_name)
  return path


@environment.local_noop
def upload_stats(stats_list, filename=None):
  """Upload the fuzzer run to the bigquery bucket. Assumes that all the stats
  given are for the same fuzzer/job run."""
  if not stats_list:
    logs.log_error('Failed to upload fuzzer stats: empty stats.')
    return

  assert isinstance(stats_list, list)

  bucket_name = big_query.get_bucket()
  if not bucket_name:
    logs.log_error('Failed to upload fuzzer stats: missing bucket name.')
    return

  kind = stats_list[0].kind
  fuzzer = stats_list[0].fuzzer

  # Group all stats for fuzz targets.
  fuzzer_or_engine_name = get_fuzzer_or_engine_name(fuzzer)

  if not filename:
    # Generate a random filename.
    filename = '%016x' % random.randint(0, (1 << 64) - 1) + '.json'

  # Handle runs that bleed into the next day.
  timestamp_start_of_day = lambda s: utils.utc_date_to_timestamp(
      datetime.datetime.utcfromtimestamp(s.timestamp).date())
  stats_list.sort(key=lambda s: s.timestamp)

  for timestamp, stats in itertools.groupby(stats_list, timestamp_start_of_day):
    upload_data = '\n'.join(stat.to_json() for stat in stats)

    day_path = 'gs:/' + get_gcs_stats_path(
        kind, fuzzer_or_engine_name, timestamp=timestamp) + filename

    if not storage.write_data(upload_data.encode('utf-8'), day_path):
      logs.log_error('Failed to upload FuzzerRun.')


def parse_stats_column_fields(column_fields):
  """Parse the stats column fields."""
  # e.g. 'sum(t.field_name) as display_name'.
  aggregate_regex = re.compile(r'^(\w+)\(([a-z])\.([^\)]+)\)(\s*as\s*(\w+))?$')

  # e.g. '_EDGE_COV as blah'.
  builtin_regex = re.compile(r'^(_\w+)(\s*as\s*(\w+))?$')

  fields = []
  parts = [field.strip() for field in column_fields.split(',')]
  for part in parts:
    match = aggregate_regex.match(part)
    if match:
      table_alias = match.group(2)
      field_name = match.group(3)
      aggregate_function = match.group(1)
      select_alias = match.group(5)
      if select_alias:
        select_alias = select_alias.strip('"')

      fields.append(
          QueryField(table_alias, field_name, aggregate_function, select_alias))
      continue

    match = builtin_regex.match(part)
    if match:
      name = match.group(1)
      alias = match.group(3)
      if alias:
        alias = alias.strip('"')
      fields.append(BuiltinFieldSpecifier(name, alias))
      continue

  return fields


def get_fuzzer_or_engine_name(fuzzer_name):
  """Return fuzzing engine name if it exists, or |fuzzer_name|."""
  fuzz_target = data_handler.get_fuzz_target(fuzzer_name)
  if fuzz_target:
    return fuzz_target.engine

  return fuzzer_name


def dataset_name(fuzzer_name):
  """Get the stats dataset name for the given |fuzzer_name|."""
  return fuzzer_name.replace('-', '_') + '_stats'


BUILTIN_FIELD_CONSTRUCTORS = {
    '_EDGE_COV':
        functools.partial(CoverageField, CoverageField.EDGE),
    '_FUNC_COV':
        functools.partial(CoverageField, CoverageField.FUNCTION),
    '_CORPUS_SIZE':
        functools.partial(CorpusSizeField, CorpusSizeField.CORPUS),
    '_CORPUS_BACKUP':
        CorpusBackupField,
    '_QUARANTINE_SIZE':
        functools.partial(CorpusSizeField, CorpusSizeField.QUARANTINE),
    '_COV_REPORT':
        CoverageReportField,
    '_FUZZER_RUN_LOGS':
        FuzzerRunLogsField,
    '_PERFORMANCE_REPORT':
        PerformanceReportField,
}
