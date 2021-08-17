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
"""Initial datastore setup."""

from google.cloud import monitoring_v3
import six

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.metrics import monitor
from clusterfuzz._internal.metrics import monitoring_metrics

LIBFUZZER_TEMPLATE = """MAX_FUZZ_THREADS = 1
MAX_TESTCASES = 2
FUZZ_TEST_TIMEOUT = 8400
TEST_TIMEOUT = 65
WARMUP_TIMEOUT = 65
BAD_BUILD_CHECK = False
THREAD_ALIVE_CHECK_INTERVAL = 1
REPORT_OOMS_AND_HANGS = True
CORPUS_FUZZER_NAME_OVERRIDE = libFuzzer
ENABLE_GESTURES = False
THREAD_DELAY = 30.0
"""

SYZKALLER_TEMPLATE = """MAX_FUZZ_THREADS = 1
MAX_TESTCASES = 1
FUZZ_TEST_TIMEOUT = 10800
TEST_TIMEOUT = 120
WARMUP_TIMEOUT = 120
BAD_BUILD_CHECK = False
THREAD_ALIVE_CHECK_INTERVAL = 1
REPORT_OOMS_AND_HANGS = True
ENABLE_GESTURES = False
THREAD_DELAY = 30.0
"""

AFL_TEMPLATE = """MAX_FUZZ_THREADS = 1
MAX_TESTCASES = 2
FUZZ_TEST_TIMEOUT = 8400
TEST_TIMEOUT = 30
WARMUP_TIMEOUT = 30
BAD_BUILD_CHECK = False
THREAD_ALIVE_CHECK_INTERVAL = 1
CORPUS_FUZZER_NAME_OVERRIDE = libFuzzer
ADDITIONAL_PROCESSES_TO_KILL = afl-fuzz afl-showmap
ENABLE_GESTURES = False
THREAD_DELAY  = 30.0
"""

HONGGFUZZ_TEMPLATE = """MAX_FUZZ_THREADS = 1
MAX_TESTCASES = 2
FUZZ_TEST_TIMEOUT = 8400
TEST_TIMEOUT = 65
WARMUP_TIMEOUT = 65
BAD_BUILD_CHECK = False
THREAD_ALIVE_CHECK_INTERVAL = 1
CORPUS_FUZZER_NAME_OVERRIDE = libFuzzer
ENABLE_GESTURES = False
THREAD_DELAY = 30.0
"""

GOOGLEFUZZTEST_TEMPLATE = """MAX_FUZZ_THREADS = 1
MAX_TESTCASES = 2
FUZZ_TEST_TIMEOUT = 8400
TEST_TIMEOUT = 65
WARMUP_TIMEOUT = 65
BAD_BUILD_CHECK = False
THREAD_ALIVE_CHECK_INTERVAL = 1
REPORT_OOMS_AND_HANGS = True
ENABLE_GESTURES = False
THREAD_DELAY = 30.0
"""

ENGINE_ASAN_TEMPLATE = ('LSAN = True\n'
                        'ADDITIONAL_ASAN_OPTIONS = '
                        'symbolize=0:'
                        'quarantine_size_mb=64:'
                        'strict_memcmp=1:'
                        'fast_unwind_on_fatal=0:'
                        'allocator_release_to_os_interval_ms=500:'
                        'handle_abort=2:'
                        'handle_segv=2:'
                        'handle_sigbus=2:'
                        'handle_sigfpe=2:'
                        'handle_sigill=2')

ENGINE_MSAN_TEMPLATE = ('ADDITIONAL_MSAN_OPTIONS = '
                        'symbolize=0:'
                        'print_stats=1:'
                        'allocator_release_to_os_interval_ms=500:'
                        'halt_on_error=1:'
                        'handle_abort=2:'
                        'handle_segv=2:'
                        'handle_sigbus=2:'
                        'handle_sigfpe=2:'
                        'handle_sigill=2')

ENGINE_UBSAN_TEMPLATE = ('LSAN = False\n'
                         'ADDITIONAL_UBSAN_OPTIONS = '
                         'symbolize=0:'
                         'allocator_release_to_os_interval_ms=500:'
                         'handle_abort=2:'
                         'handle_segv=2:'
                         'handle_sigbus=2:'
                         'handle_sigfpe=2:'
                         'handle_sigill=2')

PRUNE_TEMPLATE = 'CORPUS_PRUNE = True'

TEMPLATES = {
    'afl': AFL_TEMPLATE,
    'engine_asan': ENGINE_ASAN_TEMPLATE,
    'engine_msan': ENGINE_MSAN_TEMPLATE,
    'engine_ubsan': ENGINE_UBSAN_TEMPLATE,
    'honggfuzz': HONGGFUZZ_TEMPLATE,
    'googlefuzztest': GOOGLEFUZZTEST_TEMPLATE,
    'libfuzzer': LIBFUZZER_TEMPLATE,
    'syzkaller': SYZKALLER_TEMPLATE,
    'prune': PRUNE_TEMPLATE,
}


class BaseBuiltinFuzzerDefaults(object):
  """Default values for a builtin Fuzzer data_type. Note this class should be
  inherited and should not be used directly."""

  def __init__(self):
    # Set defaults for any builtin fuzzer.
    self.revision = 1
    self.file_size = 'builtin'
    self.source = 'builtin'
    self.builtin = True

    # Create attributes that must be set by child classes.
    self.name = None
    self.stats_column_descriptions = None
    self.stats_columns = None
    self.key_id = None

  def create_fuzzer(self):
    """Create a Fuzzer data_type with columns set to the defaults specified by
    this object."""
    assert self.name is not None
    return data_types.Fuzzer(
        id=self.key_id,
        revision=self.revision,
        file_size=self.file_size,
        source=self.source,
        name=self.name,
        builtin=self.builtin,
        stats_column_descriptions=self.stats_column_descriptions,
        stats_columns=self.stats_columns)


class LibFuzzerDefaults(BaseBuiltinFuzzerDefaults):
  """Default values for libFuzzer."""

  def __init__(self):
    super().__init__()
    # Override empty values from parent.
    self.name = 'libFuzzer'
    self.key_id = 1337
    # Use single quotes since the string ends in a double quote.
    # pylint: disable=line-too-long
    self.stats_column_descriptions = '''fuzzer: "Fuzz target"
perf_report: "Link to performance analysis report"
tests_executed: "Number of testcases executed during this time period"
new_crashes: "Number of new unique crashes observed during this time period"
edge_coverage: "Coverage for this fuzz target (number of edges/total)"
cov_report: "Link to coverage report"
corpus_size: "Size of the minimized corpus generated based on code coverage (number of testcases and total size on disk)"
avg_exec_per_sec: "Average number of testcases executed per second"
fuzzing_time_percent: "Percent of expected fuzzing time that is actually spent fuzzing."
new_tests_added: "New testcases added to the corpus during fuzzing based on code coverage"
new_features: "New coverage features based on new tests added to corpus."
regular_crash_percent: "Percent of fuzzing runs that had regular crashes (other than ooms, leaks, timeouts, startup and bad instrumentation crashes)"
oom_percent: "Percent of fuzzing runs that crashed on OOMs (should be 0)"
leak_percent: "Percent of fuzzing runs that crashed on memory leaks (should be 0)"
timeout_percent: "Percent of fuzzing runs that had testcases timeout (should be 0)"
startup_crash_percent: "Percent of fuzzing runs that crashed on startup (should be 0)"
avg_unwanted_log_lines: "Average number of unwanted log lines in fuzzing runs (should be 0)"
total_fuzzing_time_hrs: "Total time in hours for which the fuzzer(s) ran. Will be lower if fuzzer hits a crash frequently."
logs: "Link to fuzzing logs"
corpus_backup: "Backup copy of the minimized corpus generated based on code coverage"'''

    self.stats_columns = """_PERFORMANCE_REPORT as perf_report,
sum(t.number_of_executed_units) as tests_executed,
custom(j.new_crashes) as new_crashes,
_EDGE_COV as edge_coverage,
_COV_REPORT as cov_report,
_CORPUS_SIZE as corpus_size,
avg(t.average_exec_per_sec) as avg_exec_per_sec,
avg(t.fuzzing_time_percent) as fuzzing_time_percent,
sum(t.new_units_added) as new_tests_added,
sum(t.new_features) as new_features,
avg(t.crash_count*100) as regular_crash_percent,
avg(t.oom_count*100) as oom_percent,
avg(t.leak_count*100) as leak_percent,
avg(t.timeout_count*100) as timeout_percent,
avg(t.startup_crash_count*100) as startup_crash_percent,
avg(t.log_lines_unwanted) as avg_unwanted_log_lines,
sum(t.actual_duration/3600.0) as total_fuzzing_time_hrs,
_FUZZER_RUN_LOGS as logs,
_CORPUS_BACKUP as corpus_backup,"""


class AflDefaults(BaseBuiltinFuzzerDefaults):
  """Default values for AFL."""

  def __init__(self):
    super().__init__()
    # Override empty values from parent.
    self.name = 'afl'
    self.key_id = 1338
    # Use single quotes since the string ends in a double quote.
    # pylint: disable=line-too-long
    self.stats_column_descriptions = '''fuzzer: "Fuzz target"
new_crashes: "Number of new unique crashes observed during this time period"
edge_coverage: "Edge coverage for this fuzz target (number of edges / total)"
cov_report: "Link to coverage report"
corpus_size: "Size of the minimized corpus generated based on code coverage (number of testcases and total size on disk)"
avg_exec_per_sec: "Average number of testcases executed per second"
stability: "Percentage of edges that behave deterministically"
new_tests_added: "New testcases added to the corpus during fuzzing based on code coverage"
regular_crash_percent: "Percent of fuzzing runs that had regular crashes (other than startup and bad instrumentation crashes)"
timeout_percent: "Percent of fuzzing runs that had testcases timeout (should be 0)"
startup_crash_percent: "Percent of fuzzing runs that crashed on startup (should be 0)"
avg_unwanted_log_lines: "Average number of unwanted log lines in fuzzing runs (should be 0)"
total_fuzzing_time_hrs: "Total time in hours for which the fuzzer(s) ran. Will be lower if fuzzer hits a crash frequently."
logs: "Link to fuzzing logs"
corpus_backup: "Backup copy of the minimized corpus generated based on code coverage"'''

    self.stats_columns = """custom(j.new_crashes) as new_crashes,
_EDGE_COV as edge_coverage,
_COV_REPORT as cov_report,
_CORPUS_SIZE as corpus_size,
avg(t.average_exec_per_sec) as avg_exec_per_sec,
avg(t.stability) as stability,
sum(t.new_units_added) as new_tests_added,
avg(t.crash_count*100) as regular_crash_percent,
avg(t.timeout_count*100) as timeout_percent,
avg(t.startup_crash_count*100) as startup_crash_percent,
avg(t.log_lines_unwanted) as avg_unwanted_log_lines,
sum(t.actual_duration/3600.0) as total_fuzzing_time_hrs,
_FUZZER_RUN_LOGS as logs,
_CORPUS_BACKUP as corpus_backup,"""


class HonggfuzzDefaults(BaseBuiltinFuzzerDefaults):
  """Default values for honggfuzz."""

  def __init__(self):
    super().__init__()
    self.name = 'honggfuzz'
    self.key_id = 1339


class SyzkallerDefaults(BaseBuiltinFuzzerDefaults):
  """Default values for syzkaller."""

  def __init__(self):
    super().__init__()
    # Override empty values from parent.
    self.name = 'syzkaller'
    self.key_id = 1340


class GoogleFuzzTestDefaults(BaseBuiltinFuzzerDefaults):
  """Default values for googlefuzztest."""

  def __init__(self):
    super().__init__()
    self.name = 'googlefuzztest'
    self.key_id = 1341


def setup_config(non_dry_run):
  """Set up configuration."""
  config = data_types.Config.query().get()
  if not config:
    config = data_types.Config()

    if non_dry_run:
      print('Creating config')
      config.put()
    else:
      print('Skip creating config (dry-run mode)')


def setup_fuzzers(non_dry_run):
  """Set up fuzzers."""
  for fuzzer_defaults in [
      AflDefaults(),
      LibFuzzerDefaults(),
      HonggfuzzDefaults(),
      GoogleFuzzTestDefaults(),
      SyzkallerDefaults()
  ]:
    fuzzer = data_types.Fuzzer.query(
        data_types.Fuzzer.name == fuzzer_defaults.name).get()
    if fuzzer:
      print(fuzzer_defaults.name, 'fuzzer already exists')
      if non_dry_run:
        print('Updating stats metrics.')
        fuzzer.stats_columns = fuzzer_defaults.stats_columns
        fuzzer.stats_column_descriptions = (
            fuzzer_defaults.stats_column_descriptions)
        fuzzer.put()

      continue

    if non_dry_run:
      print('Creating fuzzer', fuzzer_defaults.name)
      fuzzer_defaults.create_fuzzer().put()
    else:
      print('Skip creating fuzzer', fuzzer_defaults.name, '(dry-run mode)')


def setup_templates(non_dry_run):
  """Set up templates."""
  for name, template in six.iteritems(TEMPLATES):
    job = data_types.JobTemplate.query(
        data_types.JobTemplate.name == name).get()
    if job:
      print('Template with name', name, 'already exists.')
      continue

    if non_dry_run:
      print('Creating template', name)
      data_types.JobTemplate(name=name, environment_string=template).put()
    else:
      print('Skip creating template', name, '(dry-run mode)')


def setup_metrics(non_dry_run):
  """Set up metrics."""
  client = monitoring_v3.MetricServiceClient()
  project_name = utils.get_application_id()
  project_path = client.project_path(project_name)

  for name in dir(monitoring_metrics):
    metric = getattr(monitoring_metrics, name)
    if not isinstance(metric, monitor.Metric):
      continue

    descriptor = monitoring_v3.types.MetricDescriptor()
    metric.monitoring_v3_metric_descriptor(descriptor)

    if non_dry_run:
      print('Creating metric', descriptor)
      client.create_metric_descriptor(project_path, descriptor)
    else:
      print('Skip creating metric', descriptor, '(dry-run mode)')


def execute(args):
  """Set up initial Datastore models."""
  setup_config(args.non_dry_run)
  setup_fuzzers(args.non_dry_run)
  setup_templates(args.non_dry_run)

  if not args.local:
    setup_metrics(args.non_dry_run)

  print('Done')
