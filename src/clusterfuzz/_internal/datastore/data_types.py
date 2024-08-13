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
"""Classes for objects stored in the datastore."""

import json
import re

from google.cloud import ndb

from clusterfuzz._internal.base import json_utils
from clusterfuzz._internal.base import utils
from clusterfuzz._internal.datastore import search_tokenizer
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment

# pylint: disable=no-member,arguments-differ

# Prefix used when a large testcase is stored in the blobstore.
BLOBSTORE_STACK_PREFIX = 'BLOB_KEY='

# List of builtin fuzzers.
BUILTIN_FUZZERS = ['afl', 'libFuzzer']

# Time to look back to find a corpus backup that is marked public.
CORPUS_BACKUP_PUBLIC_LOOKBACK_DAYS = 90

# Marker to indicate end of crash stacktrace. Anything after that is excluded
# from being stored as part of crash stacktrace (e.g. merge content, etc).
CRASH_STACKTRACE_END_MARKER = 'CRASH OUTPUT ENDS HERE'

# Skips using crash state similarity for these types.
CRASH_TYPES_WITH_UNIQUE_STATE = [
    'Missing-library',
    'Out-of-memory',
    'Overwrites-const-input',
    'Timeout',
    # V8 correctness failures use metadata from the fuzz test cases as crash
    # state. This is not suitable for using levenshtein distance for
    # similarity.
    'V8 correctness failure',
]

# Maximum size allowed for an appengine entity type.
# Explicily kept slightly lower than 1 MB.
ENTITY_SIZE_LIMIT = 900000

# Minimum number of unreproducible crashes to see before filing it.
FILE_UNREPRODUCIBLE_TESTCASE_MIN_CRASH_THRESHOLD = 100

# Heartbeat wait interval.
HEARTBEAT_WAIT_INTERVAL = 10 * 60

# Android device heartbeat wait interval.
ANDROID_HEARTBEAT_WAIT_INTERVAL = 60

# Time to wait after a report is marked fixed and before filing another similar
# one (hours).
MIN_ELAPSED_TIME_SINCE_FIXED = 2 * 24

# Time to wait for grouping task to finish, before filing the report (hours).
MIN_ELAPSED_TIME_SINCE_REPORT = 4

# Valid name check for fuzzer, job, etc.
NAME_CHECK_REGEX = re.compile(r'^[a-zA-Z0-9_-]+$')

# Regex to match special chars in project name.
SPECIAL_CHARS_REGEX = re.compile('[^a-zA-Z0-9_-]')

# List of supported platforms.
PLATFORMS = [
    'LINUX',
    'ANDROID',
    'CHROMEOS',
    'MAC',
    'WINDOWS',
    'FUCHSIA',
    'ANDROID_AUTO',
]

# Maximum size allowed for an appengine pubsub request.
# Explicily kept slightly lower than 1 MB.
PUBSUB_REQUEST_LIMIT = 900000

# We store at most 3 stacktraces per Testcase entity (original, second, latest).
STACKTRACE_LENGTH_LIMIT = ENTITY_SIZE_LIMIT // 3

# Maximum size allowed for testcase comments.
# 1MiB (maximum Datastore entity size) - ENTITY_SIZE_LIMIT (our limited entity
# size with breathing room), divided by 2 to leave room for other things in the
# entity. This is around 74KB.
TESTCASE_COMMENTS_LENGTH_LIMIT = (1024 * 1024 - ENTITY_SIZE_LIMIT) // 2

# Maximum number of testcase entities to query in one batch.
TESTCASE_ENTITY_QUERY_LIMIT = 256

# Deadlines for testcase filing, closures and deletions (in days).
DUPLICATE_TESTCASE_NO_BUG_DEADLINE = 3
CLOSE_TESTCASE_WITH_CLOSED_BUG_DEADLINE = 14
FILE_CONSISTENT_UNREPRODUCIBLE_TESTCASE_DEADLINE = 14
NOTIFY_CLOSED_BUG_WITH_OPEN_TESTCASE_DEADLINE = 7
UNREPRODUCIBLE_TESTCASE_NO_BUG_DEADLINE = 7
UNREPRODUCIBLE_TESTCASE_WITH_BUG_DEADLINE = 14

# Chromium specific issue state tracking labels.
CHROMIUM_ISSUE_RELEASEBLOCK_BETA_LABEL = 'ReleaseBlock-Beta'
# TODO(ochang): Find some way to remove these.
CHROMIUM_ISSUE_PREDATOR_AUTO_CC_LABEL = 'Test-Predator-Auto-CC'
CHROMIUM_ISSUE_PREDATOR_AUTO_COMPONENTS_LABEL = 'Test-Predator-Auto-Components'
CHROMIUM_ISSUE_PREDATOR_AUTO_OWNER_LABEL = 'Test-Predator-Auto-Owner'
CHROMIUM_ISSUE_PREDATOR_WRONG_COMPONENTS_LABEL = (
    'Test-Predator-Wrong-Components')
CHROMIUM_ISSUE_PREDATOR_WRONG_CL_LABEL = 'Test-Predator-Wrong-CLs'

MISSING_VALUE_STRING = '---'

COVERAGE_INFORMATION_DATE_FORMAT = '%Y%m%d'


def clone_entity(e, **extra_args):
  """Clones a DataStore entity and returns the clone."""
  ent_class = e.__class__
  # pylint: disable=protected-access,unnecessary-dunder-call
  props = {
      v._code_name: v.__get__(e, ent_class)
      for v in ent_class._properties.values()
      if not isinstance(v, ndb.ComputedProperty)
  }
  props.update(extra_args)
  return ent_class(**props)


class SecuritySeverity:
  """Enum for Security Severity."""
  CRITICAL = 0
  HIGH = 1
  MEDIUM = 2
  LOW = 3
  MISSING = 4

  @classmethod
  def is_valid(cls, security_severity):
    """Return bool on whether a severity is valid."""
    return (security_severity in [cls.CRITICAL, cls.HIGH, cls.MEDIUM, cls.LOW])

  @classmethod
  def list(cls):
    """Return the list of severities for a dropdown menu."""
    return [
        {
            'value': cls.CRITICAL,
            'name': 'Critical'
        },
        {
            'value': cls.HIGH,
            'name': 'High',
            'default': True
        },
        {
            'value': cls.MEDIUM,
            'name': 'Medium'
        },
        {
            'value': cls.LOW,
            'name': 'Low'
        },
        {
            'value': cls.MISSING,
            'name': 'Missing'
        },
    ]


# Impact values for security issues.
class SecurityImpact:
  EXTENDED_STABLE = 0
  STABLE = 1
  BETA = 2
  HEAD = 3
  NONE = 4
  MISSING = 5


# Archive state enums.
class ArchiveStatus:
  NONE = 0
  FUZZED = 1
  MINIMIZED = 2
  ALL = FUZZED | MINIMIZED


# ExternalUserPermission Auto-CC type.
class AutoCCType:
  # Don't Auto-CC user.
  NONE = 0
  # Auto-CC user for all issues.
  ALL = 1
  # Auto-CC only for security issues.
  SECURITY = 2


# Type of permission. Used by ExternalUserPermision.
class PermissionEntityKind:
  FUZZER = 0
  JOB = 1
  UPLOADER = 2


# Task state string mappings.
class TaskState:
  STARTED = 'started'
  WIP = 'in-progress'
  FINISHED = 'finished'
  ERROR = 'errored out'
  NA = ''


# Build state.
class BuildState:
  UNMARKED = 0
  GOOD = 1
  BAD = 2


class TestcaseVariantStatus:
  PENDING = 0
  REPRODUCIBLE = 1
  FLAKY = 2
  UNREPRODUCIBLE = 3


class Model(ndb.Model):
  """Cache-less NDB model."""
  _use_cache = False
  _use_memcache = False


class Blacklist(Model):
  """Represents global blacklist to track entries for suppressions files."""
  # Function name.
  function_name = ndb.StringProperty()

  # Tool name.
  tool_name = ndb.StringProperty()

  # Testcase ID.
  testcase_id = ndb.IntegerProperty()


class Fuzzer(Model):
  """Represents a fuzzer."""

  # Additionally allows '.' and '@' over NAME_CHECK_REGEX.
  VALID_NAME_REGEX = re.compile(r'^[a-zA-Z0-9_@.-]+$')

  # Last update time.
  timestamp = ndb.DateTimeProperty()

  # Fuzzer Name.
  name = ndb.StringProperty()

  # The name of the archive that the user uploaded.
  filename = ndb.StringProperty()

  # Blobstore key for this fuzzer.
  blobstore_key = ndb.StringProperty()

  # String representation of the file size.
  file_size = ndb.StringProperty()

  # Fuzzer's main executable path, relative to root.
  executable_path = ndb.StringProperty()

  # Revision number of the fuzzer.
  revision = ndb.IntegerProperty()

  # Fuzzer's source (for accountability).
  source = ndb.StringProperty()

  # Testcase timeout.
  timeout = ndb.IntegerProperty()

  # Supported platforms.
  supported_platforms = ndb.StringProperty()

  # Custom script that should be used to launch chrome for this fuzzer.
  launcher_script = ndb.StringProperty()

  # Result from the last fuzzer run showing the number of testcases generated.
  result = ndb.StringProperty()

  # Last result update timestamp.
  result_timestamp = ndb.DateTimeProperty()

  # Console output from last fuzzer run.
  console_output = ndb.TextProperty()

  # Return code from last fuzzer run.
  return_code = ndb.IntegerProperty()

  # Blobstore key for the sample testcase generated by the fuzzer.
  sample_testcase = ndb.StringProperty()

  # Job types for this fuzzer.
  jobs = ndb.TextProperty(repeated=True)

  # Is the fuzzer coming from an external contributor ? Useful for adding
  # reward flags.
  external_contribution = ndb.BooleanProperty(default=False)

  # Max testcases to generate for this fuzzer.
  max_testcases = ndb.IntegerProperty()

  # Does it run un-trusted content ? Examples including running live sites.
  untrusted_content = ndb.BooleanProperty(default=False)

  # Data bundle name.
  data_bundle_name = ndb.StringProperty(default='')

  # Additional environment variables that need to be set for this fuzzer.
  additional_environment_string = ndb.TextProperty()

  # Column specification for stats.
  stats_columns = ndb.TextProperty()

  # Helpful descriptions for the stats_column.sw In a yaml format.
  stats_column_descriptions = ndb.TextProperty(indexed=False)

  # Whether this is a builtin fuzzer.
  builtin = ndb.BooleanProperty(indexed=False, default=False)

  # Whether this is a differential fuzzer.
  differential = ndb.BooleanProperty(default=False)

  # If this flag is set, fuzzer generates the testcase in the larger directory
  # on disk |FUZZ_INPUTS_DISK|, rather than smaller tmpfs one (FUZZ_INPUTS).
  has_large_testcases = ndb.BooleanProperty(default=False)


class BuildCrashStatsJobHistory(Model):
  """Represents the record of build_crash_stats run."""
  # End time in hours from epoch, inclusively.
  end_time_in_hours = ndb.IntegerProperty()


class Testcase(Model):
  """Represents a single testcase."""
  # Crash on an invalid read/write.
  crash_type = ndb.StringProperty()

  # Crashing address.
  crash_address = ndb.TextProperty()

  # First x stack frames.
  crash_state = ndb.StringProperty()

  # Complete stacktrace.
  crash_stacktrace = ndb.TextProperty(indexed=False)

  # Last tested crash stacktrace using the latest revision.
  last_tested_crash_stacktrace = ndb.TextProperty(indexed=False)

  # Blobstore keys for various things like original testcase, minimized
  # testcase, etc.
  fuzzed_keys = ndb.TextProperty()
  minimized_keys = ndb.TextProperty()
  minidump_keys = ndb.TextProperty()

  # Tracking issue tracker bug. One bug number per line (future extension).
  bug_information = ndb.StringProperty()

  # Regression range.
  regression = ndb.StringProperty(default='')

  # Revisions where this issue has been fixed.
  fixed = ndb.StringProperty(default='')

  # Is it a security bug ?
  security_flag = ndb.BooleanProperty(default=False)

  # Security severity of the bug.
  security_severity = ndb.IntegerProperty(indexed=False)

  # Did the bug only reproduced once ?
  one_time_crasher_flag = ndb.BooleanProperty(default=False)

  # Any additional comments.
  comments = ndb.TextProperty(default='', indexed=False)

  # Revision that we discovered the crash in.
  crash_revision = ndb.IntegerProperty()

  # The file on the bot that generated the testcase.
  absolute_path = ndb.TextProperty()

  # Minimized argument list.
  minimized_arguments = ndb.TextProperty(default='', indexed=False)

  # Window argument (usually width, height, top, left, etc).
  window_argument = ndb.TextProperty(default='', indexed=False)

  # Type of job associated with this testcase.
  job_type = ndb.StringProperty()

  # Original job queue used for tasks created for this testcase.
  queue = ndb.TextProperty()

  # State representing whether the fuzzed or minimized testcases are archived.
  archive_state = ndb.IntegerProperty(default=0, indexed=False)

  # File name of the original uploaded archive.
  archive_filename = ndb.TextProperty()

  # Timestamp.
  timestamp = ndb.DateTimeProperty()

  # Does the testcase crash stack vary b/w crashes ?
  flaky_stack = ndb.BooleanProperty(default=False, indexed=False)

  # Do we need to test this testcase using an HTTP/HTTPS server?
  http_flag = ndb.BooleanProperty(default=False, indexed=False)

  # Name of the fuzzer used to generate this testcase.
  fuzzer_name = ndb.StringProperty()

  # Status of this testcase (pending, processed, unreproducible, etc).
  status = ndb.StringProperty(default='Processed')

  # Id of the testcase that this is marked as a duplicate of.
  duplicate_of = ndb.IntegerProperty(indexed=False)

  # Flag indicating whether or not the testcase has been symbolized.
  symbolized = ndb.BooleanProperty(default=False, indexed=False)

  # Id for this testcase's associated group.
  group_id = ndb.IntegerProperty(default=0)

  # Tracking issue tracker bug for this testcase group.
  group_bug_information = ndb.IntegerProperty(default=0)

  # Fake user interaction sequences like key clicks, mouse movements, etc.
  gestures = ndb.TextProperty(repeated=True)

  # ASAN redzone size in bytes.
  redzone = ndb.IntegerProperty(default=128, indexed=False)

  # Flag indicating if UBSan detection should be disabled. This is needed for
  # cases when ASan and UBSan are bundled in the same build configuration
  # and we need to disable UBSan in some runs to find the potentially more
  # interesting ASan bugs.
  disable_ubsan = ndb.BooleanProperty(default=False)

  # Whether testcase is open.
  open = ndb.BooleanProperty(default=True)

  # Adjusts timeout based on multiplier value.
  timeout_multiplier = ndb.FloatProperty(default=1.0, indexed=False)

  # Additional metadata stored as a JSON object. This should be used for
  # properties that are not commonly accessed and do not need to be indexed.
  additional_metadata = ndb.TextProperty(indexed=False)

  # Boolean attribute indicating if cleanup triage needs to be done.
  triaged = ndb.BooleanProperty(default=False)

  # Project name associated with this test case.
  project_name = ndb.StringProperty()

  # keywords is used for searching.
  keywords = ndb.StringProperty(repeated=True)

  # Whether testcase has a bug (either bug_information or
  # group_bug_information).
  has_bug_flag = ndb.BooleanProperty()

  # Indices for bug_information and group_bug_information.
  bug_indices = ndb.StringProperty(repeated=True)

  # Overridden fuzzer name because actual fuzzer name can be different in many
  # scenarios (libfuzzer, afl, etc).
  overridden_fuzzer_name = ndb.StringProperty()

  # Platform (e.g. windows, linux, android).
  platform = ndb.StringProperty()

  # Platform id (e.g. windows, linux, android:hammerhead:l).
  # For Android, includes device type and underlying OS version.
  platform_id = ndb.StringProperty()

  # Impact indices for searching.
  impact_indices = ndb.StringProperty(repeated=True)

  # Whether or not a testcase is a duplicate of other testcase.
  is_a_duplicate_flag = ndb.BooleanProperty()

  # Whether or not a testcase is the leader of its group.
  # If the testcase is not in a group, it's the leader of a group of 1.
  # The default is false because we prefer not to show crashes until we are
  # sure. And group_task will correctly set the value within 30 minutes.
  is_leader = ndb.BooleanProperty(default=False)

  # Fuzzer name indices
  fuzzer_name_indices = ndb.StringProperty(repeated=True)

  # The impacted version indices (including beta, stable and extended_stable).
  impact_version_indices = ndb.StringProperty(repeated=True)

  # The impacted extended stable version.
  impact_extended_stable_version = ndb.StringProperty()

  # The impacted extended stable version indices.
  impact_extended_stable_version_indices = ndb.StringProperty(repeated=True)

  # The impacted extended stable version is merely probable (not definite).
  # See the comment on impact_stable_version_likely.
  impact_extended_stable_version_likely = ndb.BooleanProperty()

  # The impacted stable version.
  impact_stable_version = ndb.StringProperty()

  # The impacted stable version indices.
  impact_stable_version_indices = ndb.StringProperty(repeated=True)

  # The impacted stable version is merely probable (not definite). Because
  # for a non-asan build, we don't have a stable/beta build. Therefore, we
  # make an intelligent guess on the version.
  impact_stable_version_likely = ndb.BooleanProperty()

  # The impacted beta version.
  impact_beta_version = ndb.StringProperty()

  # The impacted beta version indices.
  impact_beta_version_indices = ndb.StringProperty(repeated=True)

  # The impacted beta version is merely probable (not definite). See the
  # comment on impact_stable_version_likely.
  impact_beta_version_likely = ndb.BooleanProperty()

  # The impacted 'head' version
  impact_head_version = ndb.StringProperty()

  # The impacted head version indices.
  impact_head_version_indices = ndb.StringProperty(repeated=True)

  # The impacted head version is likely.
  impact_head_version_likely = ndb.BooleanProperty()

  # Whether or not impact task has been run on this testcase.
  is_impact_set_flag = ndb.BooleanProperty()

  # Uploader email address.
  uploader_email = ndb.StringProperty()

  # Identifies the GitHub repository to mirror the issue of the testcase.
  github_repo_id = ndb.IntegerProperty()

  # Identifies the issue of the testcase in the repo above.
  # Note that the number is specific to the repository.
  github_issue_num = ndb.IntegerProperty()

  # Whether the testcase is from a trustworthy source.
  # False by default since this will determine what is put in the regression
  # corpus.
  trusted = ndb.BooleanProperty(default=False)

  def is_chromium(self):
    return self.project_name in ('chromium', 'chromium-testing')

  def has_blame(self):
    return self.is_chromium()

  def has_impacts(self):
    return self.is_chromium() and not self.one_time_crasher_flag

  def impacts_production(self):
    return (bool(self.impact_extended_stable_version) or
            bool(self.impact_stable_version) or bool(self.impact_beta_version))

  def is_status_unreproducible(self):
    return self.status and self.status.startswith('Unreproducible')

  def is_crash(self):
    return bool(self.crash_state)

  def populate_indices(self):
    """Populate keywords for fast test case list searching."""
    self.keywords = list(
        search_tokenizer.tokenize(self.crash_state)
        | search_tokenizer.tokenize(self.crash_type)
        | search_tokenizer.tokenize(self.fuzzer_name)
        | search_tokenizer.tokenize(self.overridden_fuzzer_name)
        | search_tokenizer.tokenize(self.job_type)
        | search_tokenizer.tokenize(self.platform_id))

    self.bug_indices = search_tokenizer.tokenize_bug_information(self)
    self.has_bug_flag = bool(self.bug_indices)
    self.is_a_duplicate_flag = bool(self.duplicate_of)
    fuzzer_name_indices = list({self.fuzzer_name, self.overridden_fuzzer_name})
    self.fuzzer_name_indices = [f for f in fuzzer_name_indices if f]

    # If the impact task hasn't been run (aka is_impact_set_flag=False) OR
    # if impact isn't applicable (aka has_impacts() is False), we wipe all
    # the impact fields' indices.
    if self.has_impacts() and self.is_impact_set_flag:
      self.impact_extended_stable_version_indices = (
          search_tokenizer.tokenize_impact_version(
              self.impact_extended_stable_version))
      self.impact_stable_version_indices = (
          search_tokenizer.tokenize_impact_version(self.impact_stable_version))
      self.impact_beta_version_indices = (
          search_tokenizer.tokenize_impact_version(self.impact_beta_version))
      self.impact_head_version_indices = (
          search_tokenizer.tokenize_impact_version(self.impact_head_version))
      self.impact_version_indices = list(
          set(self.impact_extended_stable_version_indices +
              self.impact_stable_version_indices +
              self.impact_head_version_indices +
              self.impact_beta_version_indices))
      if self.impact_extended_stable_version:
        self.impact_version_indices.append('extended_stable')
      if self.impact_beta_version:
        self.impact_version_indices.append('beta')
      if self.impact_stable_version:
        self.impact_version_indices.append('stable')
      if not self.impacts_production():
        self.impact_version_indices.append('head')
    else:
      self.impact_version_indices = []
      self.impact_extended_stable_version_indices = []
      self.impact_stable_version_indices = []
      self.impact_beta_version_indices = []

  def _pre_put_hook(self):
    self.populate_indices()

  def _post_put_hook(self, _):
    if not self.key:
      # Failed put. An exception will be thrown automatically afterwards.
      return

    logs.info(
        f'Updated testcase {self.key.id()} (bug {self.bug_information or "-"}).'
    )

  def set_impacts_as_na(self):
    self.impact_stable_version = self.impact_beta_version = None
    self.impact_extended_stable_version = None
    self.impact_stable_version_likely = self.impact_beta_version_likely = False
    self.impact_extended_stable_version_likely = False
    self.is_impact_set_flag = False

  def _ensure_metadata_is_cached(self):
    """Ensure that the metadata for this has been cached."""
    if hasattr(self, 'metadata_cache'):
      return

    try:
      cache = json_utils.loads(self.additional_metadata)
    except (TypeError, ValueError):
      cache = {}

    setattr(self, 'metadata_cache', cache)

  def get_metadata(self, key=None, default=None):
    """Get metadata for a test case. Slow on first access."""
    self._ensure_metadata_is_cached()

    # If no key is specified, return all metadata.
    if not key:
      return self.metadata_cache

    try:
      if key == 'issue_metadata':
        return json.loads(self.metadata_cache[key])
      return self.metadata_cache[key]
    except KeyError:
      return default

  def set_metadata(self, key, value, update_testcase=True):
    """Set metadata for a test case."""
    self._ensure_metadata_is_cached()
    if key == 'issue_metadata' and not isinstance(value, str):
      self.metadata_cache[key] = json.dumps(value)
    else:
      self.metadata_cache[key] = value

    self.additional_metadata = json_utils.dumps(self.metadata_cache)
    if update_testcase:
      self.put()

  def delete_metadata(self, key, update_testcase=True):
    """Remove metadata key for a test case."""
    self._ensure_metadata_is_cached()

    # Make sure that the key exists in cache. If not, no work to do here.
    if key not in self.metadata_cache:
      return

    del self.metadata_cache[key]
    self.additional_metadata = json_utils.dumps(self.metadata_cache)
    if update_testcase:
      self.put()

  def actual_fuzzer_name(self):
    """Actual fuzzer name, uses one from overridden attribute if available."""
    return self.overridden_fuzzer_name or self.fuzzer_name

  def get_fuzz_target(self):
    """Get the associated FuzzTarget entity for this test case."""
    name = self.actual_fuzzer_name()
    if not name:
      return None

    target = ndb.Key(FuzzTarget, name).get()
    if not target:
      binary = self.get_metadata('fuzzer_binary_name')
      if not binary:
        # Not applicable.
        return None

      target = FuzzTarget(
          engine=self.fuzzer_name, project=self.project_name, binary=binary)

    if environment.get_value('ORIGINAL_JOB_NAME'):
      # Overridden engine (e.g. for minimization).
      target.engine = environment.get_engine_for_job()

    return target


class TestcaseGroup(Model):
  """Group for a set of testcases."""


class DataBundle(Model):
  """Represents a data bundle associated with a fuzzer."""

  VALID_NAME_REGEX = NAME_CHECK_REGEX

  # The data bundle's name (important for identifying shared bundles).
  name = ndb.StringProperty()

  # Name of cloud storage bucket on GCS.
  bucket_name = ndb.StringProperty()

  # Data bundle's source (for accountability).
  # TODO(ochang): Remove.
  source = ndb.StringProperty()

  # Creation timestamp.
  timestamp = ndb.DateTimeProperty()

  # Whether or not bundle should be synced to worker instead.
  # Fuzzer scripts are usually run on trusted hosts, so data bundles are synced
  # there. In libFuzzer's case, we want the bundle to be on the same machine as
  # where the libFuzzer binary will run (untrusted).
  sync_to_worker = ndb.BooleanProperty(default=False)


class Config(Model):
  """Configuration."""
  previous_hash = ndb.StringProperty(default='')

  # Project's url.
  url = ndb.StringProperty(default='')

  # Issue tracker client authentication parameters.
  client_credentials = ndb.TextProperty(default='')

  # Jira url and credentials
  jira_url = ndb.StringProperty(default='')
  jira_credentials = ndb.TextProperty(default='')

  # Build apiary authentication parameters.
  build_apiary_service_account_private_key = ndb.TextProperty(default='')

  # Google test account for login, gms testing, etc.
  test_account_email = ndb.StringProperty(default='')
  test_account_password = ndb.StringProperty(default='')

  # Privileged users.
  privileged_users = ndb.TextProperty(default='')

  # Blacklisted users.
  blacklisted_users = ndb.TextProperty(default='')

  # Admin contact string.
  contact_string = ndb.StringProperty(default='')

  # Component to repository mappings.
  component_repository_mappings = ndb.TextProperty(default='')

  # URL for help page for reproducing issues.
  reproduction_help_url = ndb.StringProperty(default='')

  # Documentation url.
  documentation_url = ndb.StringProperty(default='')

  # Bug report url.
  bug_report_url = ndb.StringProperty(default='')

  # Platforms that coverage is supported for.
  platform_group_mappings = ndb.TextProperty(default='')

  # More relaxed restrictions: allow CC'ed users and reporters of issues to view
  # testcase details.
  relax_testcase_restrictions = ndb.BooleanProperty(default=False)

  # More relaxed restrictions: allow domain users to access both security and
  # functional bugs.
  relax_security_bug_restrictions = ndb.BooleanProperty(default=False)

  # Coverage reports bucket.
  coverage_reports_bucket = ndb.StringProperty(default='')

  # For GitHub API.
  github_credentials = ndb.StringProperty(default='')

  # For filing issues to GitHub repositories under test.
  oss_fuzz_robot_github_personal_access_token = ndb.StringProperty(default='')

  # Pub/Sub topics for the Predator service.
  predator_crash_topic = ndb.StringProperty(default='')
  predator_result_topic = ndb.StringProperty(default='')

  # Wifi connection information.
  wifi_ssid = ndb.StringProperty(default='')
  wifi_password = ndb.StringProperty(default='')

  # SendGrid config.
  sendgrid_api_key = ndb.StringProperty(default='')
  sendgrid_sender = ndb.StringProperty(default='')


class TestcaseUploadMetadata(Model):
  """Metadata associated with a user uploaded test case."""
  # Timestamp.
  timestamp = ndb.DateTimeProperty()

  # Testcase filename.
  filename = ndb.StringProperty()

  # Current status of the testcase.
  status = ndb.StringProperty()

  # Uploader email address.
  uploader_email = ndb.StringProperty()

  # Name of the bot that ran analyze on this testcase.
  bot_name = ndb.StringProperty()

  # Id of the associated testcase.
  testcase_id = ndb.IntegerProperty()

  # Id of the testcase that this is marked as a duplicate of.
  duplicate_of = ndb.IntegerProperty()

  # Blobstore key for the testcase associated with this object.
  blobstore_key = ndb.StringProperty()

  # Testcase timeout.
  timeout = ndb.IntegerProperty()

  # Is this a single testcase bundled in an archive?
  bundled = ndb.BooleanProperty()

  # Path to the file in the archive.
  path_in_archive = ndb.TextProperty()

  # Original blobstore key for this object (used for archives).
  original_blobstore_key = ndb.StringProperty()

  # Security flag.
  security_flag = ndb.BooleanProperty(default=False)

  # Number of retries for this testcase.
  retries = ndb.IntegerProperty()

  # Flag to indicate where bug title should be updated or not.
  bug_summary_update_flag = ndb.BooleanProperty()

  # Flag to indicate if we are running in quiet mode (e.g. bug updates).
  quiet_flag = ndb.BooleanProperty()

  # Additional testcase metadata dict stored as a string.
  additional_metadata_string = ndb.TextProperty(indexed=False)

  # Specified issue id.
  bug_information = ndb.StringProperty()


class JobTemplate(Model):
  # Job template name.
  name = ndb.StringProperty()

  # Environment string.
  environment_string = ndb.TextProperty()


class Job(Model):
  """Definition of a job type used by the bots."""

  VALID_NAME_REGEX = NAME_CHECK_REGEX

  # Job type name.
  name = ndb.StringProperty()

  # Job environment string.
  environment_string = ndb.TextProperty()

  # The platform that this job can run on.
  platform = ndb.StringProperty()

  # Blobstore key of the custom binary for this job.
  custom_binary_key = ndb.StringProperty()

  # Filename for the custom binary.
  custom_binary_filename = ndb.StringProperty()

  # Revision of the custom binary.
  custom_binary_revision = ndb.IntegerProperty()

  # Description of the job.
  description = ndb.TextProperty()

  # Template to use, if any.
  templates = ndb.StringProperty(repeated=True)

  # Project name.
  project = ndb.StringProperty()

  # Keywords is used for searching.
  keywords = ndb.StringProperty(repeated=True)

  # If this is set, this Job is for an external reproduction infrastructure. The
  # value here is the topic used for reproduction requests.
  external_reproduction_topic = ndb.StringProperty()

  # If this is set, this Job is for an external reproduction infrastructure. The
  # value here is the subscription used for receiving reproduction updates.
  external_updates_subscription = ndb.StringProperty()

  def is_external(self):
    """Whether this job is external."""
    return (bool(self.external_reproduction_topic) or
            bool(self.external_updates_subscription))

  def get_environment(self):
    """Get the environment as a dict for this job, including any environment
    variables in its template."""
    if not self.templates:
      return environment.parse_environment_definition(self.environment_string)

    job_environment = {}
    for template_name in self.templates:
      template = JobTemplate.query(JobTemplate.name == template_name).get()
      if not template:
        continue

      template_environment = environment.parse_environment_definition(
          template.environment_string)

      job_environment.update(template_environment)

    environment_overrides = environment.parse_environment_definition(
        self.environment_string)

    job_environment.update(environment_overrides)
    return job_environment

  def get_environment_string(self):
    """Get the environment string for this job, including any environment
    variables in its template. Avoid using this if possible."""
    environment_string = ''
    job_environment = self.get_environment()
    for key, value in job_environment.items():
      environment_string += f'{key} = {value}\n'

    return environment_string

  def populate_indices(self):
    """Populate keywords for fast job searching."""
    self.keywords = list(
        search_tokenizer.tokenize(self.name)
        | search_tokenizer.tokenize(self.project))

  def _pre_put_hook(self):
    """Pre-put hook."""
    self.project = self.get_environment().get('PROJECT_NAME',
                                              utils.default_project_name())
    self.populate_indices()


class CSRFToken(Model):
  """Token used to prevent CSRF attacks."""
  # Value of this token.
  value = ndb.StringProperty()

  # Expiration time for this token.
  expiration_time = ndb.DateTimeProperty()

  # User that this token is associated with.
  user_email = ndb.StringProperty()


class Heartbeat(Model):
  """Bot health metadata."""
  # Name of the bot.
  bot_name = ndb.StringProperty()

  # Time of the last heartbeat.
  last_beat_time = ndb.DateTimeProperty()

  # Task payload containing information on current task execution.
  task_payload = ndb.StringProperty()

  # Expected end time for task.
  task_end_time = ndb.DateTimeProperty()

  # Source version (for accountability).
  source_version = ndb.StringProperty()

  # Platform id (esp important for Android platform for OS version).
  platform_id = ndb.StringProperty()

  # Keywords is used for searching.
  keywords = ndb.StringProperty(repeated=True)

  def populate_indices(self):
    """Populate keywords for fast job searching."""
    self.keywords = list(
        search_tokenizer.tokenize(self.bot_name)
        | search_tokenizer.tokenize(self.task_payload))

  def _pre_put_hook(self):
    """Pre-put hook."""
    self.populate_indices()


class Notification(Model):
  """Tracks whether or not an email has been sent to a user for a test case."""
  # Testcase id associated with this notification.
  testcase_id = ndb.IntegerProperty()

  # User that this notification was sent to.
  user_email = ndb.StringProperty()


class BundledArchiveMetadata(Model):
  """Metadata needed for multiple test cases uploaded in an archive."""
  # Blobstore key of the archive.
  blobstore_key = ndb.StringProperty()

  # Timeout in seconds for each testcase in the bundle.
  timeout = ndb.IntegerProperty()

  # Job queue for the analyze tasks created for this bundle.
  job_queue = ndb.StringProperty()

  # Job type that should be used for all testcases in this bundle.
  job_type = ndb.StringProperty()

  # Flag indicating whether or not these testcases need http.
  http_flag = ndb.BooleanProperty()

  # File name of the uploaded archive.
  archive_filename = ndb.StringProperty()

  # Email address of the uploader of the archive.
  uploader_email = ndb.StringProperty()

  # Fake user interaction sequences like key clicks, mouse movements, etc.
  gestures = ndb.StringProperty(repeated=True)

  # Optional. Revision that we discovered the crash in.
  crash_revision = ndb.IntegerProperty()

  # Optional. Additional arguments.
  additional_arguments = ndb.StringProperty()

  # Optional. Bug information.
  bug_information = ndb.StringProperty()

  # Optional. Platform id, e.g. android:shamu.
  platform_id = ndb.StringProperty()

  # Optional. App launch command. e.g. shell am start ...
  app_launch_command = ndb.StringProperty()

  # Fuzzer name.
  fuzzer_name = ndb.StringProperty()

  # Overridden fuzzer name because actual fuzzer name can be different in many
  # scenarios (libfuzzer, afl, etc).
  overridden_fuzzer_name = ndb.StringProperty()

  # Binary name for fuzz target (only applicable to libFuzzer, AFL).
  fuzzer_binary_name = ndb.StringProperty()


class TaskStatus(Model):
  """Information about task status."""
  # Bot name.
  bot_name = ndb.StringProperty()

  # Status.
  status = ndb.StringProperty()

  # Time of creation or last update time.
  time = ndb.DateTimeProperty()


class BuildMetadata(Model):
  """Metadata associated with a particular archived build."""
  # Job type that this build belongs to.
  job_type = ndb.StringProperty()

  # Revision of the build.
  revision = ndb.IntegerProperty()

  # Good build or bad build.
  bad_build = ndb.BooleanProperty(default=False)

  # Stdout and stderr.
  console_output = ndb.TextProperty()

  # Bot name.
  bot_name = ndb.StringProperty()

  # Symbol data.
  symbols = ndb.StringProperty()

  # Creation timestamp.
  timestamp = ndb.DateTimeProperty()


class ReportMetadata(Model):
  """Metadata associated with a crash report."""
  # Job type from testcase.
  job_type = ndb.StringProperty()

  # Revision of build from report.
  crash_revision = ndb.IntegerProperty(default=-1)

  # Has this report been successfully uploaded?
  is_uploaded = ndb.BooleanProperty(default=False)

  # Product.
  product = ndb.StringProperty(default='')

  # Version.
  version = ndb.TextProperty(default='')

  # Key to minidump previously written to blobstore.
  minidump_key = ndb.TextProperty(default='')

  # Processed crash bytes.
  serialized_crash_stack_frames = ndb.BlobProperty(default='', indexed=False)

  # Id of the associated testcase.
  testcase_id = ndb.StringProperty(default='')

  # Id of the associated bot.
  bot_id = ndb.TextProperty(default='')

  # Optional upload params, stored as a JSON object.
  optional_params = ndb.TextProperty(indexed=False)

  # Report id from crash/.
  crash_report_id = ndb.StringProperty()


class Lock(Model):
  """Lock entity."""
  # Expiration time for the lock.
  expiration_time = ndb.DateTimeProperty()

  # The bot name denoting the holder of the lock.
  holder = ndb.StringProperty()


class FuzzTarget(Model):
  """Fuzz target."""
  # The engine this target is a child of.
  engine = ndb.StringProperty()

  # Project name.
  project = ndb.StringProperty()

  # Binary name.
  binary = ndb.StringProperty()

  def _pre_put_hook(self):
    """Pre-put hook."""
    self.key = ndb.Key(FuzzTarget, self.fully_qualified_name())

  def fully_qualified_name(self):
    """Get the fully qualified name for this fuzz target."""
    return fuzz_target_fully_qualified_name(self.engine, self.project,
                                            self.binary)

  def project_qualified_name(self):
    """Get the name qualified by project."""
    return fuzz_target_project_qualified_name(self.project, self.binary)


def fuzz_target_fully_qualified_name(engine, project, binary):
  """Get a fuzz target's fully qualified name."""
  return engine + '_' + fuzz_target_project_qualified_name(project, binary)


def normalized_name(name):
  """Return normalized name with special chars like slash, colon, etc normalized
  to hyphen(-). This is important as otherwise these chars break local and cloud
  storage paths."""
  return SPECIAL_CHARS_REGEX.sub('-', name).strip('-')


def fuzz_target_project_qualified_name(project, binary):
  """Get a fuzz target's project qualified name."""
  binary = normalized_name(binary)
  if not project:
    return binary

  if project == utils.default_project_name():
    # Don't prefix with project name if it's the default project.
    return binary

  normalized_project_prefix = normalized_name(project) + '_'
  if binary.startswith(normalized_project_prefix):
    return binary

  return normalized_project_prefix + binary


class FuzzTargetsCount(Model):
  """Fuzz targets count for every job. Key IDs are the job name."""
  count = ndb.IntegerProperty(indexed=False)


class FuzzTargetJob(Model):
  """Mapping between fuzz target and jobs with additional metadata for
  selection."""
  # Fully qualified fuzz target name.
  fuzz_target_name = ndb.StringProperty()

  # Job this target ran as.
  job = ndb.StringProperty()

  # Engine this ran as.
  engine = ndb.StringProperty()

  # Relative frequency with which to select this fuzzer.
  weight = ndb.FloatProperty(default=1.0)

  # Approximate last time this target was run.
  last_run = ndb.DateTimeProperty()

  def _pre_put_hook(self):
    """Pre-put hook."""
    self.key = ndb.Key(FuzzTargetJob,
                       fuzz_target_job_key(self.fuzz_target_name, self.job))


class FuzzStrategyProbability(Model):
  """Mapping between fuzz strategies and probabilities with which they
  should be selected."""

  strategy_name = ndb.StringProperty()
  probability = ndb.FloatProperty()
  engine = ndb.StringProperty()


def fuzz_target_job_key(fuzz_target_name, job):
  """Return the key for FuzzTargetJob."""
  return f'{fuzz_target_name}/{job}'


class ExternalUserPermission(Model):
  """Permissions for external users."""
  # Email user is authenticated as.
  email = ndb.StringProperty()

  # Type of |entity_name|. Can be one of the values of PermissionEntityKind.
  entity_kind = ndb.IntegerProperty()

  # Name of the entity that user is allowed to view.
  entity_name = ndb.StringProperty()

  # Whether or not |allowed_name| is a prefix.
  is_prefix = ndb.BooleanProperty(default=False)

  # Auto CC type.
  auto_cc = ndb.IntegerProperty()


class FiledBug(Model):
  """Metadata information for issues that were filed automatically."""
  # Timestamp when the issue was filed.
  timestamp = ndb.DateTimeProperty()

  # ID of the test case that is associated with the filed issue.
  testcase_id = ndb.IntegerProperty()

  # Tracking issue tracker bug for this testcase.
  bug_information = ndb.IntegerProperty(default=0)

  # Group ID associated with this issue.
  group_id = ndb.IntegerProperty()

  # Crash type for easy reference.
  crash_type = ndb.StringProperty()

  # Crash state for easy reference.
  crash_state = ndb.StringProperty()

  # Is it a security bug?
  security_flag = ndb.BooleanProperty()

  # Platform id.
  platform_id = ndb.StringProperty()

  # Project name that is associated with the filed issue.
  project_name = ndb.StringProperty()

  # Job type that is associated with the filed issue.
  job_type = ndb.StringProperty()


class CoverageInformation(Model):
  """Coverage info."""
  date = ndb.DateProperty(auto_now_add=True)
  fuzzer = ndb.StringProperty()

  # Function coverage information.
  functions_covered = ndb.IntegerProperty()
  functions_total = ndb.IntegerProperty()

  # Edge coverage information.
  edges_covered = ndb.IntegerProperty()
  edges_total = ndb.IntegerProperty()

  # Corpus size information.
  corpus_size_units = ndb.IntegerProperty()
  corpus_size_bytes = ndb.IntegerProperty()
  corpus_location = ndb.StringProperty()

  # Corpus backup information.
  corpus_backup_location = ndb.StringProperty()

  # Quarantine size information.
  quarantine_size_units = ndb.IntegerProperty()
  quarantine_size_bytes = ndb.IntegerProperty()
  quarantine_location = ndb.StringProperty()

  # Link to the HTML report.
  html_report_url = ndb.StringProperty()

  def _pre_put_hook(self):
    """Pre-put hook."""
    self.key = ndb.Key(CoverageInformation,
                       coverage_information_key(self.fuzzer, self.date))


def coverage_information_date_to_string(date):
  """Returns string representation of the date in a format used for coverage."""
  return date.strftime(COVERAGE_INFORMATION_DATE_FORMAT)


def coverage_information_key(project_qualified_fuzzer_name, date):
  """Constructs an ndb key for CoverageInformation entity."""
  date_string = coverage_information_date_to_string(date)
  return project_qualified_fuzzer_name + '-' + date_string


class Trial(Model):
  """Trials for specific binaries."""
  # App name that this trial is applied to. E.g. "d8" or "chrome".
  app_name = ndb.StringProperty()

  # Chance to select this set of arguments. Zero to one.
  probability = ndb.FloatProperty()

  # Additional arguments to apply if selected.
  app_args = ndb.TextProperty()

  # Flags that contradict the app args.
  contradicts = ndb.StringProperty(repeated=True)


# TODO(ochang): Make this generic.
class OssFuzzProject(Model):
  """Represents a project that has been set up for OSS-Fuzz."""
  # Name of the project.
  name = ndb.StringProperty()

  # Whether or not the project should run on high end hosts.
  high_end = ndb.BooleanProperty(default=False)

  # Weight for CPU distribution. This is set by admins.
  cpu_weight = ndb.FloatProperty(default=1.0)

  # The disk size to use (overrides the default).
  disk_size_gb = ndb.IntegerProperty()

  # Service account for this project.
  service_account = ndb.StringProperty()

  # CCs for the project.
  ccs = ndb.StringProperty(repeated=True)


class OssFuzzProjectInfo(Model):
  """Set up information for a project (cpu allocation, instance groups, service
  accounts)."""

  class ClusterInfo(Model):
    """Cpu allocation information for a project in a zone."""
    # The cluster for the CPU allocation.
    cluster = ndb.StringProperty()

    # The number of allocated CPUs in this cluster.
    cpu_count = ndb.IntegerProperty(default=0)

    # The GCE zone for this cluster.
    gce_zone = ndb.StringProperty()

  # Name of the project.
  name = ndb.StringProperty()

  # Information about CPUs in each cluster.
  clusters = ndb.StructuredProperty(ClusterInfo, repeated=True)

  def get_cluster_info(self, name):
    return next((info for info in self.clusters if info.cluster == name), None)


class HostWorkerAssignment(Model):
  """Host worker assignment information."""
  # The host instance name.
  host_name = ndb.StringProperty()

  # The instance number (0 to WORKERS_PER_HOST - 1).
  instance_num = ndb.IntegerProperty()

  # The worker instance name.
  worker_name = ndb.StringProperty()

  # The project name.
  project_name = ndb.StringProperty()


class WorkerTlsCert(Model):
  """TLS certs for untrusted workers."""
  # The name of the project.
  project_name = ndb.StringProperty()

  # The contents of the TLS cert.
  cert_contents = ndb.BlobProperty()

  # The contents of the private key.
  key_contents = ndb.BlobProperty()


class FuzzerJob(Model):
  """Mapping between a fuzzer and job with additional metadata for selection."""
  fuzzer = ndb.StringProperty()
  job = ndb.StringProperty()
  platform = ndb.StringProperty()
  weight = ndb.FloatProperty(default=1.0)
  multiplier = ndb.FloatProperty(default=1.0)

  @property
  def actual_weight(self):
    """Get the actual weight for this job."""
    return self.weight * self.multiplier


class FuzzerJobs(Model):
  """(Batched) mappings between a fuzzer and jobs with additional metadata for
  selection."""
  platform = ndb.StringProperty()
  fuzzer_jobs = ndb.LocalStructuredProperty(FuzzerJob, repeated=True)


class OssFuzzBuildFailure(Model):
  """Represents build failure."""
  # Project name.
  project_name = ndb.StringProperty()

  # The monorail issue ID for the failure.
  issue_id = ndb.StringProperty()

  # The last timestamp of the build.
  last_checked_timestamp = ndb.DateTimeProperty()

  # Number of consecutive failures.
  consecutive_failures = ndb.IntegerProperty(default=0)

  # Build type (fuzzing, coverage, etc).
  build_type = ndb.StringProperty()


class Admin(Model):
  """Records an admin user."""
  email = ndb.StringProperty()


class TestcaseVariant(Model):
  """Represent a testcase variant on another job (another platform / sanitizer
  / config)."""
  # Testcase ID of the testcase for which the variant is being evaluated.
  testcase_id = ndb.IntegerProperty()

  # Status of the testcase variant (pending, reproducible, unreproducible, etc).
  status = ndb.IntegerProperty(default=0)

  # Job type for the testcase variant.
  job_type = ndb.StringProperty()

  # Revision that the testcase variant was tried against.
  revision = ndb.IntegerProperty()

  # Crash type.
  crash_type = ndb.StringProperty()

  # Crash state.
  crash_state = ndb.StringProperty()

  # Bool to indicate if it is a security bug?
  security_flag = ndb.BooleanProperty()

  # Bool to indicate if crash is similar to original testcase.
  is_similar = ndb.BooleanProperty()

  # Similar testcase reproducer key (optional). This is set in case we notice a
  # similar crash on another platform.
  reproducer_key = ndb.StringProperty()

  # Platform (e.g. windows, linux, android).
  platform = ndb.StringProperty()
