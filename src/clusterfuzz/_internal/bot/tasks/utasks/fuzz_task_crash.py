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
"""Helper module for fuzz_task crashes"""
import os

from clusterfuzz._internal.protos import uworker_msg_pb2
from clusterfuzz._internal.crash_analysis.stack_parsing import stack_analyzer
from clusterfuzz._internal.base import utils


def get_unsymbolized_crash_stacktrace(stack_file_path):
  """Read unsymbolized crash stacktrace."""
  with open(stack_file_path, 'rb') as f:
    return utils.decode_to_unicode(f.read())


class Crash:
  """Represents a crash (before creating a testcase)."""

  @classmethod
  def from_testcase_manager_crash(cls, crash):
    """Create a Crash from a testcase_manager.Crash."""
    try:
      orig_unsymbolized_crash_stacktrace = (
          get_unsymbolized_crash_stacktrace(crash.stack_file_path))
    except Exception:
      logs.error(
          'Unable to read stacktrace from file %s.' % crash.stack_file_path)
      return None

    # If there are per-testcase additional flags, we need to store them.
    arguments = testcase_manager.get_command_line_flags(crash.file_path)

    needs_http = '-http-' in os.path.basename(crash.file_path)
    application_command_line = (
        testcase_manager.get_command_line_for_application(
            crash.file_path, needs_http=needs_http))

    # TODO(ochang): Remove once all engines are migrated to new pipeline.
    fuzzing_strategies = libfuzzer_stats.LIBFUZZER_FUZZING_STRATEGIES.search(
        orig_unsymbolized_crash_stacktrace)
    if fuzzing_strategies:
      assert len(fuzzing_strategies.groups()) == 1
      fuzzing_strategies_string = fuzzing_strategies.groups()[0]
      fuzzing_strategies = [
          strategy.strip() for strategy in fuzzing_strategies_string.split(',')
      ]

    return Crash(
        file_path=crash.file_path,
        crash_time=crash.crash_time,
        return_code=crash.return_code,
        resource_list=crash.resource_list,
        gestures=crash.gestures,
        unsymbolized_crash_stacktrace=orig_unsymbolized_crash_stacktrace,
        arguments=arguments,
        application_command_line=application_command_line,
        http_flag=needs_http,
        fuzzing_strategies=fuzzing_strategies)

  @classmethod
  def from_engine_crash(cls, crash, fuzzing_strategies):
    """Create a Crash from a engine.Crash."""
    return Crash(
        file_path=crash.input_path,
        crash_time=crash.crash_time,
        return_code=1,
        resource_list=[],
        gestures=[],
        unsymbolized_crash_stacktrace=utils.decode_to_unicode(crash.stacktrace),
        arguments=' '.join(crash.reproduce_args),
        application_command_line='',  # TODO(ochang): Write actual command line.
        http_flag=False,
        fuzzing_strategies=fuzzing_strategies)

  def __init__(self,
               file_path,
               crash_time,
               return_code,
               resource_list,
               gestures,
               unsymbolized_crash_stacktrace,
               arguments,
               application_command_line,
               http_flag=False,
               fuzzing_strategies=None):
    self.file_path = file_path
    self.crash_time = crash_time
    self.return_code = return_code
    self.resource_list = resource_list
    self.gestures = gestures
    self.arguments = arguments
    self.fuzzing_strategies = fuzzing_strategies

    self.security_flag = False
    self.should_be_ignored = False

    self.http_flag = http_flag
    self.application_command_line = application_command_line
    self.unsymbolized_crash_stacktrace = unsymbolized_crash_stacktrace
    state = stack_analyzer.get_crash_data(self.unsymbolized_crash_stacktrace)
    self.crash_type = state.crash_type
    self.crash_address = state.crash_address
    self.crash_state = state.crash_state
    self.crash_stacktrace = utils.get_crash_stacktrace_output(
        self.application_command_line, state.crash_stacktrace,
        self.unsymbolized_crash_stacktrace)
    self.crash_categories = state.crash_categories
    self.security_flag = crash_analyzer.is_security_issue(
        self.unsymbolized_crash_stacktrace, self.crash_type, self.crash_address)
    self.key = '%s,%s,%s' % (self.crash_type, self.crash_state,
                             self.security_flag)
    self.should_be_ignored = crash_analyzer.ignore_stacktrace(
        state.crash_stacktrace)

    # self.crash_info gets populated in create_testcase; save what we need.
    self.crash_frames = state.frames
    self.crash_info = None

  @property
  def filename(self):
    return os.path.basename(self.file_path)

  def is_archived(self):
    """Return true if archive_testcase_in_blobstore(..) was performed."""
    return hasattr(self, 'fuzzed_key')

  def archive_testcase_in_blobstore(self,
                                    upload_url: uworker_msg_pb2.BlobUploadUrl):
    """Calling setup.archive_testcase_and_dependencies_in_gcs(..)
      and hydrate certain attributes. We single out this method because it's
      expensive and we want to do it at the very last minute."""
    if self.is_archived():
      return

    if upload_url.key:
      self.fuzzed_key = upload_url.key
    (self.archived, self.absolute_path, self.archive_filename) = (
        setup.archive_testcase_and_dependencies_in_gcs(
            self.resource_list, self.file_path, upload_url.url))

  def is_valid(self):
    """Return true if the crash is valid for processing."""
    return self.get_error() is None

  def get_error(self):
    """Return the reason why the crash is invalid."""
    filter_functional_bugs = environment.get_value('FILTER_FUNCTIONAL_BUGS')
    if filter_functional_bugs and not self.security_flag:
      return f'Functional crash is ignored: {self.crash_state}'

    if self.should_be_ignored:
      return ('False crash: %s\n\n---%s\n\n---%s' %
              (self.crash_state, self.unsymbolized_crash_stacktrace,
               self.crash_stacktrace))

    if self.is_archived() and not self.fuzzed_key:
      return f'Unable to store testcase in blobstore: {self.crash_state}'

    if not self.crash_state or not self.crash_type:
      return 'Empty crash state or type'

    return None

  def to_proto(self):
    """Converts this object to a proto."""
    is_valid = self.is_valid()
    crash = uworker_msg_pb2.FuzzTaskCrash()
    crash.is_valid = is_valid
    crash.file_path = self.file_path
    crash.crash_time = self.crash_time
    crash.return_code = self.return_code
    crash.resource_list.extend(self.resource_list)
    crash.gestures.extend(self.gestures)
    crash.arguments = self.arguments
    if self.fuzzing_strategies:
      crash.fuzzing_strategies.extend(self.fuzzing_strategies)
    crash.http_flag = self.http_flag
    crash.application_command_line = self.application_command_line
    crash.unsymbolized_crash_stacktrace = self.unsymbolized_crash_stacktrace
    crash.crash_type = self.crash_type
    crash.crash_address = self.crash_address
    crash.crash_state = self.crash_state
    crash.crash_stacktrace = self.crash_stacktrace
    crash.crash_categories.extend(self.crash_categories)
    crash.security_flag = self.security_flag
    crash.key = self.key
    crash.should_be_ignored = self.should_be_ignored
    return crash


def find_main_crash(crashes: List[Crash], full_fuzzer_name: str,
                    test_timeout: int, upload_urls: UploadUrlCollection):
  """Find the first reproducible crash or the first valid crash. And return the
    crash and the one_time_crasher_flag."""
  for crash in crashes:
    # Archiving testcase to blobstore when we need to because it's expensive.
    crash.archive_testcase_in_blobstore(upload_urls.get())

    # We need to check again if the crash is valid. In other words, we check
    # if archiving to blobstore succeeded.
    if not crash.is_valid():
      continue

    # We pass an empty expected crash state since our initial stack from fuzzing
    # can be incomplete. So, make a judgement on reproducibility based on passed
    # security flag and crash state generated from re-running testcase in
    # test_for_reproducibility. Minimize task will later update the new crash
    # type and crash state parameters.
    fuzz_target = data_handler.get_fuzz_target(full_fuzzer_name)
    if testcase_manager.test_for_reproducibility(
        fuzz_target,
        crash.file_path,
        crash.crash_type,
        None,
        crash.security_flag,
        test_timeout,
        crash.http_flag,
        crash.gestures,
        arguments=crash.arguments):
      return crash, False

  # All crashes are non-reproducible. Therefore, we get the first valid one.
  for crash in crashes:
    if crash.is_valid():
      return crash, True

  return None, None


class CrashGroup:
  """Represent a group of identical crashes. The key is
      (crash_type, crash_state, security_flag)."""

  def __init__(self, crashes: List[Crash], context,
               upload_urls: UploadUrlCollection):
    for c in crashes:
      assert crashes[0].crash_type == c.crash_type
      assert crashes[0].crash_state == c.crash_state
      assert crashes[0].security_flag == c.security_flag

    self.crashes = crashes
    if context.fuzz_target:
      fully_qualified_fuzzer_name = context.fuzz_target.fully_qualified_name()
    else:
      fully_qualified_fuzzer_name = context.fuzzer_name

    self.main_crash, self.one_time_crasher_flag = find_main_crash(
        crashes, fully_qualified_fuzzer_name, context.test_timeout, upload_urls)

    self.newly_created_testcase = None


def _should_create_testcase(group: uworker_msg_pb2.FuzzTaskCrashGroup,
                            existing_testcase):
  """Return true if this crash should create a testcase."""
  if not existing_testcase:
    # No existing testcase, should create a new one.
    return True

  if not existing_testcase.one_time_crasher_flag:
    # Existing testcase is reproducible, don't need to create another one.
    return False

  if not group.one_time_crasher_flag:
    # Current testcase is reproducible, where existing one is not. Should
    # create a new one.
    return True

  # Both current and existing testcases are unreproducible, shouldn't create
  # a new testcase.
  # TODO(aarya): We should probably update last tested stacktrace in existing
  # testcase without any race conditions.
  return False


Context = collections.namedtuple('Context', [
    'project_name', 'bot_name', 'job_type', 'fuzz_target', 'redzone',
    'disable_ubsan', 'platform_id', 'crash_revision', 'fuzzer_name',
    'window_argument', 'fuzzer_metadata', 'testcases_metadata',
    'timeout_multiplier', 'test_timeout', 'data_directory'
])


class NoMoreUploadUrlsError(Exception):
  """Error for when we run out upload urls."""


class UploadUrlCollection:
  """Upload URLs collection."""

  def __init__(self, upload_urls: List[uworker_msg_pb2.BlobUploadUrl]):
    self.upload_urls = upload_urls

  def get(self) -> uworker_msg_pb2.BlobUploadUrl:
    if not self.upload_urls:
      raise NoMoreUploadUrlsError

    url = self.upload_urls[0]
    self.upload_urls = self.upload_urls[1:]
    return url


def process_crashes(crashes: List[Crash], context: Context,
                    upload_urls) -> List[uworker_msg_pb2.FuzzTaskCrashGroup]:
  """Process a list of crashes."""

  def key_fn(crash):
    return crash.key

  crash_groups = []

  # Filter invalid crashes.
  crashes = filter_crashes(crashes)
  group_of_crashes = itertools.groupby(sorted(crashes, key=key_fn), key_fn)

  upload_urls = UploadUrlCollection(upload_urls)
  for _, grouped_crashes in group_of_crashes:
    try:
      group = CrashGroup(list(grouped_crashes), context, upload_urls)
    except NoMoreUploadUrlsError:
      # Ignore the remaining crashes.
      logs.error('Ran out of crash upload URLs.')
      break

    # Archiving testcase to blobstore might fail for all crashes within this
    # group.
    if not group.main_crash:
      logs.info('Unable to store testcase in blobstore: %s' %
                group.crashes[0].crash_state)
      continue

    group_proto = uworker_msg_pb2.FuzzTaskCrashGroup(
        context=uworker_msg_pb2.FuzzContext(
            redzone=context.redzone,
            disable_ubsan=context.disable_ubsan,
            window_argument=context.window_argument,
            timeout_multiplier=context.timeout_multiplier,
            test_timeout=int(context.test_timeout),
            fuzzer_metadata=context.fuzzer_metadata,
        ),
        main_crash=group.main_crash.to_proto(),
        crashes=[c.to_proto() for c in group.crashes],
        one_time_crasher_flag=group.one_time_crasher_flag,
    )
    crash_groups.append(group_proto)

    logs.info(f'Process the crash group (file={group.main_crash.filename}, '
              f'fuzzed_key={group.main_crash.fuzzed_key}, '
              f'return code={group.main_crash.return_code}, '
              f'crash time={group.main_crash.crash_time}, '
              f'crash type={group.main_crash.crash_type}, '
              f'crash state={group.main_crash.crash_state}, '
              f'security flag={group.main_crash.security_flag}, '
              f'crash stacktrace={group.main_crash.crash_stacktrace})')
  return crash_groups

