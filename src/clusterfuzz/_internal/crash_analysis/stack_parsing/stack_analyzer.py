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
"""Stack analyzer module."""

from clusterfuzz import stacktraces
from clusterfuzz._internal.config import local_config
from clusterfuzz._internal.platforms.android import \
    kernel_utils as android_kernel
from clusterfuzz._internal.platforms.linux.lkl import kernel_utils as lkl_kernel
from clusterfuzz._internal.system import environment

MAX_REDZONE_SIZE_FOR_OOMS_AND_HANGS = 64


def linkify_kernel_or_lkl_stacktrace_if_needed(crash_info):
  """Linkify Android Kernel or lkl stacktrace."""
  kernel_prefix = ''
  kernel_hash = ''
  if (environment.is_android_kernel() and
      not environment.is_android_cuttlefish() and
      (crash_info.found_android_kernel_crash or crash_info.is_kasan)):
    kernel_prefix, kernel_hash = \
      android_kernel.get_kernel_prefix_and_full_hash()

  elif (environment.is_lkl_job() and crash_info.is_lkl and
        crash_info.lkl_kernel_build_id):
    kernel_prefix, kernel_hash = \
      lkl_kernel.get_kernel_prefix_and_full_hash(crash_info.lkl_kernel_build_id)

  if kernel_prefix and kernel_hash:
    _linkify_android_kernel_stacktrace(crash_info, kernel_prefix, kernel_hash)


def _linkify_android_kernel_stacktrace(crash_info, kernel_prefix, kernel_hash):
  """Linkify Android Kernel or lkl stacktrace."""
  temp_crash_stacktrace = ''
  for line in crash_info.crash_stacktrace.splitlines():
    temp_crash_stacktrace += android_kernel.get_kernel_stack_frame_link(
        line, kernel_prefix, kernel_hash) + '\n'

  crash_info.crash_stacktrace = temp_crash_stacktrace


def get_crash_data(crash_data,
                   symbolize_flag=True,
                   fuzz_target=None,
                   already_symbolized=False,
                   detect_ooms_and_hangs=None):
  """Get crash parameters from crash data.
  Crash parameters include crash type, address, state and stacktrace.
  If the stacktrace is not already symbolized, we will try to symbolize it
  unless |symbolize| flag is set to False. Symbolized stacktrace will contain
  inline frames, but we do exclude them for purposes of crash state generation
  (helps in testcase deduplication)."""
  # Decide whether to symbolize or not symbolize the input stacktrace.
  # Note that Fuchsia logs are always symbolized.
  if symbolize_flag:
    # Defer imports since stack_symbolizer pulls in a lot of things.
    from clusterfuzz._internal.crash_analysis.stack_parsing import \
        stack_symbolizer
    crash_stacktrace_with_inlines = stack_symbolizer.symbolize_stacktrace(
        crash_data, enable_inline_frames=True)
    crash_stacktrace_without_inlines = stack_symbolizer.symbolize_stacktrace(
        crash_data, enable_inline_frames=False)
  else:
    # We are explicitly indicated to not symbolize using |symbolize_flag|. There
    # is no distinction between inline and non-inline frames for an unsymbolized
    # stacktrace.
    crash_stacktrace_with_inlines = crash_data
    crash_stacktrace_without_inlines = crash_data

  # Additional stack frame ignore regexes.
  custom_stack_frame_ignore_regexes = (
      local_config.ProjectConfig().get('stacktrace.stack_frame_ignore_regexes',
                                       []))

  if environment.get_value('TASK_NAME') == 'analyze':
    detect_v8_runtime_errors = True
  else:
    detect_v8_runtime_errors = environment.get_value('DETECT_V8_RUNTIME_ERRORS',
                                                     False)

  fuzz_target = fuzz_target or environment.get_value('FUZZ_TARGET')
  redzone_size = environment.get_value('REDZONE')
  if detect_ooms_and_hangs is None:
    detect_ooms_and_hangs = (
        environment.get_value('REPORT_OOMS_AND_HANGS') and
        (not redzone_size or
         redzone_size <= MAX_REDZONE_SIZE_FOR_OOMS_AND_HANGS))

  include_ubsan = 'halt_on_error=0' not in environment.get_value(
      'UBSAN_OPTIONS', '')

  stack_parser = stacktraces.StackParser(
      symbolized=symbolize_flag or already_symbolized,
      detect_ooms_and_hangs=detect_ooms_and_hangs,
      detect_v8_runtime_errors=detect_v8_runtime_errors,
      custom_stack_frame_ignore_regexes=custom_stack_frame_ignore_regexes,
      fuzz_target=fuzz_target,
      include_ubsan=include_ubsan)

  result = stack_parser.parse(crash_stacktrace_without_inlines)

  # Use stacktrace with inlines for the result.
  if result.crash_stacktrace:
    result.crash_stacktrace = crash_stacktrace_with_inlines

  # Linkify Android Kernel or lkl stacktrace.
  linkify_kernel_or_lkl_stacktrace_if_needed(result)

  return result
