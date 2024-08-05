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
"""Helper module for fuzz_task that tracks fuzzing time."""
import time

from clusterfuzz._internal.metrics import monitoring_metrics


class TrackFuzzTime:
  """Track the actual fuzzing time (e.g. excluding preparing binary)."""

  def __init__(self, fuzzer_name, job_type, time_module=time):
    self.fuzzer_name = fuzzer_name
    self.job_type = job_type
    self.time = time_module

  def __enter__(self):
    self.start_time = self.time.time()
    self.timeout = False
    return self

  def __exit__(self, exc_type, value, traceback):
    duration = self.time.time() - self.start_time
    monitoring_metrics.FUZZER_TOTAL_FUZZ_TIME.increment_by(
        int(duration), {
            'fuzzer': self.fuzzer_name,
            'timeout': self.timeout
        })
    monitoring_metrics.JOB_TOTAL_FUZZ_TIME.increment_by(
        int(duration), {
            'job': self.job_type,
            'timeout': self.timeout
        })


def track_fuzzer_run_result(fuzzer_name, generated_testcase_count,
                            expected_testcase_count, return_code):
  """Tracks fuzzer run result."""
  if expected_testcase_count > 0:
    ratio = float(generated_testcase_count) / expected_testcase_count
    monitoring_metrics.FUZZER_TESTCASE_COUNT_RATIO.add(ratio,
                                                       {'fuzzer': fuzzer_name})

  def clamp(val, minimum, maximum):
    return max(minimum, min(maximum, val))

  # Clamp return code to max, min int 32-bit, otherwise it can get detected as
  # type long and we will exception out in infra_libs parsing pipeline.
  min_int32 = -(2**31)
  max_int32 = 2**31 - 1

  return_code = int(clamp(return_code, min_int32, max_int32))

  monitoring_metrics.FUZZER_RETURN_CODE_COUNT.increment({
      'fuzzer': fuzzer_name,
      'return_code': return_code,
  })


def track_build_run_result(job_type, _, is_bad_build):
  """Track build run result."""
  # FIXME: Add support for |crash_revision| as part of state.
  monitoring_metrics.JOB_BAD_BUILD_COUNT.increment({
      'job': job_type,
      'bad_build': is_bad_build
  })


def track_testcase_run_result(fuzzer, job_type, new_crash_count,
                              known_crash_count):
  """Track testcase run result."""
  monitoring_metrics.FUZZER_KNOWN_CRASH_COUNT.increment_by(
      known_crash_count, {
          'fuzzer': fuzzer,
      })
  monitoring_metrics.FUZZER_NEW_CRASH_COUNT.increment_by(
      new_crash_count, {
          'fuzzer': fuzzer,
      })
  monitoring_metrics.JOB_KNOWN_CRASH_COUNT.increment_by(known_crash_count, {
      'job': job_type,
  })
  monitoring_metrics.JOB_NEW_CRASH_COUNT.increment_by(new_crash_count, {
      'job': job_type,
  })
