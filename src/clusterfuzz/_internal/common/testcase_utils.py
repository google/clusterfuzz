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
"""Holds helpers for reuse across different tasks."""

import datetime
import os
from typing import Optional

from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.metrics import monitoring_metrics

TESTCASE_TRIAGE_DURATION_ANALYZE_LAUNCHED_STEP = 'analyze_launched'
TESTCASE_TRIAGE_DURATION_IMPACT_COMPLETED_STEP = 'impact_completed'
TESTCASE_TRIAGE_DURATION_ANALYZE_COMPLETED_STEP = 'analyze_completed'
TESTCASE_TRIAGE_DURATION_MINIMIZE_COMPLETED_STEP = 'minimize_completed'
TESTCASE_TRIAGE_DURATION_REGRESSION_COMPLETED_STEP = 'regression_completed'
TESTCASE_TRIAGE_DURATION_ISSUE_UPDATED_STEP = 'issue_updated'


def emit_testcase_triage_duration_metric(testcase_id: int, step: str):
  '''Finds out if a testcase is fuzzer generated or manually uploaded,
      and emits the TESTCASE_UPLOAD_TRIAGE_DURATION metric.'''
  testcase = data_handler.get_testcase_by_id(testcase_id)

  if not testcase:
    logs.warning(f'No testcase found with id {testcase_id},'
                 ' failed to emit TESTCASE_UPLOAD_TRIAGE_DURATION metric.')
    return

  if not testcase.job_type:
    logs.warning(f'No job_type associated to testcase {testcase_id},'
                 ' failed to emit TESTCASE_UPLOAD_TRIAGE_DURATION metric.')
    return

  from_fuzzer = not get_testcase_upload_metadata(testcase_id)

  assert step in [
      'analyze_launched', 'analyze_completed', 'minimize_completed',
      'regression_completed', 'impact_completed', 'issue_updated'
  ]

  if not testcase.get_age_in_seconds():
    logs.warning(f'No timestamp associated to testcase {testcase_id},'
                 ' failed to emit TESTCASE_UPLOAD_TRIAGE_DURATION metric.')
    return

  monitoring_metrics.TESTCASE_UPLOAD_TRIAGE_DURATION.add(
      testcase.get_age_in_seconds(),
      labels={
          'job': testcase.job_type,
          'step': step,
          'origin': 'fuzzer' if from_fuzzer else 'manually_uploaded'
      })


def get_testcase_upload_metadata(
    testcase_id) -> Optional[data_types.TestcaseUploadMetadata]:
  return data_types.TestcaseUploadMetadata.query(
      data_types.TestcaseUploadMetadata.testcase_id == int(testcase_id)).get()
