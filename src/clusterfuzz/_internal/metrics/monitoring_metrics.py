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
"""Metrics. All metrics should go into this file."""

from clusterfuzz._internal.metrics import monitor

# Fuzz task metrics.
BIG_QUERY_WRITE_COUNT = monitor.CounterMetric(
    'debug/big_query/write_count',
    description='The number of BigQuery writes',
    field_spec=[
        monitor.BooleanField('success'),
    ])

JOB_BAD_BUILD_COUNT = monitor.CounterMetric(
    'task/fuzz/job/bad_build_count',
    description=("Count of fuzz task's bad build count "
                 '(grouped by job type)'),
    field_spec=[
        monitor.StringField('job'),
        monitor.BooleanField('bad_build'),
    ])

JOB_BUILD_AGE = monitor.CumulativeDistributionMetric(
    'job/build_age',
    bucketer=monitor.FixedWidthBucketer(width=0.05, num_finite_buckets=20),
    description=('Distribution of latest build\'s age in hours. '
                 '(grouped by fuzzer/job)'),
    field_spec=[
        monitor.StringField('job'),
        monitor.StringField('platform'),
        monitor.StringField('task'),
    ],
)

JOB_BUILD_RETRIEVAL_TIME = monitor.CumulativeDistributionMetric(
    'task/build_retrieval_time',
    bucketer=monitor.FixedWidthBucketer(width=0.05, num_finite_buckets=20),
    description=('Distribution of fuzz task\'s build retrieval times. '
                 '(grouped by fuzzer/job)'),
    field_spec=[
        monitor.StringField('job'),
        monitor.StringField('step'),
        monitor.StringField('platform'),
        monitor.StringField('build_type'),
    ],
)

FUZZER_KNOWN_CRASH_COUNT = monitor.CounterMetric(
    'task/fuzz/fuzzer/known_crash_count',
    description=('Count of fuzz task\'s known crash count '
                 '(grouped by fuzzer)'),
    field_spec=[
        monitor.StringField('fuzzer'),
        monitor.StringField('platform'),
    ])

FUZZER_NEW_CRASH_COUNT = monitor.CounterMetric(
    'task/fuzz/fuzzer/new_crash_count',
    description=('Count of fuzz task\'s new crash count '
                 '(grouped by fuzzer)'),
    field_spec=[
        monitor.StringField('fuzzer'),
        monitor.StringField('platform'),
    ])

JOB_KNOWN_CRASH_COUNT = monitor.CounterMetric(
    'task/fuzz/job/known_crash_count',
    description=('Count of fuzz task\'s known crash count '
                 '(grouped by job)'),
    field_spec=[
        monitor.StringField('job'),
        monitor.StringField('platform'),
    ])

JOB_NEW_CRASH_COUNT = monitor.CounterMetric(
    'task/fuzz/job/new_crash_count',
    description=('Count of fuzz task\'s new crash count '
                 '(grouped by job)'),
    field_spec=[
        monitor.StringField('job'),
        monitor.StringField('platform'),
    ])

FUZZER_RETURN_CODE_COUNT = monitor.CounterMetric(
    'task/fuzz/fuzzer/return_code_count',
    description=("Count of fuzz task's return codes "
                 '(grouped by fuzzer)'),
    field_spec=[
        monitor.StringField('fuzzer'),
        monitor.IntegerField('return_code'),
        monitor.StringField('platform'),
        monitor.StringField('job'),
    ],
)

FUZZER_TOTAL_FUZZ_TIME = monitor.CounterMetric(
    'task/fuzz/fuzzer/total_time',
    description=('The total fuzz time in seconds '
                 '(grouped by fuzzer)'),
    field_spec=[
        monitor.StringField('fuzzer'),
        monitor.BooleanField('timeout'),
        monitor.StringField('platform'),
    ],
)

# This metric tracks fuzzer setup and data bundle update,
# fuzzing time and the time to upload results to datastore
FUZZING_SESSION_DURATION = monitor.CumulativeDistributionMetric(
    'task/fuzz/session/duration',
    bucketer=monitor.FixedWidthBucketer(width=0.05, num_finite_buckets=20),
    description=('Total duration of fuzzing session.'),
    field_spec=[
        monitor.StringField('fuzzer'),
        monitor.StringField('job'),
        monitor.StringField('platform'),
    ],
)

JOB_TOTAL_FUZZ_TIME = monitor.CounterMetric(
    'task/fuzz/job/total_time',
    description=('The total fuzz time in seconds '
                 '(grouped by job)'),
    field_spec=[
        monitor.StringField('job'),
        monitor.BooleanField('timeout'),
        monitor.StringField('platform'),
    ],
)

FUZZER_TESTCASE_COUNT_RATIO = monitor.CumulativeDistributionMetric(
    'task/fuzz/fuzzer/testcase_count_ratio',
    bucketer=monitor.FixedWidthBucketer(width=0.05, num_finite_buckets=20),
    description=('Distribution of fuzz task\'s generated testcase '
                 'counts divided by expected testcase counts '
                 '(grouped by fuzzers)'),
    field_spec=[
        monitor.StringField('fuzzer'),
    ],
)

# Global error count.
LOG_ERROR_COUNT = monitor.CounterMetric(
    'errors/count',
    description='Error count.',
    field_spec=[
        monitor.StringField('task_name'),
    ])

# Untrusted host metrics.
HOST_INCONSISTENT_COUNT = monitor.CounterMetric(
    'untrusted_runner/host/inconsistent_count',
    description='Inconsistent worker state count.',
    field_spec=None)

HOST_ERROR_COUNT = monitor.CounterMetric(
    'untrusted_runner/host/error_count',
    description='Error count.',
    field_spec=[
        monitor.IntegerField('return_code'),
    ])

TRY_COUNT = monitor.CounterMetric(
    'utils/retry/count',
    description='Success/Failure count when utils.retry fails',
    field_spec=[
        monitor.StringField('function'),
        monitor.BooleanField('is_succeeded'),
    ])

BOT_COUNT = monitor.GaugeMetric(
    'bot_count',
    description='Bot count',
    field_spec=[
        monitor.StringField('revision'),
        monitor.StringField('os_type'),
        monitor.StringField('release'),
        monitor.StringField('os_version')
    ])

TASK_COUNT = monitor.CounterMetric(
    'task/count',
    description='The number of started tasks',
    field_spec=[
        monitor.StringField('task'),
        monitor.StringField('job'),
    ])

TASK_TOTAL_RUN_TIME = monitor.CounterMetric(
    'task/total_time',
    description=('The task run time in seconds'),
    field_spec=[
        monitor.StringField('task'),
        monitor.StringField('job'),
    ],
)

TESTCASE_UPLOAD_TRIAGE_DURATION = monitor.CumulativeDistributionMetric(
    'uploaded_testcase_analysis/triage_duration_secs',
    description=('Time elapsed between testcase upload and completion'
                 ' of relevant tasks in the testcase upload lifecycle.'),
    bucketer=monitor.GeometricBucketer(),
    field_spec=[
        monitor.StringField('step'),
        monitor.StringField('job'),
    ],
)
TASK_RATE_LIMIT_COUNT = monitor.CounterMetric(
    'task/rate_limit',
    description=('Counter for rate limit events.'),
    field_spec=[
        monitor.StringField('task'),
        monitor.StringField('job'),
        monitor.StringField('argument'),
    ])

UTASK_SUBTASK_E2E_DURATION_SECS = monitor.CumulativeDistributionMetric(
    'utask/subtask_e2e_duration_secs',
    description=(
        'Time elapsed since preprocess started for this task, in ' +
        'seconds, per subtask ("preprocess", "uworker_main" and ' +
        '"postprocess"). Subtask "postprocess" being the last, that ' +
        'measures total e2e task duration. Mode is either "batch" or ' +
        '"queue" depending on whether uworker_main was scheduled and ' +
        'executed on Cloud Batch or not, respectively.'),
    bucketer=monitor.GeometricBucketer(),
    field_spec=[
        monitor.StringField('task'),
        monitor.StringField('job'),
        monitor.StringField('subtask'),
        monitor.StringField('mode'),
        monitor.StringField('platform'),
    ],
)

UTASK_SUBTASK_DURATION_SECS = monitor.CumulativeDistributionMetric(
    'utask/subtask_duration_secs',
    description=(
        'Duration of each subtask ("preprocess", "uworker_main" and ' +
        '"postprocess"). Mode is either "batch" or "queue" depending on ' +
        'whether uworker_main was scheduled and executed on Cloud Batch or ' +
        'not, respectively.'),
    bucketer=monitor.GeometricBucketer(),
    field_spec=[
        monitor.StringField('task'),
        monitor.StringField('job'),
        monitor.StringField('subtask'),
        monitor.StringField('mode'),
        monitor.StringField('platform'),
    ],
)

ANDROID_UPTIME = monitor.CounterMetric(
    'android_device_uptime',
    description='Android device uptime',
    field_spec=[
        monitor.StringField('serial'),
        monitor.StringField('platform'),
    ],
)

CHROME_TEST_SYNCER_SUCCESS = monitor.CounterMetric(
    'chrome_test_syncer_success',
    description='Counter for successful test syncer exits.',
    field_spec=[],
)

# Metrics related to issue lifecycle

ISSUE_FILING = monitor.CounterMetric(
    'issues/filing',
    description='Bugs opened through triage task.',
    field_spec=[
        monitor.StringField('fuzzer_name'),
        monitor.StringField('status'),
    ])

ISSUE_CLOSING = monitor.CounterMetric(
    'issues/closing/success',
    description='Bugs closed during cleanup task.',
    field_spec=[
        monitor.StringField('fuzzer_name'),
        monitor.StringField('status'),
    ])

UNTRIAGED_TESTCASE_AGE = monitor.CumulativeDistributionMetric(
    'issues/untriaged_testcase_age',
    description='Age of testcases that were not yet triaged '
    '(have not yet completed analyze, regression,'
    ' minimization, impact task), in seconds.',
    bucketer=monitor.GeometricBucketer(),
    field_spec=[
        monitor.StringField('job'),
        monitor.StringField('platform'),
    ])

ANALYZE_TASK_REPRODUCIBILITY = monitor.CounterMetric(
    'task/analyze/reproducibility',
    description='Outcome count for analyze task.',
    field_spec=[
        monitor.StringField('job'),
        monitor.StringField('fuzzer_name'),
        monitor.BooleanField('reproducible'),
        monitor.BooleanField('crashes'),
    ])
