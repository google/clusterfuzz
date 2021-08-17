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

FUZZER_KNOWN_CRASH_COUNT = monitor.CounterMetric(
    'task/fuzz/fuzzer/known_crash_count',
    description=('Count of fuzz task\'s known crash count '
                 '(grouped by fuzzer)'),
    field_spec=[
        monitor.StringField('fuzzer'),
    ])

FUZZER_NEW_CRASH_COUNT = monitor.CounterMetric(
    'task/fuzz/fuzzer/new_crash_count',
    description=('Count of fuzz task\'s new crash count '
                 '(grouped by fuzzer)'),
    field_spec=[
        monitor.StringField('fuzzer'),
    ])

JOB_KNOWN_CRASH_COUNT = monitor.CounterMetric(
    'task/fuzz/job/known_crash_count',
    description=('Count of fuzz task\'s known crash count '
                 '(grouped by job)'),
    field_spec=[
        monitor.StringField('job'),
    ])

JOB_NEW_CRASH_COUNT = monitor.CounterMetric(
    'task/fuzz/job/new_crash_count',
    description=('Count of fuzz task\'s new crash count '
                 '(grouped by job)'),
    field_spec=[
        monitor.StringField('job'),
    ])

FUZZER_RETURN_CODE_COUNT = monitor.CounterMetric(
    'task/fuzz/fuzzer/return_code_count',
    description=("Count of fuzz task's return codes "
                 '(grouped by fuzzer)'),
    field_spec=[
        monitor.StringField('fuzzer'),
        monitor.IntegerField('return_code'),
    ],
)

FUZZER_TOTAL_FUZZ_TIME = monitor.CounterMetric(
    'task/fuzz/fuzzer/total_time',
    description=('The total fuzz time in seconds '
                 '(grouped by fuzzer)'),
    field_spec=[
        monitor.StringField('fuzzer'),
        monitor.BooleanField('timeout'),
    ],
)

JOB_TOTAL_FUZZ_TIME = monitor.CounterMetric(
    'task/fuzz/job/total_time',
    description=('The total fuzz time in seconds '
                 '(grouped by job)'),
    field_spec=[
        monitor.StringField('job'),
        monitor.BooleanField('timeout'),
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

# Global log_error count.
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
    field_spec=[monitor.StringField('revision')])

TASK_COUNT = monitor.CounterMetric(
    'task/count',
    description='The number of started tasks',
    field_spec=[
        monitor.StringField('task'),
        monitor.StringField('job'),
    ])
