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
"""Performance analyzer constants."""

DISPLAY_COLUMNS = [
    {
        'name': 'type',
        'title': 'Issue type',
        'tooltip': 'Type of issue affecting the fuzz target.'
    },
    {
        'name': 'percent',
        'title': 'Percent runs affected',
        'tooltip': 'Percentage of fuzz target runs impacted by this issue.'
    },
    {
        'name': 'score',
        'title': 'Priority score (experimental)',
        'tooltip': 'Feature indicating the priority of this issue.'
    },
    {
        'name': 'examples',
        'title': 'Log examples',
        'tooltip': 'Sample logs showing this issue.'
    },
    {
        'name': 'solutions',
        'title': 'Recommended solutions',
        'tooltip': 'Possible solutions to fix this issue.'
    },
]

ISSUE_TYPE_SOLUTIONS_MAP = {
    'bad_instrumentation':
        """The fuzz target has been built incorrectly. Fuzzing engine has not
 detected coverage information, so most likely coverage flags (i.e.
 `-fsanitize-coverage`) have not been properly used during compilation.).""",
    'coverage':
        """The fuzz target cannot find new 'interesting' inputs and hence
 unable to cover new code. There are several ways to improve code coverage:<br/>
- Add a new dictionary or update existing ones with new strings.<br/>
- Add new testcases to the corpus (these can be manually generated, used from
 unit tests, valid files, traffic streams, etc depending on the target).<br/>
- Update the target function to use different combinations of flags passed to
 the target.<br/>
- Check `max_len` value, may be it is not appropriate for the target (too big
 for some data which cannot be too big, or too small for some data which
 cannot be too small).""",
    'crash':
        """The fuzz target crashes frequently. You need to fix these crashers
 first so that fuzzing can be efficient and explore new code and crashes.""",
    'leak':
        """The fuzz target is leaking memory often. You need to fix these leaks
 first so that fuzzing can be efficient and not crash on out-of-memory. If these
 leaks are false positives, you can suppress them using LeakSanitizer
 suppressions.""",
    'logging':
        """The fuzz target writes too many log messages (either stdout or
 stderr). Excessive logging is extremely detrimental to efficient fuzzing.
 Most targets support different levels of logging for a target. You need to
 modify the target function or compilation flags to use the lowest level of
 logging verbosity.<br/>
 If target does not provide a way to control logging levels or to disable
 logging in any other possible way, you can use `-close_fd_mask` option of
 libFuzzer.""",
    'none':
        """The fuzz target is working well. No issues were detected.""",
    'oom':
        """The fuzz target hits out-of-memory errors. It may be caused by a
 valid input (e.g. a large array allocation). In that case, you need to
 implement a workaround to avoid generation of such testcases. Or the target
 function could be leaking memory, so you need to fix those memory leak
 crashes.""",
    'slow_unit':
        """The target spends several seconds on a single input. It can a bug in
 the target, so you need to profile whether this is a real bug in the target.
 For some cases, lowering `max_len` option may help to avoid slow units
 (e.g. regexp processing time increases exponentially with larger inputs).""",
    'speed':
        """Execution speed is one of the most important factors for efficient
 fuzzing. You need to optimize the target function so that the execution speed
 is at least 1,000 testcases per second.""",
    'startup_crash':
        """The fuzz target does not work and crashes instantly on startup.
 Compile the fuzz target locally and run it as per the documentation. In most
 cases, fuzz target does not work due to linking errors or due to the bug in
 target itself (i.e. `LLVMFuzzerTestOneInput` function).""",
    'timeout':
        """The fuzz target hits timeout error. Timeout bugs slow down fuzzing
 significantly since fuzz target hangs on the processing of those inputs. You
 need to debug the root cause for the hang and fix it. Possible causes are
 getting stuck on an infinite loop, some complex computation, etc.""",
}

QUERY_COLUMNS = [
    'actual_duration',
    'average_exec_per_sec',
    'bad_instrumentation',
    'crash_count',
    'expected_duration',
    'leak_count',
    'log_lines_from_engine',
    'log_lines_ignored',
    'log_lines_unwanted',
    'new_units_added',
    'new_units_generated',
    'oom_count',
    'slow_units_count',
    'startup_crash_count',
    'strategy_corpus_subset',
    'strategy_random_max_len',
    'strategy_value_profile',
    'timeout_count',
    'timestamp',
]
