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
"""Fuzzer related helper functions."""

from python.base import modules
modules.fix_module_search_paths()

# Import some functions that may be used by existing fuzzers before
# fuzzer_utils was split up.

from fuzzer_utils.tests import create_testcase_list_file
from fuzzer_utils.tests import get_testcases
from fuzzer_utils.tests import is_locked
from fuzzer_utils.tests import is_valid_testcase_file
