# Copyright 2025 Google LLC
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
"""Bridge logic for calling the butler reproduce command programmatically."""

from local.butler import reproduce as butler_reproduce

# No environment initialization is needed here anymore, as the new
# run_reproduction function handles it.

def reproduce_testcase_by_id(testcase_id: int, config_dir: str):
  """
  Calls the public reproduction function from the butler script.
  """
  # This now calls the clean, public API we exposed, instead of a
  # private function.
  butler_reproduce.run_reproduction(testcase_id, config_dir)
