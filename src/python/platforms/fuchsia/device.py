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
"""Helper functions for running commands on Fuchsia devices."""

# TODO(mbarbella): Re-enable this check once functions below are implemented.
# pylint: disable=unused-argument


def get_application_launch_command(arguments, testcase_path):
  """Prepare a command to run on the host to launch on the device."""
  # TODO(mbarbella): Implement this.
  return ''


def reset_state():
  """Reset the device to a clean state."""
  # TODO(mbarbella): Implement this.


def run_command(command_line, timeout):
  """Run the desired command on the device."""
  # TODO(mbarbella): Implement this.


def clear_testcase_directory():
  """Delete test cases stored on the device."""
  # TODO(mbarbella): Implement this.


def copy_testcase_to_device(testcase_path):
  """Copy a file to the device's test case directory."""
  # TODO(mbarbella): Implement this.
