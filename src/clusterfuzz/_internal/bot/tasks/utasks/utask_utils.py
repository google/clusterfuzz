# Copyright 2023 Google LLC
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
"""Module providing utilities for utask users. This module should not depend on
any other module in tasks to prevent circular imports."""


def get_command_from_module(full_module_name):
  module_name = full_module_name.split('.')[-1]
  if not module_name.endswith('_task'):
    raise ValueError(f'{full_module_name} is not a real command')
  return module_name[:-len('_task')]
