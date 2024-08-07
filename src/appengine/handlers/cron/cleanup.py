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
"""Cleanup task for cleaning up unneeded testcases."""

from clusterfuzz._internal.cron import cleanup
from handlers import base_handler
from libs import handler


class Handler(base_handler.Handler):
  """Cleanup."""

  @handler.cron()
  def get(self):
    cleanup.main()
