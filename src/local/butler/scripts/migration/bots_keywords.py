# Copyright 2020 Google LLC
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
"""Build keyword attributes for every job."""

from datastore import data_types
from google.cloud import ndb


def execute(args):
  """Build keywords for jobs."""
  bots = list(data_types.Heartbeat.query())
  if args.non_dry_run:
    ndb.put_multi(bots)
    print("Done building keywords for bots.")
