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
"""Build keyword attributes for every job."""

import sys

from datastore import data_types
from google.cloud import ndb


def execute(args):
  """Build keywords for jobs."""
  jobs = list(data_types.Job.query())
  if args.non_dry_run:
    try:
      ndb.put_multi(jobs)
    except Exception:
      for job in jobs:
        try:
          job.put()
        except Exception:
          print('Error: %s %s' % (job.key.id(), sys.exc_info()))

    print("Done building keywords for jobs.")
