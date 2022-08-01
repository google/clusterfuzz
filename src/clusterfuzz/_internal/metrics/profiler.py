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
"""Profiling functions."""
from clusterfuzz._internal.base import utils
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment


def start_if_needed(service):
  """Start Google Cloud Profiler if |USE_PYTHON_PROFILER| environment variable
  is set."""
  if not environment.get_value('USE_PYTHON_PROFILER'):
    return True

  project_id = utils.get_application_id()
  service_with_platform = '{service}_{platform}'.format(
      service=service, platform=environment.platform().lower())

  try:
    # Import the package here since it is only needed when profiler is enabled.
    # Also, this is supported on Linux only.
    import googlecloudprofiler
    googlecloudprofiler.start(
        project_id=project_id, service=service_with_platform)
  except Exception:
    logs.log_error(
        'Failed to start the profiler for service %s.' % service_with_platform)
    return False

  return True
