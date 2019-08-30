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
"""Build setup (untrusted side)."""

from build_management import build_manager
from protos import untrusted_runner_pb2
from system import environment


def _build_response(result):
  if not result:
    return untrusted_runner_pb2.SetupBuildResponse(result=False)

  return untrusted_runner_pb2.SetupBuildResponse(
      result=True,
      app_path=environment.get_value('APP_PATH'),
      app_path_debug=environment.get_value('APP_PATH_DEBUG'),
      app_dir=environment.get_value('APP_DIR'),
      build_dir=environment.get_value('BUILD_DIR'),
      build_url=environment.get_value('BUILD_URL'),
      fuzz_target=environment.get_value('FUZZ_TARGET'),
      fuzz_target_count=environment.get_value('FUZZ_TARGET_COUNT'))


def setup_regular_build(request):
  """Set up a regular build."""
  build = build_manager.RegularBuild(request.base_build_dir, request.revision,
                                     request.build_url, request.target_weights,
                                     request.build_prefix)
  return _build_response(build.setup())
