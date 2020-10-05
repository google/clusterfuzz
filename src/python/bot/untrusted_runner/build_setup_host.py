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
"""Build setup host (client)."""

from . import host

from build_management import build_manager
from protos import untrusted_runner_pb2
from system import environment


def _clear_env():
  """Clear build env vars."""
  environment.remove_key('APP_PATH')
  environment.remove_key('APP_REVISION')
  environment.remove_key('APP_PATH_DEBUG')
  environment.remove_key('APP_DIR')
  environment.remove_key('BUILD_DIR')
  environment.remove_key('BUILD_URL')
  environment.remove_key('FUZZ_TARGET')


def _handle_response(build, response):
  """Handle build setup response."""
  if not response.result:
    _clear_env()
    return False

  _update_env_from_response(response)

  if not environment.get_value('APP_PATH'):
    fuzzer_directory = environment.get_value('FUZZER_DIR')
    if fuzzer_directory:
      build_manager.set_environment_vars([fuzzer_directory])

  environment.set_value('APP_REVISION', build.revision)
  return True


def _update_env_from_response(response):
  """Update environment variables from response."""
  environment.set_value('APP_PATH', response.app_path)
  environment.set_value('APP_PATH_DEBUG', response.app_path_debug)
  environment.set_value('APP_DIR', response.app_dir)
  environment.set_value('BUILD_DIR', response.build_dir)
  environment.set_value('BUILD_URL', response.build_url)
  environment.set_value('FUZZ_TARGET', response.fuzz_target)
  environment.set_value('FUZZ_TARGET_COUNT', response.fuzz_target_count)


class RemoteRegularBuild(build_manager.RegularBuild):
  """Remote regular build."""

  def setup(self):
    request = untrusted_runner_pb2.SetupRegularBuildRequest(
        base_build_dir=self.base_build_dir,
        revision=self.revision,
        build_url=self.build_url,
        build_prefix=self.build_prefix)
    if self.target_weights:
      request.target_weights.update(self.target_weights)

    return _handle_response(self, host.stub().SetupRegularBuild(request))
