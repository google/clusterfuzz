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
"""Build server - create stable and beta builds and upload to GCS."""

# Before any other imports, we must fix the path. Some libraries might expect
# to be able to import dependencies directly, but we must store these in
# subdirectories of common so that they are shared with App Engine.
from clusterfuzz._internal.base import modules

modules.fix_module_search_paths()

import os
import time

from clusterfuzz._internal.chrome import build_info
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment

BUILD_HELPER_SCRIPT = os.path.join(
    os.path.abspath(os.path.dirname(__file__)), 'build_helper.sh')
GN_COMMON_ARGS = 'is_debug=false v8_enable_verify_heap=true'
LAST_BUILD = {}
TOOLS_BUCKET_DIR_MAPPINGS = {
    'asan': 'linux-release',
    'msan': 'linux-release',
    'tsan': 'linux-release',
    'ubsan': 'linux-release',
    'ubsan-vptr': 'linux-release-vptr'
}
TOOLS_GN_MAPPINGS = {
    'asan': 'is_asan=true',
    'msan': 'is_msan=true use_prebuilt_instrumented_libraries=true',
    'tsan': 'is_tsan=true enable_nacl=false',
    'ubsan': 'is_ubsan=true',
    'ubsan-vptr': 'is_ubsan_vptr=true',
}


def main():
  """Main build routine."""
  bucket_prefix = environment.get_value('BUCKET_PREFIX')
  build_dir = environment.get_value('BUILD_DIR')
  wait_time = environment.get_value('WAIT_TIME')

  try:
    builds_metadata = build_info.get_production_builds_info_from_cd(
        environment.platform())
  except Exception:
    logs.log_error('Errors when fetching from ChromiumDash')
    # fallback to omahaproxy in the transition stage
    # TODO(yuanjunh): remove the fallback logic after migration is done.
    builds_metadata = build_info.get_production_builds_info(
        environment.platform())

  if not builds_metadata:
    return

  global LAST_BUILD
  for build_metadata in builds_metadata:
    build_type = build_metadata.build_type
    revision = build_metadata.revision
    version = build_metadata.version

    if build_type not in ['extended_stable', 'stable', 'beta']:
      # We don't need dev or canary builds atm.
      continue

    # Starting building the builds.
    for tool in TOOLS_GN_MAPPINGS:
      tool_and_build_type = '%s-%s' % (tool, build_type)
      logs.log('Building %s.' % tool_and_build_type)

      # Check if we already have built the same build.
      if (tool_and_build_type in LAST_BUILD and
          revision == LAST_BUILD[tool_and_build_type]):
        logs.log('Skipping same build %s (revision %s).' % (tool_and_build_type,
                                                            revision))
        continue

      LAST_BUILD[tool_and_build_type] = revision

      file_name_prefix = '%s-linux-%s-%s' % (tool, build_type, version)
      archive_filename = '%s.zip' % file_name_prefix
      archive_path_local = '%s/%s' % (build_dir, archive_filename)
      bucket_name = '%s%s' % (bucket_prefix, tool.split('-')[0])
      archive_path_remote = ('gs://%s/%s/%s' % (
          bucket_name, TOOLS_BUCKET_DIR_MAPPINGS[tool], archive_filename))

      # Run the build script with required gn arguments.
      command = ''
      gn_args = '%s %s' % (TOOLS_GN_MAPPINGS[tool], GN_COMMON_ARGS)
      command += '%s "%s" %s %s' % (BUILD_HELPER_SCRIPT, gn_args, version,
                                    file_name_prefix)
      logs.log('Executing build script: %s.' % command)
      os.system(command)

      # Check if the build succeeded based on the existence of the
      # local archive file.
      if os.path.exists(archive_path_local):
        # Build success. Now, copy it to google cloud storage and make it
        # public.
        os.system('gsutil cp %s %s' % (archive_path_local, archive_path_remote))
        os.system('gsutil acl set public-read %s' % archive_path_remote)
        logs.log('Build succeeded, created %s.' % archive_filename)
      else:
        LAST_BUILD[tool_and_build_type] = ''
        logs.log_error('Build failed, unable to create %s.' % archive_filename)

  logs.log('Completed cycle, waiting for %d secs.' % wait_time)
  time.sleep(wait_time)


if __name__ == '__main__':
  # Make sure environment is correctly configured.
  logs.configure('run_bot')
  environment.set_bot_environment()

  fail_wait = environment.get_value('FAIL_WAIT')

  # Continue this forever.
  while True:
    try:
      main()
    except Exception:
      logs.log_error('Failed to create build.')
      time.sleep(fail_wait)
