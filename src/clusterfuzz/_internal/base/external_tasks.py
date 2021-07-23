# Copyright 2021 Google LLC
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
"""External tasks."""

from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.google_cloud_utils import blobs
from clusterfuzz._internal.google_cloud_utils import pubsub
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment


def add_external_task(command, testcase_id, job):
  """Add external task."""
  if command != 'progression':
    # Only progression is supported.
    return

  pubsub_client = pubsub.PubSubClient()
  topic_name = job.external_reproduction_topic
  assert topic_name is not None

  testcase = data_handler.get_testcase_by_id(testcase_id)
  fuzz_target = testcase.get_fuzz_target()

  memory_tool_name = environment.get_memory_tool_name(job.name)
  sanitizer = environment.SANITIZER_NAME_MAP.get(memory_tool_name)
  job_environment = job.get_environment()
  if job_environment.get('CUSTOM_BINARY'):
    raise RuntimeError('External jobs should never have custom binaries.')

  build_path = (
      job_environment.get('RELEASE_BUILD_BUCKET_PATH') or
      job_environment.get('FUZZ_TARGET_BUILD_BUCKET_PATH'))
  if build_path is None:
    raise RuntimeError(f'{job.name} has no build path defined.')

  min_revision = (
      testcase.get_metadata('last_tested_revision') or testcase.crash_revision)

  logs.log(f'Publishing external reproduction task for {testcase_id}.')
  attributes = {
      'project': job.project,
      'target': fuzz_target.binary,
      'fuzzer': testcase.fuzzer_name,
      'sanitizer': sanitizer,
      'job': job.name,
      'testcaseId': str(testcase_id),
      'buildPath': build_path,
      'minRevisionAbove': str(min_revision),
  }

  reproducer = blobs.read_key(testcase.fuzzed_keys)
  message = pubsub.Message(data=reproducer, attributes=attributes)
  pubsub_client.publish(topic_name, [message])
