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
"""Tests for uworker_io2."""

import unittest

from google.cloud.datastore_v1.proto import entity_pb2

from clusterfuzz._internal.bot.tasks.utasks import uworker_io2
from clusterfuzz._internal.protos import uworker_msg_pb2
from clusterfuzz._internal.tests.test_libs import test_utils


@test_utils.with_cloud_emulators('datastore')
class UworkerIo2Test(unittest.TestCase):
  """Tests for proto conversion to and from python types."""

  def test_analyze_task_input_to_proto(self):
    proto = uworker_io2.AnalyzeTaskInput(bad_revisions=[1, 2, 3]).to_proto()
    self.assertEqual(proto.bad_revisions, [1, 2, 3])

  def test_analyze_task_input_from_proto(self):
    task_input = uworker_io2.AnalyzeTaskInput.from_proto(
        uworker_msg_pb2.AnalyzeTaskInput(bad_revisions=[1, 2, 3]))
    self.assertEqual(
        task_input, uworker_io2.AnalyzeTaskInput(bad_revisions=[1, 2, 3]))

  def test_analyze_task_input_roundtrip(self):
    task_input = uworker_io2.AnalyzeTaskInput(bad_revisions=[1, 2, 3])
    self.assertEqual(
        uworker_io2.AnalyzeTaskInput.from_proto(task_input.to_proto()),
        task_input)

  def test_json_to_proto(self):
    pass

  def test_json_from_proto(self):
    pass

  def test_model_roundtrip(self):
    testcase = test_utils.create_generic_testcase()
    proto = uworker_io2.model_to_proto(testcase)

    self.assertIsInstance(proto, entity_pb2.Entity)

    roundtripped = uworker_io2.model_from_proto(proto)

    self.assertEqual(roundtripped, testcase)

  def test_input_to_proto(self):
    """Verifies that `uworker_io2.Input` is correctly converted to a protobuf.
    """
    testcase = test_utils.create_generic_testcase()
    inp = uworker_io2.Input(
        testcase=testcase,
        testcase_id='123',
        job_type='foo-job',
        original_job_type='original-job',
        uworker_env={'a': 'b'},
        uworker_output_upload_url='http://foo',
        fuzzer_name='foo-fuzzer',
        module_name='foo_module',
    )

    proto = inp.to_proto()

    self.assertEqual(proto.testcase_id, '123')
    self.assertEqual(proto.job_type, 'foo-job')
    self.assertEqual(proto.original_job_type, 'original-job')
    self.assertEqual(proto.uworker_output_upload_url, 'http://foo')
    self.assertEqual(proto.fuzzer_name, 'foo-fuzzer')
    self.assertEqual(proto.module_name, 'foo_module')

    roundtripped_testcase = uworker_io2.model_from_proto(proto.testcase)
    self.assertEqual(roundtripped_testcase, testcase)

    roundtripped_uworker_env = uworker_io2.json_from_proto(proto.uworker_env)
    self.assertEqual(roundtripped_uworker_env, {'a': 'b'})

  def test_input_from_proto(self):
    """Verifies that `uworker_io2.Input` is correctly converted from a protobuf.
    """
    testcase = test_utils.create_generic_testcase()
    proto = uworker_msg_pb2.Input(
        testcase=uworker_io2.model_to_proto(testcase),
        testcase_id='123',
        job_type='foo-job',
        original_job_type='original-job',
        uworker_env=uworker_io2.json_to_proto({
            'a': 'b'
        }),
        uworker_output_upload_url='http://foo',
        fuzzer_name='foo-fuzzer',
        module_name='foo_module',
    )

    inp = uworker_io2.Input.from_proto(proto)

    self.assertEqual(
        inp,
        uworker_io2.Input(
            testcase=testcase,
            testcase_id='123',
            job_type='foo-job',
            original_job_type='original-job',
            uworker_env={'a': 'b'},
            uworker_output_upload_url='http://foo',
            fuzzer_name='foo-fuzzer',
            module_name='foo_module',
        ))

  def test_input_roundtrip(self):
    """Verifies that converting a `uworker_io2.Input` to protobufs and back
    yields the same value.
    """
    inp = uworker_io2.Input(
        testcase=test_utils.create_generic_testcase(),
        testcase_id='123',
        job_type='foo-job',
        original_job_type='original-job',
        uworker_env={'a': 'b'},
        uworker_output_upload_url='http://foo',
        fuzzer_name='foo-fuzzer',
        module_name='foo_module',
    )

    roundtripped = uworker_io2.Input.from_proto(inp.to_proto())

    self.assertEqual(roundtripped, inp)
