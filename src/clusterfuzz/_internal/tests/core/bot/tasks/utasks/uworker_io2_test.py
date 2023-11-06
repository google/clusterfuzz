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
from clusterfuzz._internal.datastore import data_types
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

    roundtripped = uworker_io2.model_from_proto(proto, data_types.Testcase)

    self.assertEqual(roundtripped, testcase)

  def _make_testcase_upload_metadata(self):
    metadata = data_types.TestcaseUploadMetadata()
    metadata.put()  # Put before mutating, to ensure local changes propagate.
    metadata.filename = 'bar.txt'
    return metadata

  def _make_fuzzer(self):
    fuzzer = data_types.Fuzzer()
    fuzzer.put()  # See `_make_testcase_upload_metadata()`.
    fuzzer.name = 'foo-fuzzer'
    return fuzzer

  def _make_data_bundle(self, name='foo-bundle'):
    bundle = data_types.DataBundle()
    bundle.put()  # See `_make_testcase_upload_metadata()`.
    bundle.name = name
    return bundle

  def _make_setup_input(self):
    return uworker_io2.SetupInput(
        fuzzer=self._make_fuzzer(),
        data_bundles=[
            self._make_data_bundle(name='foo-bundle'),
            self._make_data_bundle(name='bar-bundle'),
        ],
        fuzzer_name='foo-fuzzer',
        fuzzer_log_upload_url='http://fuzzer-log-upload',
        fuzzer_download_url='http://fuzzer-download',
        testcase_download_url='http://testcase-download',
    )

  def _make_analyze_task_input(self):
    return uworker_io2.AnalyzeTaskInput(bad_revisions=[1, 2, 3])

  def test_setup_input_to_proto(self):
    """Verifies that `uworker_io2.SetupInput.to_proto()` works correctly."""
    setup_input = self._make_setup_input()

    proto = setup_input.to_proto()

    self.assertEqual(proto.fuzzer_name, setup_input.fuzzer_name)
    self.assertEqual(proto.fuzzer_log_upload_url,
                     setup_input.fuzzer_log_upload_url)
    self.assertEqual(proto.fuzzer_download_url, setup_input.fuzzer_download_url)
    self.assertEqual(proto.testcase_download_url,
                     setup_input.testcase_download_url)

    roundtripped_fuzzer = uworker_io2.model_from_proto(proto.fuzzer,
                                                       data_types.Fuzzer)
    self.assertEqual(roundtripped_fuzzer, setup_input.fuzzer)

    roundtripped_bundles = [
        uworker_io2.model_from_proto(bundle, data_types.DataBundle)
        for bundle in proto.data_bundles
    ]
    self.assertEqual(roundtripped_bundles, setup_input.data_bundles)

  def test_setup_input_roundtrip(self):
    """Verifies that converting a `uworker_io2.SetupInput` to protobufs and back
    yields the same value.
    """
    setup_input = self._make_setup_input()

    roundtripped = uworker_io2.SetupInput.from_proto(setup_input.to_proto())

    self.assertEqual(roundtripped, setup_input)

  def test_input_to_proto(self):
    """Verifies that `uworker_io2.Input` is correctly converted to a protobuf.
    """
    testcase = test_utils.create_generic_testcase()
    inp = uworker_io2.Input(
        testcase=testcase,
        testcase_id='123',
        testcase_upload_metadata=None,
        job_type='foo-job',
        original_job_type='original-job',
        uworker_env={'a': 'b'},
        uworker_output_upload_url='http://foo',
        fuzzer_name='foo-fuzzer',
        module_name='foo_module',
        setup_input=None,
        analyze_task_input=None,
    )

    proto = inp.to_proto()

    self.assertEqual(proto.testcase_id, '123')
    self.assertEqual(proto.job_type, 'foo-job')
    self.assertEqual(proto.original_job_type, 'original-job')
    self.assertEqual(proto.uworker_output_upload_url, 'http://foo')
    self.assertEqual(proto.fuzzer_name, 'foo-fuzzer')
    self.assertEqual(proto.module_name, 'foo_module')

    self.assertFalse(proto.HasField('testcase_upload_metadata'))
    self.assertFalse(proto.HasField('setup_input'))
    self.assertFalse(proto.HasField('analyze_task_input'))

    roundtripped_testcase = uworker_io2.model_from_proto(
        proto.testcase, data_types.Testcase)
    self.assertEqual(roundtripped_testcase, testcase)

    roundtripped_uworker_env = uworker_io2.json_from_proto(proto.uworker_env)
    self.assertEqual(roundtripped_uworker_env, {'a': 'b'})

  def test_input_to_proto_optional_fields(self):
    """Verifies that `uworker_io2.Input` correctly converts its optional fields
    to protobuf fields when they are set.
    """
    metadata = self._make_testcase_upload_metadata()
    inp = uworker_io2.Input(
        testcase=test_utils.create_generic_testcase(),
        testcase_id='123',
        testcase_upload_metadata=metadata,
        job_type='foo-job',
        original_job_type='original-job',
        uworker_env={'a': 'b'},
        uworker_output_upload_url='http://foo',
        fuzzer_name='foo-fuzzer',
        module_name='foo_module',
        setup_input=self._make_setup_input(),
        analyze_task_input=self._make_analyze_task_input(),
    )

    proto = inp.to_proto()

    roundtripped_metadata = uworker_io2.model_from_proto(
        proto.testcase_upload_metadata, data_types.TestcaseUploadMetadata)
    self.assertEqual(roundtripped_metadata, metadata)

    roundtripped_setup_input = uworker_io2.SetupInput.from_proto(
        proto.setup_input)
    self.assertEqual(roundtripped_setup_input, inp.setup_input)

    roundtripped_analyze_task_input = uworker_io2.AnalyzeTaskInput.from_proto(
        proto.analyze_task_input)
    self.assertEqual(roundtripped_analyze_task_input, inp.analyze_task_input)

  def test_input_from_proto(self):
    """Verifies that `uworker_io2.Input` is correctly converted from a protobuf.
    """
    testcase = test_utils.create_generic_testcase()
    proto = uworker_msg_pb2.Input(
        testcase=uworker_io2.model_to_proto(testcase),
        testcase_id='123',
        testcase_upload_metadata=None,
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
            testcase_upload_metadata=None,
            job_type='foo-job',
            original_job_type='original-job',
            uworker_env={'a': 'b'},
            uworker_output_upload_url='http://foo',
            fuzzer_name='foo-fuzzer',
            module_name='foo_module',
            setup_input=None,
            analyze_task_input=None,
        ))

  def test_input_from_proto_optional_fields(self):
    """Verifies that `uworker_io2.Input.from_proto()` correctly converts
    optional fields when they are set.
    """
    testcase = test_utils.create_generic_testcase()
    metadata = self._make_testcase_upload_metadata()
    setup_input = self._make_setup_input()
    analyze_task_input = self._make_analyze_task_input()
    proto = uworker_msg_pb2.Input(
        testcase=uworker_io2.model_to_proto(testcase),
        testcase_id='123',
        testcase_upload_metadata=uworker_io2.model_to_proto(metadata),
        job_type='foo-job',
        original_job_type='original-job',
        uworker_env=uworker_io2.json_to_proto({
            'a': 'b'
        }),
        uworker_output_upload_url='http://foo',
        fuzzer_name='foo-fuzzer',
        module_name='foo_module',
        setup_input=setup_input.to_proto(),
        analyze_task_input=analyze_task_input.to_proto(),
    )

    inp = uworker_io2.Input.from_proto(proto)

    self.assertEqual(inp.testcase_upload_metadata, metadata)
    self.assertEqual(inp.setup_input, setup_input)
    self.assertEqual(inp.analyze_task_input, analyze_task_input)

  def test_input_roundtrip(self):
    """Verifies that converting a `uworker_io2.Input` to protobufs and back
    yields the same value.
    """
    inp = uworker_io2.Input(
        testcase=test_utils.create_generic_testcase(),
        testcase_id='123',
        testcase_upload_metadata=self._make_testcase_upload_metadata(),
        job_type='foo-job',
        original_job_type='original-job',
        uworker_env={'a': 'b'},
        uworker_output_upload_url='http://foo',
        fuzzer_name='foo-fuzzer',
        module_name='foo_module',
        setup_input=self._make_setup_input(),
        analyze_task_input=self._make_analyze_task_input(),
    )

    roundtripped = uworker_io2.Input.from_proto(inp.to_proto())

    self.assertEqual(roundtripped, inp)
