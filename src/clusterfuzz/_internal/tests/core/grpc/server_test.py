# Copyright 2025 Google LLC
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
"""Tests for the gRPC server, now with expanded coverage."""

import unittest
from concurrent import futures
from unittest import mock
import grpc
import os

# Mock the problematic module before it's imported by the server.
mock_reproduce_logic = mock.MagicMock()
with mock.patch.dict('sys.modules', {'clusterfuzz.grpc.reproduce_logic': mock_reproduce_logic}):
    from clusterfuzz.grpc import reproduce_pb2
    from clusterfuzz.grpc import reproduce_pb2_grpc
    from clusterfuzz.grpc.auth import ApiKeyInterceptor
    from clusterfuzz.grpc.server import ReproduceServiceImpl

_VALID_API_KEY = "test-key-1"

@mock.patch('clusterfuzz.grpc.server.JobStore')
@mock.patch('dbm.open', new_callable=mock.mock_open)
@mock.patch.dict('os.environ', {'VALID_API_KEYS': _VALID_API_KEY})
class GrpcServerTest(unittest.TestCase):
    """Expanded tests for the gRPC server."""

    def setUp(self):
        """Sets up the test server and client."""
        # Manually start the patchers that were causing issues as decorators.
        self.job_store_patcher = mock.patch('clusterfuzz.grpc.server.JobStore')
        self.mock_job_store_class = self.job_store_patcher.start()

        self._server = grpc.server(
            futures.ThreadPoolExecutor(max_workers=1),
            interceptors=[ApiKeyInterceptor()])

        self.service_impl = ReproduceServiceImpl()
        reproduce_pb2_grpc.add_ReproduceServiceServicer_to_server(
            self.service_impl, self._server)

        self.port = self._server.add_insecure_port('[::]:0')
        self._server.start()
        self.channel = grpc.insecure_channel(f'localhost:{self.port}')
        self.stub = reproduce_pb2_grpc.ReproduceServiceStub(self.channel)

        # Get the instance of the mock from the service.
        self.mock_job_store = self.service_impl._job_store

    def tearDown(self):
        """Stops the server and the patchers."""
        self.job_store_patcher.stop()
        self.channel.close()
        self._server.stop(0)

    def test_start_job_success(self):
        """Tests starting a job with a valid API key."""
        mock_job = reproduce_pb2.Job(job_id="new-job-id", status=reproduce_pb2.JOB_STATUS_QUEUED)
        self.mock_job_store.create_job.return_value = mock_job

        metadata = [('x-api-key', _VALID_API_KEY)]
        request = reproduce_pb2.StartReproductionJobRequest(testcase_ids=[123], image_tag="latest")

        with mock.patch.object(self.service_impl._job_runner, 'start_job') as mock_start_runner:
            response = self.stub.StartReproductionJob(request, metadata=metadata)
            self.assertEqual(response.job_id, "new-job-id")
            self.assertEqual(response.status, reproduce_pb2.JOB_STATUS_QUEUED)
            mock_start_runner.assert_called_once_with(mock_job)

    def test_get_job_results_success(self):
        """Tests getting results for a completed job."""
        job_id = "completed-job"
        metadata_dict = {
            'job': reproduce_pb2.Job(job_id=job_id, status=reproduce_pb2.JOB_STATUS_COMPLETED),
            'testcase_statuses': {
                '101': reproduce_pb2.TEST_CASE_STATUS_REPRODUCED,
                '102': reproduce_pb2.TEST_CASE_STATUS_FAILED_REPRODUCTION,
            }
        }
        self.mock_job_store.get_job_metadata.return_value = metadata_dict

        metadata = [('x-api-key', _VALID_API_KEY)]
        request = reproduce_pb2.GetJobResultsRequest(job_id=job_id)
        response = self.stub.GetJobResults(request, metadata=metadata)

        self.assertAlmostEqual(response.success_percentage, 50.0)
        self.assertAlmostEqual(response.failure_percentage, 50.0)
        self.assertEqual(len(response.results), 2)

if __name__ == '__main__':
    unittest.main()
