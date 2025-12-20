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
"""The gRPC server for the reproduce service."""

import time
from concurrent import futures

import grpc

from clusterfuzz.grpc import reproduce_pb2
from clusterfuzz.grpc import reproduce_pb2_grpc
from clusterfuzz.grpc.auth import ApiKeyInterceptor
from clusterfuzz.grpc.jobs import JobStore, JobRunner


class ReproduceServiceImpl(reproduce_pb2_grpc.ReproduceServiceServicer):
  """Implements the ReproduceService."""

  def __init__(self):
    self._job_store = JobStore()
    self._job_runner = JobRunner()

  def StartReproductionJob(self, request, context):
    """Starts a new reproduction job."""
    print(f'Received StartReproductionJob request: {request}')
    job = self._job_store.create_job(
        request.testcase_ids, request.image_tag, request.time_limit)

    self._job_runner.start_job(job)
    return job

  def SubscribeToJobUpdates(self, request, context):
    """Subscribes to job updates with server-side streaming."""
    print(f'Received SubscribeToJobUpdates request for job: {request.job_id}')

    # Keep track of sent updates to avoid sending duplicates.
    sent_updates = set()

    while True:
        metadata = self._job_store.get_job_metadata(request.job_id)
        if not metadata:
            context.abort(grpc.StatusCode.NOT_FOUND, "Job not found.")
            return

        # Check for new testcase status updates.
        for testcase_id, status in metadata['testcase_statuses'].items():
            update_key = (testcase_id, status)
            if update_key not in sent_updates:
                yield reproduce_pb2.JobUpdate(
                    job_id=request.job_id,
                    testcase_id=int(testcase_id),
                    status=status)
                sent_updates.add(update_key)

        # If the job is completed or failed, end the stream.
        job_status = metadata['job'].status
        if job_status in [reproduce_pb2.JOB_STATUS_COMPLETED, reproduce_pb2.JOB_STATUS_FAILED]:
            print(f"Ending stream for completed job {request.job_id}.")
            break

        # Wait before polling for new updates to avoid busy-waiting.
        time.sleep(2)


  def GetJobStatus(self, request, context):
    """Gets job status."""
    print(f'Received GetJobStatus request for job: {request.job_id}')
    job = self._job_store.get_job(request.job_id)
    if not job:
      context.abort(grpc.StatusCode.NOT_FOUND, f"Job with ID {request.job_id} not found.")
      return reproduce_pb2.Job()
    return job

  def GetJobResults(self, request, context):
    """Gets job results and calculates final metrics."""
    print(f'Received GetJobResults request for job: {request.job_id}')
    metadata = self._job_store.get_job_metadata(request.job_id)

    if not metadata:
        context.abort(grpc.StatusCode.NOT_FOUND, "Job not found.")
        return reproduce_pb2.JobResults()

    job = metadata['job']
    if job.status not in [reproduce_pb2.JOB_STATUS_COMPLETED, reproduce_pb2.JOB_STATUS_FAILED]:
        context.abort(grpc.StatusCode.FAILED_PRECONDITION, "Job has not completed yet.")
        return reproduce_pb2.JobResults()

    statuses = metadata['testcase_statuses'].values()
    total_cases = len(statuses)
    if total_cases == 0:
        return reproduce_pb2.JobResults(job_id=job.job_id)

    # Calculate metrics.
    success_count = sum(1 for s in statuses if s == reproduce_pb2.TEST_CASE_STATUS_REPRODUCED)
    timeout_count = sum(1 for s in statuses if s == reproduce_pb2.TEST_CASE_STATUS_TIMEOUT)
    failure_count = sum(1 for s in statuses if s == reproduce_pb2.TEST_CASE_STATUS_FAILED_REPRODUCTION)

    results = [
        reproduce_pb2.TestCaseResult(testcase_id=int(tid), final_status=s)
        for tid, s in metadata['testcase_statuses'].items()
    ]

    return reproduce_pb2.JobResults(
        job_id=job.job_id,
        success_percentage=(success_count / total_cases) * 100.0,
        timeout_percentage=(timeout_count / total_cases) * 100.0,
        failure_percentage=(failure_count / total_cases) * 100.0,
        results=results
    )


def serve():
  """Starts the gRPC server."""
  auth_interceptor = ApiKeyInterceptor()
  server = grpc.server(
      futures.ThreadPoolExecutor(max_workers=10),
      interceptors=[auth_interceptor])

  reproduce_pb2_grpc.add_ReproduceServiceServicer_to_server(
      ReproduceServiceImpl(), server)
  server.add_insecure_port('[::]:50051')
  print('Starting gRPC server on port 50051 with authentication enabled.')
  server.start()
  server.wait_for_termination()


if __name__ == '__main__':
  serve()
