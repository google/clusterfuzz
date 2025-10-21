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
"""Core logic for managing and running reproduction jobs with persistence."""

import dbm
import json
import threading
import uuid
from concurrent import futures
from typing import Dict, Any

from google.protobuf import timestamp_pb2, json_format
from clusterfuzz.grpc import reproduce_pb2
from clusterfuzz.grpc.reproduce_logic import initialize_environment, reproduce_testcase_by_id

_DB_PATH = './jobs.db'
_db_lock = threading.Lock()

class JobStore:
  """A class to manage the state of reproduction jobs with DBM persistence."""

  def _serialize(self, data: Dict[str, Any]) -> str:
    """Serializes job data, converting protobuf messages to dicts."""
    if 'job' in data:
        data['job'] = json_format.MessageToDict(data['job'])
    return json.dumps(data)

  def _deserialize(self, data_str: str) -> Dict[str, Any]:
    """Deserializes job data, converting dicts back to protobuf messages."""
    data = json.loads(data_str)
    if 'job' in data:
        data['job'] = json_format.ParseDict(data['job'], reproduce_pb2.Job())
    return data

  def create_job(self, testcase_ids, image_tag, time_limit) -> reproduce_pb2.Job:
    """Creates a new job and stores it in the DBM file."""
    job_id = str(uuid.uuid4())
    now = timestamp_pb2.Timestamp()
    now.GetCurrentTime()
    job = reproduce_pb2.Job(
        job_id=job_id,
        status=reproduce_pb2.JOB_STATUS_QUEUED,
        creation_time=now)

    # Track individual testcase statuses.
    testcase_statuses = {str(tid): reproduce_pb2.TEST_CASE_STATUS_PENDING for tid in testcase_ids}

    job_metadata = {
        'job': job,
        'testcase_ids': testcase_ids,
        'image_tag': image_tag,
        'time_limit': time_limit.ToJsonString(),
        'testcase_statuses': testcase_statuses,
        'updates': [],
    }

    with _db_lock:
      with dbm.open(_DB_PATH, 'c') as db:
        db[job_id] = self._serialize(job_metadata)

    return job

  def get_job_metadata(self, job_id: str) -> Dict[str, Any]:
    """Retrieves full job metadata from the DBM file."""
    with _db_lock:
      with dbm.open(_DB_PATH, 'r') as db:
        if job_id not in db:
          return None
        return self._deserialize(db[job_id])

  def get_job(self, job_id: str):
    """Retrieves a job by its ID."""
    metadata = self.get_job_metadata(job_id)
    return metadata.get('job') if metadata else None

  def _update_metadata(self, job_id: str, metadata: Dict[str, Any]):
      """Writes updated metadata back to the DBM file."""
      with _db_lock:
          with dbm.open(_DB_PATH, 'w') as db:
              db[job_id] = self._serialize(metadata)

  def update_job_status(self, job_id: str, status: reproduce_pb2.JobStatus):
    """Updates the overall status of a job."""
    metadata = self.get_job_metadata(job_id)
    if metadata:
      metadata['job'].status = status
      if status in [reproduce_pb2.JOB_STATUS_COMPLETED, reproduce_pb2.JOB_STATUS_FAILED]:
        now = timestamp_pb2.Timestamp()
        now.GetCurrentTime()
        metadata['job'].completion_time = now
      self._update_metadata(job_id, metadata)

  def update_testcase_status(self, job_id: str, testcase_id: int, status: reproduce_pb2.TestCaseStatus):
    """Updates the status of a single testcase within a job."""
    metadata = self.get_job_metadata(job_id)
    if metadata:
        metadata['testcase_statuses'][str(testcase_id)] = status
        self._update_metadata(job_id, metadata)


class JobRunner:
  """A class responsible for running the reproduction logic."""
  def __init__(self):
    self._executor = futures.ThreadPoolExecutor(max_workers=4)
    self._job_store = JobStore()
    initialize_environment('./configs/local')

  def start_job(self, job: reproduce_pb2.Job):
    """Starts a job execution in the background."""
    self._executor.submit(self._run_job, job.job_id)

  def _run_job(self, job_id: str):
    """The actual job execution logic."""
    print(f"Starting execution for job {job_id}")
    self._job_store.update_job_status(job_id, reproduce_pb2.JOB_STATUS_RUNNING)
    metadata = self._job_store.get_job_metadata(job_id)
    if not metadata:
      print(f"Job {job_id} not found.")
      return

    testcase_ids = metadata.get('testcase_ids', [])
    for testcase_id in testcase_ids:
      self._job_store.update_testcase_status(job_id, testcase_id, reproduce_pb2.TEST_CASE_STATUS_RUNNING)
      try:
        print(f"Reproducing testcase {testcase_id} for job {job_id}")
        reproduce_testcase_by_id(testcase_id, './configs/local')
        # Assuming success if no exception is raised. A real implementation
        # would return a status from the reproduce function.
        self._job_store.update_testcase_status(job_id, testcase_id, reproduce_pb2.TEST_CASE_STATUS_REPRODUCED)
      except Exception as e:
        print(f"Error reproducing testcase {testcase_id}: {e}")
        self._job_store.update_testcase_status(job_id, testcase_id, reproduce_pb2.TEST_CASE_STATUS_FAILED_REPRODUCTION)

    print(f"Finished execution for job {job_id}")
    self._job_store.update_job_status(job_id, reproduce_pb2.JOB_STATUS_COMPLETED)
