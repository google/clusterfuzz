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
"""Fuzzer log utilities."""

import datetime

from clusterfuzz._internal.config import local_config
from clusterfuzz._internal.google_cloud_utils import storage
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment

DATE_FORMAT = '%Y-%m-%d'
TIME_FORMAT = '%H:%M:%S:%f'

LOG_EXTENSION = '.log'
LOG_PATH_FORMAT = DATE_FORMAT + '/' + TIME_FORMAT


def get_bucket():
  """Return path to fuzzer logs bucket."""
  return local_config.ProjectConfig().get('logs.fuzzer.bucket')


def get_log_relative_path(log_time, file_extension=None):
  """Generate a relative path for a log using the given time.
  Args:
    log_time: A datetime object.
    file_extension: A string appended to the end of the log file name.
      LOG_EXTENSION is used if None.
  Returns:
    A string containing name of the log file.
  """
  if file_extension is None:
    file_extension = LOG_EXTENSION

  return log_time.strftime(LOG_PATH_FORMAT) + file_extension


def get_logs_directory(bucket_name, fuzzer_name, job_type=None, logs_date=None):
  """Get directory path of logs for a given fuzzer/job.
  Args:
    bucket_name: Bucket logs are stored in.
    fuzzer_name: Name of the fuzzer.
    job_type: Job name.
    logs_date: Optional datetime.date for the logs.

  Returns:
    A cloud storage path to the directory containing the desired logs. Format
    returned is /{bucket name}/{path}.
  """
  path = '/%s/%s' % (bucket_name, fuzzer_name)
  if job_type:
    path += '/%s' % job_type

  if logs_date is not None:
    assert job_type is not None
    path += '/%s' % logs_date

  return path


def get_logs_gcs_path(bucket_name=None,
                      time=None,
                      fuzzer_name=None,
                      job_type=None,
                      file_extension=None):
  """Determines the GCS path to upload a log file to.
  Args:
    bucket_name: Bucket logs are stored in.
    time: A datetime object used to generate filename for the log.
    fuzzer_name: Name of the fuzzer. If None, gets this from the environment.
    job_type: Job name. If None, gets this from the environment.
    file_extension: A string appended to the end of the log filename. A default
      value is used if None.
  Returns:
    The path of the uploaded file and whether the uploaded succeeded.
  """
  if bucket_name is None:
    bucket_name = get_bucket()

  if not fuzzer_name:
    fuzzer_name = environment.get_value('FUZZER_NAME')

  if not job_type:
    job_type = environment.get_value('JOB_NAME')

  log_directory = get_logs_directory(bucket_name, fuzzer_name, job_type)

  if not time:
    time = datetime.datetime.utcnow()

  log_path = 'gs:/' + log_directory + '/' + get_log_relative_path(
      time, file_extension)
  return log_path


def upload_to_logs(bucket_name,
                   contents,
                   time=None,
                   fuzzer_name=None,
                   job_type=None,
                   file_extension=None,
                   signed_upload_url=None):
  """Uploads file contents to log directory in GCS bucket.
  Args:
    bucket_name: Bucket logs are stored in.
    contents: String containing log to be uploaded.
    time: A datetime object used to generate filename for the log.
    fuzzer_name: Name of the fuzzer. If None, gets this from the environment.
    job_type: Job name. If None, gets this from the environment.
    file_extension: A string appended to the end of the log filename. A default
      value is used if None.
    signed_upload_url: A signed url to upload the logs to.

  Returns:
    The path of the uploaded file and whether the uploaded succeeded.
  """
  if signed_upload_url:
    if storage.upload_signed_url(contents, signed_upload_url):
      logs.log(
          'Uploaded file to logs bucket.', signed_upload_url=signed_upload_url)
    else:
      logs.log_error(
          'Failed to write file to logs bucket.',
          signed_upload_url=signed_upload_url)

    return

  log_path = get_logs_gcs_path(
      bucket_name,
      time=time,
      fuzzer_name=fuzzer_name,
      job_type=job_type,
      file_extension=file_extension)

  if storage.write_data(contents, log_path):
    logs.log('Uploaded file to logs bucket.', log_path=log_path)
  else:
    logs.log_error('Failed to write file to logs bucket.', log_path=log_path)


def upload_script_log(log_contents,
                      fuzzer_name=None,
                      job_type=None,
                      signed_upload_url=None):
  """Uploads logs to script logs GCS bucket.
  Args:
    logs_bucket: Bucket logs are stored in.
    log_contents: String containing log to be uploaded.
    fuzzer_name: Name of the fuzzer. If None, gets this from the environment.
    job_type: Job name. If None, gets this from the environment.
    signed_upload_url: A signed URL to upload this to.
  """
  logs_bucket = get_bucket()
  if logs_bucket and log_contents and log_contents.strip():
    upload_to_logs(
        logs_bucket,
        log_contents,
        fuzzer_name=fuzzer_name,
        job_type=job_type,
        signed_upload_url=signed_upload_url)
