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
"""Handler that uploads a testcase"""

import ast
import datetime
import json
import StringIO

from google.appengine.ext import blobstore
from google.appengine.ext.webapp import blobstore_handlers

from base import external_users
from base import tasks
from base import utils
from datastore import data_handler
from datastore import data_types
from datastore import ndb
from google_cloud_utils import blobs
from google_cloud_utils import storage
from handlers import base_handler
from libs import access
from libs import form
from libs import gcs
from libs import handler
from libs import helpers
from libs.query import datastore_query
from system import archive

MAX_RETRIES = 50
RUN_FILE_PATTERNS = ['run', 'fuzz-', 'index.', 'crash.']
PAGE_SIZE = 20
MORE_LIMIT = 100 - PAGE_SIZE


def attach_testcases(rows):
  """Attach testcase to each crash."""
  testcases = {}
  for index, row in enumerate(rows):
    testcases[index] = query_testcase(row['testcaseId'])

  for index, row in enumerate(rows):
    testcase = (list(testcases[index]) or [None])[0]
    if testcase:
      testcase = {
          'crashType': testcase.crash_type,
          'crashStateLines': (testcase.crash_state or '').strip().splitlines(),
          'isSecurity': testcase.security_flag,
          'issueNumber': testcase.bug_information,
          'job': testcase.job_type,
          'fuzzerName': testcase.overridden_fuzzer_name or testcase.fuzzer_name
      }
    row['testcase'] = testcase


def get_result(this):
  """Get the result."""
  params = {k: v for k, v in this.request.iterparams()}
  page = helpers.cast(
      this.request.get('page') or 1, int, "'page' is not an int.")

  query = datastore_query.Query(data_types.TestcaseUploadMetadata)
  query.order('timestamp', is_desc=True)

  if not access.has_access(need_privileged_access=True):
    query.filter('uploader_email', helpers.get_user_email())
    params['permission'] = {'uploaderEmail': helpers.get_user_email()}

  entities, total_pages, total_items, has_more = query.fetch_page(
      page=page, page_size=PAGE_SIZE, projection=None, more_limit=MORE_LIMIT)

  items = []
  for entity in entities:
    items.append({
        'timestamp': utils.utc_datetime_to_timestamp(entity.timestamp),
        'testcaseId': entity.testcase_id,
        'uploaderEmail': entity.uploader_email,
        'filename': entity.filename,
        'bundled': entity.bundled,
        'pathInArchive': entity.path_in_archive,
        'status': entity.status
    })

  attach_testcases(items)

  result = {
      'hasMore': has_more,
      'items': items,
      'page': page,
      'pageSize': PAGE_SIZE,
      'totalItems': total_items,
      'totalPages': total_pages,
  }
  return result, params


def _read_to_stringio(gcs_path):
  """Return a StringIO representing a GCS object."""
  data = storage.read_data(gcs_path)
  if not data:
    raise helpers.EarlyExitException('Failed to read uploaded archive.')

  return StringIO.StringIO(data)


def guess_input_file(uploaded_file, filename):
  """Guess the main test case file from an archive."""
  for file_pattern in RUN_FILE_PATTERNS:
    blob_reader = _read_to_stringio(uploaded_file.gcs_path)
    file_path_input = archive.get_first_file_matching(file_pattern, blob_reader,
                                                      filename)
    if file_path_input:
      return file_path_input

  return None


def query_testcase(testcase_id):
  """Start a query for an associated testcase."""
  if not testcase_id:
    return []

  return data_types.Testcase.query(data_types.Testcase.key == ndb.Key(
      data_types.Testcase, testcase_id)).iter(
          limit=1,
          projection=[
              data_types.Testcase.crash_type,
              data_types.Testcase.crash_state,
              data_types.Testcase.security_flag,
              data_types.Testcase.bug_information,
              data_types.Testcase.job_type,
              data_types.Testcase.fuzzer_name,
              data_types.Testcase.overridden_fuzzer_name,
          ])


def filter_target_names(targets, engine):
  """Filter target names for a fuzzer and remove parent fuzzer prefixes."""
  prefix = engine + '_'
  return [t[len(prefix):] for t in targets if t.startswith(prefix)]


def find_fuzz_target(engine, target_name, job_name):
  """Find a fuzz target given the engine, target name (which may or may not be
  prefixed with project), and job."""
  project_name = data_handler.get_project_name(job_name)
  candidate_name = data_types.fuzz_target_fully_qualified_name(
      engine, project_name, target_name)

  target = data_handler.get_fuzz_target(candidate_name)
  if target:
    return target.fully_qualified_name(), target.binary

  return None, None


class Handler(base_handler.Handler):
  """Handler for the testcase uploads page."""

  @handler.get(handler.HTML)
  def get(self):
    """Handles get request."""
    email = helpers.get_user_email()
    if not email:
      raise helpers.AccessDeniedException()

    is_privileged_or_domain_user = access.has_access(
        need_privileged_access=False)

    if is_privileged_or_domain_user:
      # Privileged and domain users can see all job and fuzzer names.
      allowed_jobs = data_handler.get_all_job_type_names()
      allowed_fuzzers = data_handler.get_all_fuzzer_names_including_children(
          include_parents=True)
    else:
      # Check if this is an external user with access to certain fuzzers/jobs.
      allowed_jobs = external_users.allowed_jobs_for_user(email)
      allowed_fuzzers = external_users.allowed_fuzzers_for_user(
          email, include_from_jobs=True)

      if not allowed_fuzzers and not allowed_jobs:
        raise helpers.AccessDeniedException()

    has_issue_tracker = bool(data_handler.get_issue_tracker_name())

    result, params = get_result(self)
    self.render(
        'upload.html', {
            'fieldValues': {
                'jobs':
                    allowed_jobs,
                'libfuzzerTargets':
                    filter_target_names(allowed_fuzzers, 'libFuzzer'),
                'aflTargets':
                    filter_target_names(allowed_fuzzers, 'afl'),
                'isChromium':
                    utils.is_chromium(),
                'sandboxedJobs':
                    data_types.INTERNAL_SANDBOXED_JOB_TYPES,
                'csrfToken':
                    form.generate_csrf_token(),
                'isExternalUser':
                    not is_privileged_or_domain_user,
                'uploadInfo':
                    gcs.prepare_blob_upload()._asdict(),
                'hasIssueTracker':
                    has_issue_tracker,
            },
            'params': params,
            'result': result
        })


class PrepareUploadHandler(base_handler.Handler):
  """Handler that creates an upload URL."""

  @handler.check_user_access(need_privileged_access=False)
  def post(self):
    """Serves the url."""
    self.render_json({'uploadInfo': gcs.prepare_blob_upload()._asdict()})


class UploadUrlHandlerOAuth(base_handler.Handler):
  """Handler that creates an upload URL (OAuth)."""

  UPLOAD_URL = '/upload-testcase/upload-oauth'

  @handler.oauth
  @handler.check_user_access(need_privileged_access=False)
  def post(self):
    """Serves the url."""
    self.render_json({
        'uploadUrl': blobstore.create_upload_url(self.UPLOAD_URL)
    })


class JsonHandler(base_handler.Handler):
  """JSON handler for past testcase uploads."""

  @handler.post(handler.JSON, handler.JSON)
  def post(self):
    """Handles a post request."""
    if not helpers.get_user_email():
      raise helpers.AccessDeniedException()

    result, _ = get_result(self)
    self.render_json(result)


class UploadHandlerCommon(object):
  """Handler that uploads the testcase file."""

  def get_upload(self):
    """Get the upload."""
    raise NotImplementedError

  def do_post(self):
    """Upload a testcase."""
    testcase_id = self.request.get('testcaseId')
    uploaded_file = self.get_upload()
    if testcase_id and not uploaded_file:
      testcase = helpers.get_testcase(testcase_id)
      if not access.can_user_access_testcase(testcase):
        raise helpers.AccessDeniedException()

      # Use minimized testcase for upload (if available).
      key = (
          testcase.minimized_keys if testcase.minimized_keys and
          testcase.minimized_keys != 'NA' else testcase.fuzzed_keys)

      uploaded_file = blobs.get_blob_info(key)

    job_type = self.request.get('job')
    if (not job_type or not data_types.Job.VALID_NAME_REGEX.match(job_type) or
        not data_types.Job.query(data_types.Job.name == job_type).get()):
      raise helpers.EarlyExitException('Invalid job name.', 400)

    fuzzer_name = ''
    job_type_lowercase = job_type.lower()
    if 'libfuzzer' in job_type_lowercase:
      fuzzer_name = 'libFuzzer'
    elif 'afl' in job_type_lowercase:
      fuzzer_name = 'afl'

    target_name = self.request.get('target')
    if not fuzzer_name and target_name:
      raise helpers.EarlyExitException(
          'Target name is not applicable to non-engine jobs (AFL, libFuzzer).',
          400)

    if fuzzer_name and not target_name:
      raise helpers.EarlyExitException(
          'Missing target name for engine job (AFL, libFuzzer).', 400)

    if (target_name and
        not data_types.Fuzzer.VALID_NAME_REGEX.match(target_name)):
      raise helpers.EarlyExitException('Invalid target name.', 400)

    fully_qualified_fuzzer_name = ''
    if fuzzer_name and target_name:
      fully_qualified_fuzzer_name, target_name = find_fuzz_target(
          fuzzer_name, target_name, job_type)
      if not fully_qualified_fuzzer_name:
        raise helpers.EarlyExitException('Target does not exist.', 400)

    if not access.has_access(
        need_privileged_access=False,
        job_type=job_type,
        fuzzer_name=(fully_qualified_fuzzer_name or fuzzer_name)):
      raise helpers.AccessDeniedException()

    multiple_testcases = bool(self.request.get('multiple'))
    http_flag = bool(self.request.get('http'))
    high_end_job = bool(self.request.get('highEnd'))
    bug_information = self.request.get('issue')
    crash_revision = self.request.get('revision')
    timeout = self.request.get('timeout')
    retries = self.request.get('retries')
    bug_summary_update_flag = bool(self.request.get('updateIssue'))
    additional_arguments = self.request.get('args')
    app_launch_command = self.request.get('cmd')
    platform_id = self.request.get('platform')

    testcase_metadata = self.request.get('metadata')
    if testcase_metadata:
      try:
        testcase_metadata = json.loads(testcase_metadata)
        if not isinstance(testcase_metadata, dict):
          raise helpers.EarlyExitException('Metadata is not a JSON object.',
                                           400)
      except Exception:
        raise helpers.EarlyExitException('Invalid metadata JSON.', 400)

    archive_state = 0
    bundled = False
    file_path_input = ''
    email = helpers.get_user_email()

    # If we have a AFL or libFuzzer target, use that for arguments.
    # Launch command looks like
    # python launcher.py {testcase_path} {target_name}
    if target_name:
      additional_arguments = '%%TESTCASE%% %s' % target_name

    # Certain modifications such as app launch command, issue updates are only
    # allowed for privileged users.
    privileged_user = access.has_access(need_privileged_access=True)
    if not privileged_user:
      if bug_information or bug_summary_update_flag:
        raise helpers.EarlyExitException(
            'You are not privileged to update existing issues.', 400)

      need_privileged_access = utils.string_is_true(
          data_handler.get_value_from_job_definition(job_type,
                                                     'PRIVILEGED_ACCESS'))
      if need_privileged_access:
        raise helpers.EarlyExitException(
            'You are not privileged to run this job type.', 400)

      if app_launch_command:
        raise helpers.EarlyExitException(
            'You are not privileged to run arbitary launch commands.', 400)

      if testcase_metadata:
        raise helpers.EarlyExitException(
            'You are not privileged to set testcase metadata.', 400)

    if crash_revision and crash_revision.isdigit():
      crash_revision = int(crash_revision)
    else:
      crash_revision = 0

    if bug_information and not bug_information.isdigit():
      raise helpers.EarlyExitException('Bug is not a number.', 400)

    if not timeout:
      timeout = 0
    elif not timeout.isdigit() or timeout == '0':
      raise helpers.EarlyExitException(
          'Testcase timeout must be a number greater than 0.', 400)
    else:
      timeout = int(timeout)
      if timeout > 120:
        raise helpers.EarlyExitException(
            'Testcase timeout may not be greater than 120 seconds.', 400)

    if retries:
      if retries.isdigit():
        retries = int(retries)
      else:
        retries = None

      if retries is None or retries > MAX_RETRIES:
        raise helpers.EarlyExitException(
            'Testcase retries must be a number less than %d.' % MAX_RETRIES,
            400)
    else:
      retries = None

    try:
      gestures = ast.literal_eval(self.request.get('gestures'))
    except:
      gestures = []
    if not gestures:
      gestures = []

    job_queue = tasks.queue_for_job(job_type, is_high_end=high_end_job)

    if uploaded_file is not None:
      filename = ''.join([
          x for x in uploaded_file.filename if x not in ' ;/?:@&=+$,{}|<>()\\'
      ])
      key = str(uploaded_file.key())
      if archive.is_archive(filename):
        archive_state = data_types.ArchiveStatus.FUZZED
      if archive_state:
        if multiple_testcases:
          if testcase_metadata:
            raise helpers.EarlyExitException(
                'Testcase metadata not supported with multiple testcases.', 400)
          # Create a job to unpack an archive.
          metadata = data_types.BundledArchiveMetadata()
          metadata.blobstore_key = key
          metadata.timeout = timeout
          metadata.job_queue = job_queue
          metadata.job_type = job_type
          metadata.http_flag = http_flag
          metadata.archive_filename = filename
          metadata.uploader_email = email
          metadata.gestures = gestures
          metadata.crash_revision = crash_revision
          metadata.additional_arguments = additional_arguments
          metadata.bug_information = bug_information
          metadata.platform_id = platform_id
          metadata.app_launch_command = app_launch_command
          metadata.fuzzer_name = fuzzer_name
          metadata.overridden_fuzzer_name = fully_qualified_fuzzer_name
          metadata.fuzzer_binary_name = target_name
          metadata.put()

          tasks.add_task(
              'unpack',
              str(metadata.key.id()),
              job_type,
              queue=tasks.queue_for_job(job_type))

          # Create a testcase metadata object to show the user their upload.
          upload_metadata = data_types.TestcaseUploadMetadata()
          upload_metadata.timestamp = datetime.datetime.utcnow()
          upload_metadata.filename = filename
          upload_metadata.blobstore_key = key
          upload_metadata.original_blobstore_key = key
          upload_metadata.status = 'Pending'
          upload_metadata.bundled = True
          upload_metadata.uploader_email = email
          upload_metadata.retries = retries
          upload_metadata.bug_summary_update_flag = bug_summary_update_flag
          upload_metadata.put()

          helpers.log('Uploaded multiple testcases.', helpers.VIEW_OPERATION)
          self.render_json({'multiple': True})
          return

        file_path_input = guess_input_file(uploaded_file, filename)
        if not file_path_input:
          raise helpers.EarlyExitException(
              ("Unable to detect which file to launch. The main file\'s name "
               'must contain either of %s.' % str(RUN_FILE_PATTERNS)), 400)

    else:
      raise helpers.EarlyExitException('Please select a file to upload.', 400)

    testcase_id = data_handler.create_user_uploaded_testcase(
        key,
        key,
        archive_state,
        filename,
        file_path_input,
        timeout,
        job_type,
        job_queue,
        http_flag,
        gestures,
        additional_arguments,
        bug_information,
        crash_revision,
        email,
        platform_id,
        app_launch_command,
        fuzzer_name,
        fully_qualified_fuzzer_name,
        target_name,
        bundled,
        retries,
        bug_summary_update_flag,
        additional_metadata=testcase_metadata)

    helpers.log('Uploaded testcase %s' % testcase_id, helpers.VIEW_OPERATION)
    self.render_json({'id': '%s' % testcase_id})


class UploadHandler(UploadHandlerCommon, base_handler.GcsUploadHandler):
  """Handler that uploads the testcase file."""

  # pylint: disable=unused-argument
  def before_render_json(self, values, status):
    """Add upload info when the request fails."""
    values['uploadInfo'] = gcs.prepare_blob_upload()._asdict()

  def get_upload(self):
    return base_handler.GcsUploadHandler.get_upload(self)

  @handler.post(handler.FORM, handler.JSON)
  @handler.require_csrf_token
  def post(self):
    self.do_post()


class UploadHandlerOAuth(base_handler.Handler, UploadHandlerCommon,
                         blobstore_handlers.BlobstoreUploadHandler):
  """Handler that uploads the testcase file (OAuth)."""

  # pylint: disable=unused-argument
  def before_render_json(self, values, status):
    """Add upload info when the request fails."""
    # TODO(ochang): Migrate to GCS upload.
    values['uploadUrl'] = blobstore.create_upload_url('/upload-testcase/upload')

  def get_upload(self):
    return (self.get_uploads() or [None])[0]

  @handler.oauth
  @handler.post(handler.FORM, handler.JSON)
  def post(self):
    self.do_post()
