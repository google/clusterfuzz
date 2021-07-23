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
"""Manage fuzzers types."""

import datetime
import io

from flask import request
from google.cloud import ndb

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.fuzzing import fuzzer_selection
from clusterfuzz._internal.google_cloud_utils import storage
from clusterfuzz._internal.metrics import fuzzer_logs
from clusterfuzz._internal.system import archive
from handlers import base_handler
from libs import access
from libs import form
from libs import gcs
from libs import handler
from libs import helpers

ARCHIVE_READ_SIZE_LIMIT = 16 * 1024 * 1024


class Handler(base_handler.Handler):
  """Manages fuzzers."""

  @handler.get(handler.HTML)
  @handler.check_admin_access_if_oss_fuzz
  @handler.check_user_access(need_privileged_access=False)
  def get(self):
    """Handle a get request."""
    fuzzer_logs_bucket = fuzzer_logs.get_bucket()
    fuzzers = list(data_types.Fuzzer.query().order(data_types.Fuzzer.name))
    jobs = data_handler.get_all_job_type_names()
    corpora = [
        bundle.name for bundle in data_types.DataBundle.query().order(
            data_types.DataBundle.name)
    ]

    privileged = access.has_access(need_privileged_access=True)
    # Unprivileged users can't download fuzzers, so hide the download keys.
    if not privileged:
      for fuzzer in fuzzers:
        fuzzer.blobstore_key = ''

    template_values = {
        'privileged': privileged,
        'fuzzers': fuzzers,
        'fuzzerLogsBucket': fuzzer_logs_bucket,
        'fieldValues': {
            'corpora': corpora,
            'jobs': jobs,
            'uploadInfo': gcs.prepare_blob_upload()._asdict(),
            'csrfToken': form.generate_csrf_token(),
        }
    }

    return self.render('fuzzers.html', template_values)


class BaseEditHandler(base_handler.GcsUploadHandler):
  """Base edit handler."""

  def _read_to_bytesio(self, gcs_path):
    """Return a bytesio representing a GCS object."""
    data = storage.read_data(gcs_path)
    if not data:
      raise helpers.EarlyExitException('Failed to read uploaded archive.', 500)

    return io.BytesIO(data)

  def _get_executable_path(self, upload_info):
    """Get executable path."""
    executable_path = request.get('executable_path')
    if not upload_info:
      return executable_path

    if upload_info.size > ARCHIVE_READ_SIZE_LIMIT:
      return executable_path

    if not executable_path:
      executable_path = 'run'  # Check for default.

    reader = self._read_to_bytesio(upload_info.gcs_path)
    return archive.get_first_file_matching(executable_path, reader,
                                           upload_info.filename)

  def _get_launcher_script(self, upload_info):
    """Get launcher script path."""
    launcher_script = request.get('launcher_script')
    if not upload_info:
      return launcher_script

    if not launcher_script:
      return None

    if upload_info.size > ARCHIVE_READ_SIZE_LIMIT:
      return launcher_script

    reader = self._read_to_bytesio(upload_info.gcs_path)
    launcher_script = archive.get_first_file_matching(launcher_script, reader,
                                                      upload_info.filename)
    if not launcher_script:
      raise helpers.EarlyExitException(
          'Specified launcher script was not found in archive!', 400)

    return launcher_script

  def _get_integer_value(self, key):
    """Check a numeric input value."""
    value = request.get(key)
    if value is None:
      return None

    try:
      value = int(value)
    except (ValueError, TypeError):
      raise helpers.EarlyExitException(
          '{key} must be an integer.'.format(key=key), 400)

    if value <= 0:
      raise helpers.EarlyExitException(
          '{key} must be > 0.'.format(key=key), 400)

    return value

  def apply_fuzzer_changes(self, fuzzer, upload_info):
    """Apply changes to a fuzzer."""
    if upload_info and not archive.is_archive(upload_info.filename):
      raise helpers.EarlyExitException(
          'Sorry, only zip, tgz, tar.gz, tbz, and tar.bz2 archives are '
          'allowed!', 400)

    if fuzzer.builtin:
      executable_path = launcher_script = None
    else:
      executable_path = self._get_executable_path(upload_info)
      launcher_script = self._get_launcher_script(upload_info)

      # Executable path is required for non-builtin fuzzers and if it is not
      # already set.
      if not fuzzer.executable_path and not executable_path:
        raise helpers.EarlyExitException(
            'Please enter the path to the executable, or if the archive you '
            'uploaded is less than 16MB, ensure that the executable file has '
            '"run" in its name.', 400)

    jobs = request.get('jobs', [])
    timeout = self._get_integer_value('timeout')
    max_testcases = self._get_integer_value('max_testcases')
    external_contribution = request.get('external_contribution', False)
    differential = request.get('differential', False)
    environment_string = request.get('additional_environment_string')
    data_bundle_name = request.get('data_bundle_name')

    # Save the fuzzer file metadata.
    if upload_info:
      fuzzer.filename = upload_info.filename
      fuzzer.blobstore_key = str(upload_info.key())
      fuzzer.file_size = utils.get_size_string(upload_info.size)

    fuzzer.jobs = jobs
    fuzzer.revision = fuzzer.revision + 1
    fuzzer.source = helpers.get_user_email()
    fuzzer.timeout = timeout
    fuzzer.max_testcases = max_testcases
    fuzzer.result = None
    fuzzer.sample_testcase = None
    fuzzer.console_output = None
    fuzzer.external_contribution = bool(external_contribution)
    fuzzer.differential = bool(differential)
    fuzzer.additional_environment_string = environment_string
    fuzzer.timestamp = datetime.datetime.utcnow()
    fuzzer.data_bundle_name = data_bundle_name

    # Update only if a new archive is provided.
    if executable_path:
      fuzzer.executable_path = executable_path

    # Optional. Also, update only if a new archive is provided and contains a
    # launcher script.
    if launcher_script:
      fuzzer.launcher_script = launcher_script

    fuzzer.put()

    fuzzer_selection.update_mappings_for_fuzzer(fuzzer)

    helpers.log('Uploaded fuzzer %s.' % fuzzer.name, helpers.MODIFY_OPERATION)
    return self.redirect('/fuzzers')


class CreateHandler(BaseEditHandler):
  """Create a new fuzzer."""

  @handler.post(handler.JSON, handler.JSON)
  @handler.check_user_access(need_privileged_access=True)
  @handler.require_csrf_token
  def post(self):
    """Handle a post request."""
    name = request.get('name')
    if not name:
      raise helpers.EarlyExitException('Please give the fuzzer a name!', 400)

    if not data_types.Fuzzer.VALID_NAME_REGEX.match(name):
      raise helpers.EarlyExitException(
          'Fuzzer name can only contain letters, numbers, dashes and '
          'underscores.', 400)

    existing_fuzzer = data_types.Fuzzer.query(data_types.Fuzzer.name == name)
    if existing_fuzzer.get():
      raise helpers.EarlyExitException(
          'Fuzzer already exists. Please use the EDIT button for changes.', 400)

    upload_info = self.get_upload()
    if not upload_info:
      raise helpers.EarlyExitException('Need to upload an archive.', 400)

    fuzzer = data_types.Fuzzer()
    fuzzer.name = name
    fuzzer.revision = 0
    return self.apply_fuzzer_changes(fuzzer, upload_info)


class EditHandler(BaseEditHandler):
  """Edit or create a fuzzer."""

  @handler.post(handler.JSON, handler.JSON)
  @handler.check_user_access(need_privileged_access=True)
  @handler.require_csrf_token
  def post(self):
    """Handle a post request."""
    key = helpers.get_integer_key(request)

    fuzzer = ndb.Key(data_types.Fuzzer, key).get()
    if not fuzzer:
      raise helpers.EarlyExitException('Fuzzer not found.', 400)

    upload_info = self.get_upload()
    return self.apply_fuzzer_changes(fuzzer, upload_info)


class DeleteHandler(base_handler.Handler):
  """Delete a fuzzer."""

  @handler.post(handler.JSON, handler.JSON)
  @handler.check_user_access(need_privileged_access=True)
  @handler.require_csrf_token
  def post(self):
    """Handle a post request."""
    key = helpers.get_integer_key(request)

    fuzzer = ndb.Key(data_types.Fuzzer, key).get()
    if not fuzzer:
      raise helpers.EarlyExitException('Fuzzer not found.', 400)

    fuzzer_selection.update_mappings_for_fuzzer(fuzzer, mappings=[])
    fuzzer.key.delete()

    helpers.log('Deleted fuzzer %s' % fuzzer.name, helpers.MODIFY_OPERATION)
    return self.redirect('/fuzzers')


class LogHandler(base_handler.Handler):
  """Show the console output from a fuzzer run."""

  @handler.check_user_access(need_privileged_access=False)
  def get(self, fuzzer_name):
    """Handle a get request."""
    helpers.log('LogHandler', fuzzer_name)
    fuzzer = data_types.Fuzzer.query(
        data_types.Fuzzer.name == fuzzer_name).get()
    if not fuzzer:
      raise helpers.EarlyExitException('Fuzzer not found.', 400)

    return self.render('viewer.html', {
        'title': 'Output for ' + fuzzer.name,
        'content': fuzzer.console_output,
    })
