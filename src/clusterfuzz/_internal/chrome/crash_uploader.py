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
"""Crash minidump and symbols uploader."""

import email
import os
import re
import tempfile

import requests

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.build_management import revisions
from clusterfuzz._internal.crash_analysis.stack_parsing import stack_parser
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.google_cloud_utils import blobs
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.platforms.android import adb
from clusterfuzz._internal.platforms.android import constants
from clusterfuzz._internal.protos import process_state_pb2
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.system import process_handler

CRASH_REPORT_UPLOAD_URL = {
    'staging': 'https://clients2.google.com/cr/staging_report',
    'prod': 'https://clients2.google.com/cr/report',
}

BOT_ID_KEY = 'botId'
CF_ID_KEY = 'clusterfuzzId'
CRASH_DUMP_PATH_MARKER = 'Output crash dump:'
PRODUCT_KEY = 'product'
PRODUCT_MAP = {
    'ANDROID': 'Chrome_Android',
    'LINUX': 'Chrome_Linux',
    'MAC': 'Chrome_Mac',
    'WINDOWS': 'Chrome',
}
PROCESSED_REPORT_FILE_KEY = 'processedReport'
MINIDUMP_FILE_KEY = 'upload_file_minidump'
VERSION_KEY = 'version'


def post_with_retries(upload_url, params, files):
  """Perform HTTP POST request to given upload url with provided params."""
  retry_limit = environment.get_value('FAIL_RETRIES')
  for _ in range(retry_limit):
    try:
      result = requests.post(upload_url, data=params, files=files)
      if result.status_code == requests.codes.ok:
        return result.text

      # No need to retry on a non-200 status code.
      logs.log_error(
          'Failed to upload request, error code %d.' % result.status_code)
      return None
    except Exception:
      # To catch cases like connection error, timeout error, etc.
      logs.log_warn('Failed to upload request, retrying.')

  logs.log_error('Could not upload request after retries.')
  return None


class FileMetadataInfo(object):
  """Handles file metadata for e.g. minidumps and processed reports."""

  def __init__(self, path=None, key=None, contents=None):
    self._path = path
    self._key = key
    self._contents = contents

  @property
  def path(self):
    return self._path

  @path.setter
  def path(self, local_path):
    self._path = local_path

  @property
  def key(self):
    return self._key

  @key.setter
  def key(self, key):
    self._key = key

  @property
  def contents(self):
    return self._contents

  @contents.setter
  def contents(self, contents):
    self._contents = contents

  def get_file_handle(self):
    """Return file handle to metadata contents. Prefer to use blobstore key if
       available, otherwise raw contents."""
    if self.key:
      contents = blobs.read_key(self.key)
    elif self.contents:
      contents = self.contents
    else:
      # No bot-independent file for which to get a file handle. Let the caller
      # handle any errors.
      return None

    metadata_file = tempfile.TemporaryFile()
    metadata_file.write(contents)
    metadata_file.seek(0)
    return metadata_file


class CrashReportInfo(object):
  """Stores the data collected from a run (via stacktrace or other) to be
     used in uploading to Chromecrash."""

  def __init__(self,
               minidump_path=None,
               minidump_contents=None,
               minidump_key=None,
               product=None,
               version=None,
               optional_params=None,
               unsymbolized_stacktrace=None,
               symbolized_stacktrace=None,
               testcase_id=None,
               bot_id=None,
               serialized_crash_stack_frames=None):
    self._minidump_info = FileMetadataInfo(
        path=minidump_path, contents=minidump_contents, key=minidump_key)
    self._minidump_path = minidump_path
    self._product = product
    self._version = version
    if optional_params is None:
      self._optional_params = {}
    else:
      self._optional_params = optional_params
    self._unsymbolized_stacktrace = unsymbolized_stacktrace
    self._symbolized_stacktrace = symbolized_stacktrace
    self._testcase_id = testcase_id
    self._bot_id = bot_id
    self._serialized_crash_stack_frames = serialized_crash_stack_frames

  @property
  def minidump_info(self):
    return self._minidump_info

  @minidump_info.setter
  def minidump_info(self, minidump_info):
    self._minidump_info = minidump_info

  @property
  def product(self):
    return self._product

  @product.setter
  def product(self, product):
    self._product = product

  @property
  def version(self):
    return self._version

  @version.setter
  def version(self, version):
    self._version = version

  @property
  def optional_params(self):
    return self._optional_params

  @optional_params.setter
  def optional_params(self, params):
    self._optional_params = params

  @property
  def unsymbolized_stacktrace(self):
    return self._unsymbolized_stacktrace

  @unsymbolized_stacktrace.setter
  def unsymbolized_stacktrace(self, stacktrace):
    self._unsymbolized_stacktrace = stacktrace

  @property
  def symbolized_stacktrace(self):
    return self._symbolized_stacktrace

  @symbolized_stacktrace.setter
  def symbolized_stacktrace(self, stacktrace):
    self._symbolized_stacktrace = stacktrace

  @property
  def testcase_id(self):
    return self._testcase_id

  @testcase_id.setter
  def testcase_id(self, testcase_id):
    self._testcase_id = testcase_id

  @property
  def bot_id(self):
    return self._bot_id

  @bot_id.setter
  def bot_id(self, bot_id):
    self._bot_id = bot_id

  @property
  def serialized_crash_stack_frames(self):
    return self._serialized_crash_stack_frames

  @serialized_crash_stack_frames.setter
  def serialized_crash_stack_frames(self, serialized_crash_stack_frames):
    self._serialized_crash_stack_frames = serialized_crash_stack_frames

  def upload(self):
    """Upload the minidump represented by self, with any other params to send
       along with the POST request."""
    if self.product is None or self.version is None:
      logs.log_error('Missing product/version info, cannot upload.')
      return None

    report_file = FileMetadataInfo(
        contents=self.serialized_crash_stack_frames).get_file_handle()
    if report_file is None:
      logs.log_warn('Missing processed report, falling back to minidump.')

    # Get minidump if there is one, but don't worry if there isn't. Just having
    # a report file is fine.
    minidump_file = self.minidump_info.get_file_handle()

    if report_file is None and minidump_file is None:
      logs.log_error('Neither processed report nor minidump, nothing to '
                     'upload.')
      return None

    # Build the upload parameters.
    params = {}
    params[PRODUCT_KEY] = self.product
    params[VERSION_KEY] = self.version
    if self.testcase_id is not None:
      params[CF_ID_KEY] = self.testcase_id
    if self.bot_id is not None:
      params[BOT_ID_KEY] = self.bot_id

    files = {}
    if report_file is not None:
      files[PROCESSED_REPORT_FILE_KEY] = report_file
    if minidump_file is not None:
      files[MINIDUMP_FILE_KEY] = minidump_file

    # Send off the report, returning the report ID.
    mode = environment.get_value('UPLOAD_MODE')
    if not mode or mode not in CRASH_REPORT_UPLOAD_URL:
      logs.log_warn(
          'Missing or unknown mode (%s); uploading to staging.' % str(mode))
      mode = 'staging'
    return post_with_retries(CRASH_REPORT_UPLOAD_URL[mode], params, files)

  def store_minidump(self):
    """Store the crash minidump in appengine and return key."""
    if not self.minidump_info.path:
      return ''

    minidump_key = ''
    logs.log('Storing minidump (%s) in blobstore.' % self.minidump_info.path)
    try:
      minidump_key = ''
      with open(self.minidump_info.path, 'rb') as file_handle:
        minidump_key = blobs.write_blob(file_handle)
    except:
      logs.log_error('Failed to store minidump.')

    if minidump_key:
      self.minidump_info = FileMetadataInfo(
          path=self.minidump_info.path, key=minidump_key)

    return minidump_key

  def to_report_metadata(self):
    """Export to ReportMetadata for batching upload."""
    return data_types.ReportMetadata(
        product=self.product,
        version=str(self.version),
        minidump_key=self.minidump_info.key,
        serialized_crash_stack_frames=self.serialized_crash_stack_frames,
        testcase_id=str(self.testcase_id),
        bot_id=str(self.bot_id))


def crash_report_info_from_metadata(report_metadata):
  """Return CrashReportInfo given ReportMetadata for uploading."""
  return CrashReportInfo(
      product=report_metadata.product,
      version=report_metadata.version,
      minidump_key=report_metadata.minidump_key,
      serialized_crash_stack_frames=(
          report_metadata.serialized_crash_stack_frames),
      testcase_id=(report_metadata.testcase_id or None),
      bot_id=(report_metadata.bot_id or None))


def parse_mime_to_crash_report_info(local_minidump_mime_path):
  """Read the (local) minidump MIME file into a CrashReportInfo object."""
  # Get the minidump name and path.
  minidump_path_match = re.match(r'(.*)\.mime', local_minidump_mime_path)
  if minidump_path_match is None:
    logs.log_error('Minidump filename in unexpected format: \'%s\'.' %
                   local_minidump_mime_path)
    return None
  minidump_path = '%s.dmp' % minidump_path_match.group(1).strip()

  # Reformat the minidump MIME to include the boundary.
  with open(local_minidump_mime_path, 'rb') as minidump_mime_file_content:
    # The boundary is the first line after the first two dashes.
    boundary = minidump_mime_file_content.readline().strip()[2:]
    minidump_mime_bytes = (
        b'Content-Type: multipart/form-data; boundary=\"%s\"\r\n--%s\r\n' %
        (boundary, boundary))
    minidump_mime_bytes += minidump_mime_file_content.read()

  minidump_mime_contents = email.message_from_bytes(minidump_mime_bytes)

  # Parse the MIME contents, extracting the parameters needed for upload.
  mime_key_values = {}
  for mime_part in minidump_mime_contents.get_payload():
    if isinstance(mime_part, str):
      mime_part = utils.decode_to_unicode(mime_part)
      logs.log_error('Unexpected str mime_part from mime path %s: %s' %
                     (local_minidump_mime_path, mime_part))
      continue
    part_descriptor = list(mime_part.values())
    key_tokens = part_descriptor[0].split('; ')
    key_match = re.match(r'name="(.*)".*', key_tokens[1])

    # Extract from the MIME part the key-value pairs used by report uploading.
    if key_match is not None:
      report_key = key_match.group(1)
      report_value = mime_part.get_payload(decode=True)
      if report_key == MINIDUMP_FILE_KEY:
        utils.write_data_to_file(report_value, minidump_path)
      else:
        # Take care of aliases.
        if report_key in ('prod', 'buildTargetId'):
          report_key = PRODUCT_KEY
        elif report_key == 'ver':
          report_key = VERSION_KEY

        # Save the key-value pair.
        mime_key_values[report_key] = report_value

  # Pull out product and version explicitly since these are required
  # for upload.
  product, version = None, None
  if PRODUCT_KEY in mime_key_values:
    product = mime_key_values.pop(PRODUCT_KEY).decode('utf-8')
  else:
    logs.log_error(
        'Could not find \'%s\' or alias in mime_key_values key.' % PRODUCT_KEY)
  if VERSION_KEY in mime_key_values:
    version = mime_key_values.pop(VERSION_KEY).decode('utf-8')
  else:
    logs.log_error(
        'Could not find \'%s\' or alias in mime_key_values key.' % VERSION_KEY)

  # If missing, return None and log keys that do exist; otherwise, construct
  # CrashReportInfo and return.
  if product is None or version is None:
    logs.log_error(
        'mime_key_values dict keys:\n%s' % str(list(mime_key_values.keys())))
    return None

  return CrashReportInfo(
      minidump_path=minidump_path,
      product=product,
      version=version,
      optional_params=mime_key_values)


def get_crash_info(output):
  """Parse crash output to get (local) minidump path and any other information
     useful for crash uploading, and store in a CrashReportInfo object."""
  crash_stacks_directory = environment.get_value('CRASH_STACKTRACES_DIR')

  output_lines = output.splitlines()
  num_lines = len(output_lines)
  is_android = environment.is_android()
  for i, line in enumerate(output_lines):
    if is_android:
      # If we are on Android, the dump extraction is more complicated.
      # The location placed in the crash-stacktrace is of the dump itself but
      # in fact only the MIME of the dump exists, and will have a different
      # extension. We need to pull the MIME and process it.
      match = re.match(CRASH_DUMP_PATH_MARKER, line)
      if not match:
        continue

      minidump_mime_filename_base = None
      for j in range(i + 1, num_lines):
        line = output_lines[j]
        match = re.match(r'(.*)\.dmp', line)
        if match:
          minidump_mime_filename_base = os.path.basename(match.group(1).strip())
          break
      if not minidump_mime_filename_base:
        logs.log_error('Minidump marker was found, but no path in stacktrace.')
        return None

      # Look for MIME. If none found, bail.
      # We might not have copied over the crash dumps yet (copying is buffered),
      # so we want to search both the original directory and the one to which
      # the minidumps should later be copied.
      device_directories_to_search = [
          constants.CRASH_DUMPS_DIR,
          os.path.dirname(line.strip())
      ]
      device_minidump_search_paths = []
      device_minidump_mime_path = None

      for device_directory in device_directories_to_search:
        device_minidump_mime_potential_paths = adb.run_shell_command(
            ['ls', '"%s"' % device_directory], root=True).splitlines()
        device_minidump_search_paths += device_minidump_mime_potential_paths

        for potential_path in device_minidump_mime_potential_paths:
          # Check that we actually found a file, and the right one (not logcat).
          if 'No such file or directory' in potential_path:
            continue

          if minidump_mime_filename_base not in potential_path:
            continue

          if '.up' in potential_path or '.dmp' in potential_path:
            device_minidump_mime_path = os.path.join(device_directory,
                                                     potential_path)
            break

        # Break if we found a path.
        if device_minidump_mime_path is not None:
          break

      # If we still didn't find a minidump path, bail.
      if device_minidump_mime_path is None:
        logs.log_error('Could not get MIME path from ls:\n%s' %
                       str(device_minidump_search_paths))
        return None

      # Pull out MIME and parse to minidump file and MIME parameters.
      minidump_mime_filename = '%s.mime' % minidump_mime_filename_base
      local_minidump_mime_path = os.path.join(crash_stacks_directory,
                                              minidump_mime_filename)
      adb.run_command([
          'pull',
          '"%s"' % device_minidump_mime_path, local_minidump_mime_path
      ])
      if not os.path.exists(local_minidump_mime_path):
        logs.log_error('Could not pull MIME from %s to %s.' %
                       (device_minidump_mime_path, local_minidump_mime_path))
        return None

      crash_info = parse_mime_to_crash_report_info(local_minidump_mime_path)
      if crash_info is None:
        return None

      crash_info.unsymbolized_stacktrace = output
      return crash_info

    # Other platforms are not currently supported.
    logs.log_error('Unable to fetch crash information for this platform.')
    return None

  # Could not find dump location, bail out. This could also happen when we don't
  # have a minidump location in stack at all, e.g. when testcase does not crash
  # during minimization.
  return None


def get_crash_info_and_stacktrace(application_command_line, crash_stacktrace,
                                  gestures):
  """Return crash minidump location and updated crash stacktrace."""
  app_name_lower = environment.get_value('APP_NAME').lower()
  retry_limit = environment.get_value('FAIL_RETRIES')
  using_android = environment.is_android()
  using_chrome = 'chrome' in app_name_lower or 'chromium' in app_name_lower
  warmup_timeout = environment.get_value('WARMUP_TIMEOUT', 90)

  # Minidump generation is only applicable on Chrome application.
  # FIXME: Support minidump generation on platforms other than Android.
  if not using_chrome or not using_android:
    return None, crash_stacktrace

  # Get the crash info from stacktrace.
  crash_info = get_crash_info(crash_stacktrace)

  # If we lost the minidump file, we need to recreate it.
  # Note that because of the way crash_info is generated now, if we have a
  # non-None crash_info, we should also have its minidump path; we insert
  # the check to safeguard against possibly constructing the crash_info in
  # other ways in the future that might potentially lose the minidump path.
  if not crash_info or not crash_info.minidump_info.path:
    for _ in range(retry_limit):
      _, _, output = (
          process_handler.run_process(
              application_command_line,
              timeout=warmup_timeout,
              gestures=gestures))

      crash_info = get_crash_info(output)
      if crash_info and crash_info.minidump_info.path:
        crash_stacktrace = utils.decode_to_unicode(output)
        break

    if not crash_info or not crash_info.minidump_info.path:
      # We could not regenerate a minidump for this crash.
      logs.log('Unable to regenerate a minidump for this crash.')

  return crash_info, crash_stacktrace


def get_symbolized_stack_bytes(crash_type, crash_address, symbolized_stack):
  """Get bytes for symbolized crash proto."""
  # FIXME: For some tests, crash_address is literally 'address'.
  crash_address = stack_parser.format_address_to_dec(crash_address)
  if crash_address is None:
    # Instead of ignoring such reports, we pass 0xDEADBEEF address.
    # Crash address is not applicable to many crash types (e.g. CHECK failures,
    # MSan and UBSan crashes).
    crash_address = 0xDEADBEEF

  # TODO(jchinlee): Add os[_info] and cpu[_info] in form crash/ expects.
  process_state = process_state_pb2.ProcessStateProto(
      crash=process_state_pb2.ProcessStateProto.Crash(
          reason=crash_type,
          address=stack_parser.unsigned_to_signed(crash_address)),
      requesting_thread=0,
  )

  try:
    for stack in symbolized_stack:
      thread = process_state.threads.add()
      thread.frames.extend([stackframe.to_proto() for stackframe in stack])

    return process_state.SerializeToString()
  except Exception as e:
    logs.log_error(
        'Failed to get proto for crash:\n'
        'Error: %s\n'
        'Type: %s\n'
        'Address: %s\n'
        'Stack:\n%s\n' % (e, crash_type, crash_address, symbolized_stack))
    return None


def save_crash_info_if_needed(testcase_id, crash_revision, job_type, crash_type,
                              crash_address, crash_frames):
  """Saves crash report for chromium project, skip otherwise."""
  if data_handler.get_project_name(job_type) != 'chromium':
    return None

  serialized_crash_stack_frames = get_symbolized_stack_bytes(
      crash_type, crash_address, crash_frames)
  if not serialized_crash_stack_frames:
    return None

  crash_info = CrashReportInfo(
      serialized_crash_stack_frames=serialized_crash_stack_frames)

  # Get product and version (required).
  platform = environment.platform()
  crash_info.product = PRODUCT_MAP[platform]
  crash_info.version = revisions.get_real_revision(
      crash_revision, job_type, display=True)

  # Update crash_info object with bot information and testcase id.
  crash_info.bot_id = environment.get_value('BOT_NAME')
  crash_info.testcase_id = int(testcase_id)

  # Store CrashInfo metadata.
  crash_report_metadata = crash_info.to_report_metadata()
  crash_report_metadata.job_type = job_type
  crash_report_metadata.crash_revision = crash_revision
  crash_report_metadata.put()

  logs.log('Created crash report entry for testcase %s.' % testcase_id)
  return crash_info
