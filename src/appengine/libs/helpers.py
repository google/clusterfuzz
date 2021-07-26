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
"""helper.py is a kitchen sink. It contains static methods that are used by
   multiple handlers."""

import logging
import sys
import traceback

from clusterfuzz._internal.base import errors
from clusterfuzz._internal.datastore import data_handler
from libs import auth
from libs.issue_management import issue_tracker_utils

VIEW_OPERATION = 'View'
MODIFY_OPERATION = 'Modify'
TTL_IN_SECONDS = 15 * 60


class _DoNotCatchException(Exception):
  """Serve as a dummy exception to avoid catching any exception."""


class EarlyExitException(Exception):
  """Serve as an exception for exiting a handler's method early."""

  def __init__(self, message, status, trace_dump=None):
    super(EarlyExitException, self).__init__(message)
    self.status = status
    self.trace_dump = trace_dump
    if self.trace_dump is None:
      if sys.exc_info()[0] is not None:
        self.trace_dump = traceback.format_exc()
      else:
        self.trace_dump = ''.join(traceback.format_stack())

  def to_dict(self):
    """Build dict that is used for JSON serialisation."""
    return {
        'traceDump': self.trace_dump,
        'message': str(self),
        'email': get_user_email(),
        'status': self.status,
        'type': self.__class__.__name__
    }


class AccessDeniedException(EarlyExitException):
  """Serve as an exception for exiting a handler's method with 403."""

  def __init__(self, message=''):
    super(AccessDeniedException, self).__init__(message, 403, '')


class UnauthorizedException(EarlyExitException):
  """Serve as an exception for exiting a handler's method with 401."""

  def __init__(self, message=''):
    super(UnauthorizedException, self).__init__(message, 401, '')


def get_testcase(testcase_id):
  """Get a valid testcase or raise EarlyExitException."""
  testcase = None
  try:
    testcase = data_handler.get_testcase_by_id(testcase_id)
  except errors.InvalidTestcaseError:
    pass

  if not testcase:
    raise EarlyExitException("Testcase (id=%s) doesn't exist" % testcase_id,
                             404)
  return testcase


def get_issue_tracker_for_testcase(testcase):
  """Get an IssueTracker or raise EarlyExitException."""
  issue_tracker = issue_tracker_utils.get_issue_tracker_for_testcase(testcase)
  if not issue_tracker:
    raise EarlyExitException(
        "The testcase doesn't have a corresponding issue tracker", 404)
  return issue_tracker


def cast(value, fn, error_message):
  """Return `fn(value)` or raise an EarlyExitException with 400."""
  try:
    return fn(value)
  except (ValueError, TypeError):
    raise EarlyExitException(error_message, 400)


def should_render_json(accepts, content_type):
  """Check accepts and content_type to see if we should render JSON."""
  return 'application/json' in accepts or content_type == 'application/json'


def _is_not_empty(value):
  """Check if value is empty value or a tuple of empty values."""
  if isinstance(value, tuple):
    return any(bool(elem) for elem in value)

  return bool(value)


def get_or_exit(fn,
                not_found_message,
                error_message,
                not_found_exception=_DoNotCatchException,
                non_empty_fn=_is_not_empty):
  """Get an entity using `fn`. If the returning entity is nothing (e.g. None or
    a tuple on Nones), it raises 404.

    Args:
      fn: the function to get an entity. It's a function because fn(..) might
          raise an exception.
      not_found_message: the 404 HTTP error is raised with not_found_message for
          an empty entity.
      error_message: the 500 HTTP error is raised with error_message for any
          other exception from fn(..).
      not_found_exception: the type of exception that will be considered as
          'not found' as opposed to other errors."""
  result = None
  try:
    result = fn()
  except not_found_exception:
    pass
  except Exception:
    raise EarlyExitException(
        '%s (%s: %s)' % (error_message, sys.exc_info()[0], str(
            sys.exc_info()[1])), 500)

  if non_empty_fn(result):
    return result
  raise EarlyExitException(not_found_message, 404)


def get_user_email():
  """Returns currently logged-in user's email."""
  try:
    return auth.get_current_user().email
  except Exception:
    return ''


def get_integer_key(request):
  """Convenience function for getting an integer datastore key ID."""
  key = request.get('key')
  try:
    return int(key)
  except (ValueError, KeyError):
    raise EarlyExitException('Invalid key format.', 400)


def log(message, operation_type):
  """Logs operation being carried by current logged-in user."""
  logging.info('ClusterFuzz: %s (%s): %s.', operation_type, get_user_email(),
               message)
