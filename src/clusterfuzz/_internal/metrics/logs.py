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
"""Logging functions."""

import contextlib
import dataclasses
import datetime
import enum
import functools
import json
import logging
from logging import config
import os
import platform
import socket
import sys
import threading
import time
import traceback
from typing import Any
from typing import NamedTuple
from typing import TYPE_CHECKING

from clusterfuzz._internal.system import environment

# This is needed to avoid circular import
if TYPE_CHECKING:
  from clusterfuzz._internal.cron.grouper import TestcaseAttributes
  from clusterfuzz._internal.datastore.data_types import FuzzTarget
  from clusterfuzz._internal.datastore.data_types import Testcase

# The maximum allowed log entry size is 256 KB for GCP. We set the
# STACKDRIVER_LOG_MESSAGE_LIMIT to approximately 80 KB (under 100 KB) to
# accommodate both the primary log message and potential traceback exceptions.
# This reserves roughly up to 200 KB for message content, leaving sufficient
# space for structured logging metadata within the 256 KB total limit.
STACKDRIVER_LOG_MESSAGE_LIMIT = 80000
NON_TRUNCATABLE_TYPES = (int, float, bool, type(None))
LOCAL_LOG_MESSAGE_LIMIT = 100000
LOCAL_LOG_LIMIT = 500000
_logger = None
_is_already_handling_uncaught = False
_default_extras = {}

BASE_LOGGING_LEVEL = os.getenv('LOG_LEVEL', 'INFO')


def _increment_error_count():
  """"Increment the error count metric."""
  if environment.is_running_on_swarming():
    task_name = 'swarming'
  elif environment.is_running_on_k8s():
    task_name = 'k8s'
  elif environment.is_running_on_app_engine():
    task_name = 'appengine'
  else:
    task_name = os.getenv('TASK_NAME', 'unknown')

  from clusterfuzz._internal.metrics import monitoring_metrics
  monitoring_metrics.LOG_ERROR_COUNT.increment({'task_name': task_name})


def _is_local():
  """Return whether or not in a local development environment."""
  return (bool(os.getenv('LOCAL_DEVELOPMENT')) or
          os.getenv('SERVER_SOFTWARE', '').startswith('Development/'))


def _console_logging_enabled():
  """Return bool on where console logging is enabled, usually for tests."""
  return bool(os.getenv('LOG_TO_CONSOLE'))


# TODO(pmeuleman) Revert the changeset that added these once
# https://github.com/google/clusterfuzz/pull/3422 lands.
def _file_logging_enabled() -> bool:
  """Return bool True when logging to files (bot/logs/*.log) is enabled.
  This is enabled by default."""
  return environment.get_value('LOG_TO_FILE', True)


def _cloud_logging_enabled() -> bool:
  """Return bool True where Google Cloud Logging is enabled.
  This is enabled by default but disabled for local development."""
  return (environment.get_value('LOG_TO_GCP', True) and
          not environment.is_running_unit_tests() and not _is_local())


def _allow_clusterfuzz_only(record: logging.LogRecord) -> bool:
  """Only allow logs originating from ClusterFuzz code."""
  if 'site-packages' in record.pathname or 'third_party' in record.pathname:
    return False
  return True


def suppress_unwanted_warnings():
  """Suppress unwanted warnings."""
  # See https://github.com/googleapis/google-api-python-client/issues/299
  logging.getLogger('googleapiclient.discovery_cache').setLevel(logging.ERROR)


def set_logger(logger):
  """Set the logger."""
  global _logger
  _logger = logger


def get_handler_config(filename, backup_count):
  """Get handler config."""
  root_directory = os.getenv('ROOT_DIR')
  file_path = os.path.join(root_directory, filename)
  max_bytes = 0 if _is_local() else LOCAL_LOG_LIMIT

  return {
      'class': 'logging.handlers.RotatingFileHandler',
      'level': BASE_LOGGING_LEVEL,
      'formatter': 'simple',
      'filename': file_path,
      'maxBytes': max_bytes,
      'backupCount': backup_count,
      'encoding': 'utf8',
  }


def get_logging_config_dict(name):
  """Get config dict for the logger `name`."""
  logging_handler = {
      'run_bot':
          get_handler_config('bot/logs/bot.log', 3),
      'run':
          get_handler_config('bot/logs/run.log', 1),
      'run_heartbeat':
          get_handler_config('bot/logs/run_heartbeat.log', 1),
      'heartbeat':
          get_handler_config('bot/logs/heartbeat.log', 1),
      'run_fuzzer':
          get_handler_config('bot/logs/run_fuzzer.log', 1),
      'run_testcase':
          get_handler_config('bot/logs/run_testcase.log', 1),
      'android_heartbeat':
          get_handler_config('bot/logs/android_heartbeat.log', 1),
      'run_cron':
          get_handler_config('bot/logs/run_cron.log', 1),
  }

  return {
      'version': 1,
      'disable_existing_loggers': False,
      'formatters': {
          'simple': {
              'format': ('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
          }
      },
      'handlers': {
          'handler': logging_handler[name],
      },
      'loggers': {
          name: {
              'handlers': ['handler']
          }
      },
  }


def truncate(
    msg: Any,
    limit: int,
) -> Any:
  """We need to truncate the message in the middle if it gets too long.

  If the message is a string and exceeds the character `limit`, it is truncated
  in the middle, with a notice indicating how many characters were removed.

  For dictionaries, lists, and tuples, the function recurses over their
  values/items. For dataclasses, it first converts them to dictionaries before
  recursing.

  Certain types defined in `NON_TRUNCATABLE_TYPES` are returned as-is. All other
  types are coerced to strings before truncation.

  While basic types like strings, lists, and dictionaries retain their type, be
  aware that dataclasses are converted to dictionaries, and other unhandled
  objects are converted to strings. This function should only be used in the
  logs module.

  Args:
    msg: The message or collection to truncate.
    limit: The maximum character length for strings.

  Returns:
    The truncated message. 
  """
  if isinstance(msg, NON_TRUNCATABLE_TYPES):
    return msg

  exc_msg = ""

  # Adding try catch to avoid crashing the actual flow
  try:
    # Handle collections and objects by recursing
    if dataclasses.is_dataclass(msg) and not isinstance(msg, type):
      msg = dataclasses.asdict(msg)

    # Check if it's a NamedTuple
    if isinstance(msg, tuple) and hasattr(msg, '_fields'):
      msg = msg._asdict()  # type: ignore

    if isinstance(msg, dict):
      return {k: truncate(v, limit) for k, v in msg.items()}

    if isinstance(msg, (list, tuple)):
      return type(msg)(truncate(item, limit) for item in msg)

  except Exception as ex:
    exc_msg = str(ex)

  # Coerce all other types to a string
  if not isinstance(msg, str):
    msg = str(msg)

  if len(msg) <= limit:
    return msg

  half = limit // 2
  message = '\n'.join([
      msg[:half],
      '...%d characters truncated...' % (len(msg) - limit), msg[-half:]
  ])

  if exc_msg:
    return f'Exception during truncate: {exc_msg[:limit]}. Message: {message}'

  return message


class JsonFormatter(logging.Formatter):
  """Formats log records as JSON."""

  def format(self, record: logging.LogRecord) -> str:
    """Format LogEntry into JSON string."""
    entry = {
        'message':
            truncate(record.getMessage(), STACKDRIVER_LOG_MESSAGE_LIMIT),
        'created': (
            datetime.datetime.utcfromtimestamp(record.created).isoformat() + 'Z'
        ),
        'severity':
            record.levelname,
        'bot_name':
            os.getenv('BOT_NAME'),
        'task_payload':
            os.getenv('TASK_PAYLOAD'),
        'name':
            record.name,
        'pid':
            os.getpid(),
        'release':
            os.getenv('CLUSTERFUZZ_RELEASE', 'prod'),
        'docker_image':
            os.getenv('DOCKER_IMAGE', '')
    }

    initial_payload = os.getenv('INITIAL_TASK_PAYLOAD')
    if initial_payload:
      entry['actual_task_payload'] = entry['task_payload']
      entry['task_payload'] = initial_payload

    entry['location'] = getattr(record, 'location', {'error': True})
    # This is needed to truncate the extras value, as it can be used
    # to log exceptions stacktrace.
    entry['extras'] = {
        k: truncate(v, STACKDRIVER_LOG_MESSAGE_LIMIT)
        for k, v in getattr(record, 'extras', {}).items()
    }
    update_entry_with_exc(entry, record.exc_info)

    if not entry['extras']:
      del entry['extras']

    worker_bot_name = os.environ.get('WORKER_BOT_NAME')
    if worker_bot_name:
      entry['worker_bot_name'] = worker_bot_name

    fuzz_target = os.getenv('FUZZ_TARGET')
    if fuzz_target:
      entry['fuzz_target'] = fuzz_target

    # Log bot shutdown cases as WARNINGs (this is expected for preemptibles).
    if (entry['severity'] in ['ERROR', 'CRITICAL'] and
        'IOError: [Errno 4] Interrupted function call' in entry['message']):
      entry['severity'] = 'WARNING'

    return json.dumps(entry, default=_handle_unserializable)


def _handle_unserializable(unserializable: Any) -> str:
  try:
    return str(unserializable, 'utf-8')
  except TypeError:
    return str(unserializable)


def _is_json_serializable(obj: Any) -> bool:
  """Check if an object is json serializable, using the default encoder."""
  try:
    json.dumps(obj)
    return True
  except TypeError:
    return False


def update_entry_with_exc(entry, exc_info):
  """Update the dict `entry` with exc_info."""
  if not exc_info:
    return

  error_extras = getattr(exc_info[1], 'extras', {})
  entry['task_payload'] = (
      entry.get('task_payload') or error_extras.pop('task_payload', None))
  entry['extras'].update(error_extras)
  entry['serviceContext'] = {'service': 'bots'}

  # Reference:
  # https://cloud.google.com/error-reporting/docs/formatting-error-messages,
  if exc_info[0]:
    # we need to set the result of traceback.format_exception to the field
    # `message`. And we move our
    formatted_exception = ''.join(
        traceback.format_exception(exc_info[0], exc_info[1], exc_info[2]))

    # Original message and traceback truncation are done separately before
    # combining. The start and end of a traceback are most important. The
    # truncate function keeps the start/end of the input string. Applying this
    # to a merged message+traceback could cut off the message's end or
    # traceback's start.
    truncated_exception = truncate(formatted_exception,
                                   STACKDRIVER_LOG_MESSAGE_LIMIT)
    entry['message'] += '\n' + truncated_exception
  else:
    # If we log error without exception, we need to set
    # `context.reportLocation`.
    location = entry.get('location', {})
    entry['context'] = {
        'reportLocation': {
            'filePath': location.get('path', ''),
            'lineNumber': location.get('line', 0),
            'functionName': location.get('method', '')
        }
    }


def uncaught_exception_handler(exception_type, exception_value,
                               exception_traceback):
  """Handles any exception that are uncaught by logging an error and calling
  the sys.__excepthook__."""
  # Ensure that we are not calling ourself. This shouldn't be needed since we
  # are using sys.__excepthook__. Do this check anyway since if we are somehow
  # calling ourself we might infinitely send errors to the logs, which would be
  # quite bad.
  global _is_already_handling_uncaught
  if _is_already_handling_uncaught:
    raise RuntimeError('Loop in uncaught_exception_handler')
  _is_already_handling_uncaught = True

  # Use emit since error needs sys.exc_info() to return this function's
  # arguments to call init properly.
  # Don't worry about emit() throwing an Exception, python will let us know
  # about that exception as well as the original one.
  emit(
      logging.ERROR,
      'Uncaught exception',
      exc_info=(exception_type, exception_value, exception_traceback))

  sys.__excepthook__(exception_type, exception_value, exception_traceback)


def json_fields_filter(record):
  """Add logs `extras` argument to `json_fields` metadata for cloud logging."""
  # TODO(vtcosta): This is a workaround to allow structured logs for
  # cleanup/triage cronjobs in GKE/GAE. We should try to refactor and
  # centralize the logs configurations for all environments.
  if not hasattr(record, 'json_fields'):
    record.json_fields = {}

  json_extras = {}
  for key, val in getattr(record, 'extras', {}).items():
    valid_value = (
        val if _is_json_serializable(val) else _handle_unserializable(val))
    json_extras[key] = truncate(valid_value, STACKDRIVER_LOG_MESSAGE_LIMIT)

  record.json_fields.update({'extras': json_extras})
  return True


def configure_appengine():
  """Configure logging for App Engine."""
  logging.getLogger().setLevel(BASE_LOGGING_LEVEL)

  if os.getenv('LOCAL_DEVELOPMENT') or environment.is_running_unit_tests():
    return

  import google.cloud.logging
  client = google.cloud.logging.Client()
  handler = client.get_default_handler()
  handler.addFilter(json_fields_filter)
  logging.getLogger().addHandler(handler)
  logging.getLogger().addFilter(_allow_clusterfuzz_only)


def configure_k8s():
  """Configure logging for K8S."""
  import google.cloud.logging
  from google.cloud.logging.handlers import CloudLoggingHandler
  from google.cloud.logging.handlers.transports import BackgroundThreadTransport

  client = google.cloud.logging.Client()
  labels = {
      'k8s-pod/app': os.getenv('BOT_NAME', 'unknown'),
      'bot_name': os.getenv('BOT_NAME', 'unknown'),
  }

  class FlushIntervalTransport(BackgroundThreadTransport):

    def __init__(self, client, name, **kwargs):
      super().__init__(
          client,
          name,
          grace_period=int(os.getenv('LOGGING_CLOUD_GRACE_PERIOD', '15')),
          max_latency=int(os.getenv('LOGGING_CLOUD_MAX_LATENCY', '10')),
          **kwargs)

  handler = CloudLoggingHandler(
      client=client,
      name='k8s-logs',
      labels=labels,
      transport=FlushIntervalTransport)

  def k8s_label_filter(record):
    handler.labels.update({
        'task_payload':
            os.getenv('TASK_PAYLOAD', 'null'),
        'fuzz_target':
            os.getenv('FUZZ_TARGET', 'null'),
        'worker_bot_name':
            os.getenv('WORKER_BOT_NAME', 'null'),
        'extra':
            truncate(
                json.dumps(
                    getattr(record, 'extras', {}),
                    default=_handle_unserializable),
                STACKDRIVER_LOG_MESSAGE_LIMIT),
        'location':
            json.dumps(
                getattr(record, 'location', {'Error': True}),
                default=_handle_unserializable),
    })
    return True

  handler.addFilter(k8s_label_filter)
  handler.setLevel(BASE_LOGGING_LEVEL)
  formatter = JsonFormatter()
  handler.setFormatter(formatter)

  logging.getLogger().addHandler(handler)
  logging.getLogger().setLevel(BASE_LOGGING_LEVEL)
  logging.getLogger().addFilter(_allow_clusterfuzz_only)


def configure_cloud_logging():
  """ Configure Google cloud logging, for bots not running on appengine nor k8s.
  """
  import google.cloud.logging
  from google.cloud.logging.handlers import CloudLoggingHandler
  from google.cloud.logging.handlers.transports import BackgroundThreadTransport

  # project will default to the service account's project (likely from
  #   GOOGLE_APPLICATION_CREDENTIALS).
  # Some clients might need to override this to log in a specific project using
  #   LOGGING_CLOUD_PROJECT_ID.
  # Note that CLOUD_PROJECT_ID is not used here, as it might differ from both
  #   the service account's project and the logging project.
  client = google.cloud.logging.Client(
      project=os.getenv('LOGGING_CLOUD_PROJECT_ID'))
  labels = {
      'compute.googleapis.com/resource_name': socket.getfqdn().lower(),
      'bot_name': os.getenv('BOT_NAME', 'null'),
  }

  class FlushIntervalTransport(BackgroundThreadTransport):

    def __init__(self, client, name, **kwargs):
      super().__init__(
          client,
          name,
          grace_period=int(os.getenv('LOGGING_CLOUD_GRACE_PERIOD', '15')),
          max_latency=int(os.getenv('LOGGING_CLOUD_MAX_LATENCY', '10')),
          **kwargs)

  handler = CloudLoggingHandler(
      client=client, labels=labels, transport=FlushIntervalTransport)

  def cloud_label_filter(record):
    # Update the labels with additional information.
    # Ideally we would use json_fields as done in configure_k8s(), but since
    # src/Pipfile forces google-cloud-logging = "==1.15.0", we have fairly
    # limited options to format the output, see:
    #   https://github.com/googleapis/python-logging/blob/6236537b197422d3dcfff38fe7729dee7f361ca9/google/cloud/logging/handlers/handlers.py#L98 # pylint: disable=line-too-long
    #   https://github.com/googleapis/python-logging/blob/6236537b197422d3dcfff38fe7729dee7f361ca9/google/cloud/logging/handlers/transports/background_thread.py#L233 # pylint: disable=line-too-long
    handler.labels.update({
        'task_payload':
            os.getenv('TASK_PAYLOAD', 'null'),
        'fuzz_target':
            os.getenv('FUZZ_TARGET', 'null'),
        'worker_bot_name':
            os.getenv('WORKER_BOT_NAME', 'null'),
        'extra':
            truncate(
                json.dumps(
                    getattr(record, 'extras', {}),
                    default=_handle_unserializable),
                STACKDRIVER_LOG_MESSAGE_LIMIT),
        'location':
            json.dumps(
                getattr(record, 'location', {'Error': True}),
                default=_handle_unserializable),
    })
    return True

  handler.addFilter(cloud_label_filter)
  handler.setLevel(BASE_LOGGING_LEVEL)
  formatter = JsonFormatter()
  handler.setFormatter(formatter)

  logging.getLogger().addHandler(handler)
  logging.getLogger().addFilter(_allow_clusterfuzz_only)


def configure_swarming(name: str, extras: dict[str, str] | None = None) -> None:
  """Configure logging for swarming bots."""
  if extras is None:
    extras = {}
  extras['task_id'] = os.getenv('TASK_ID')
  extras['instance_id'] = os.getenv('BOT_NAME')
  extras['platform'] = 'swarming'

  global _default_extras
  _default_extras = extras

  if _cloud_logging_enabled():
    configure_cloud_logging()

  logger = logging.getLogger(name)
  logger.setLevel(BASE_LOGGING_LEVEL)
  set_logger(logger)

  sys.excepthook = uncaught_exception_handler


def configure(name, extras=None):
  """Set logger. See the list of loggers in bot/config/logging.yaml.
  Also configures the process to log any uncaught exceptions as an error.
  |extras| will be included by emit() in log messages."""
  suppress_unwanted_warnings()

  if environment.is_running_on_swarming():
    configure_swarming(name, extras)
    return

  if environment.is_running_on_k8s():
    configure_k8s()
    return

  if environment.is_running_on_app_engine():
    configure_appengine()
    return

  if _console_logging_enabled():
    logging.basicConfig(level=BASE_LOGGING_LEVEL)
  if _file_logging_enabled():
    config.dictConfig(get_logging_config_dict(name))
  if _cloud_logging_enabled():
    configure_cloud_logging()
  logger = logging.getLogger(name)
  logger.setLevel(BASE_LOGGING_LEVEL)
  logger.addFilter(_allow_clusterfuzz_only)
  set_logger(logger)

  # Set _default_extras so they can be used later.
  if extras is None:
    extras = {}
  global _default_extras
  _default_extras = extras

  # Install an exception handler that will log an error when there is an
  # uncaught exception.
  sys.excepthook = uncaught_exception_handler


def get_logger():
  """Return logger. We need this method because we need to mock logger."""
  if _logger:
    return _logger

  if environment.is_running_on_app_engine() or environment.is_running_on_k8s():
    # Running on App Engine.
    set_logger(logging.getLogger())

  elif _console_logging_enabled():
    # Force a logger when console logging is enabled.
    configure('root')

  return _logger


def get_source_location():
  """Return the caller file, lineno, and funcName."""
  try:
    raise RuntimeError()
  except:
    # f_back is called twice. Once to leave get_source_location(..) and another
    # to leave emit(..).
    # The code is adapted from:
    # https://github.com/python/cpython/blob/2.7/Lib/logging/__init__.py#L1244
    frame = sys.exc_info()[2].tb_frame.f_back

    while frame and hasattr(frame, 'f_code'):
      if not frame.f_code.co_filename.endswith('logs.py'):
        return frame.f_code.co_filename, frame.f_lineno, frame.f_code.co_name
      frame = frame.f_back

  return 'Unknown', '-1', 'Unknown'


def _add_appengine_trace(extras):
  """Add App Engine tracing information."""
  if not environment.is_running_on_app_engine():
    return

  from libs import auth

  try:
    request = auth.get_current_request()
    if not request:
      return
  except Exception:
    # FIXME: Find a way to add traces in threads. Skip adding for now, as
    # otherwise, we hit an exception "Request global variable is not set".
    return

  trace_header = request.headers.get('X-Cloud-Trace-Context')
  if not trace_header:
    return

  project_id = os.getenv('APPLICATION_ID')
  trace_id = trace_header.split('/')[0]
  extras['logging.googleapis.com/trace'] = (
      'projects/{project_id}/traces/{trace_id}').format(
          project_id=project_id, trace_id=trace_id)


def intercept_log_context(func):
  """Intercepts the wrapped function and injects metadata
     into the kwargs for a given log context
  """

  @functools.wraps(func)
  def wrapper(*args, **kwargs):
    if not kwargs.get('ignore_context'):
      for context in log_contexts.contexts:
        context.setup()
        kwargs.update(context.get_extras()._asdict())
    else:
      # This is needed to avoid logging the label 'ingore_context: True'.
      del kwargs["ignore_context"]
    return func(*args, **kwargs)

  return wrapper


def _parse_symmetric_logs(extras):
  """Return a list containing the fields of each symmetrics log entry.

  Checks if the symmetric logs label was passed and formatted as expected,
  i.e., a label called `symmetric_logs` containing a list of dicts, which
  represent the fields used for each log entry. Then, removes this label from
  extras and return it. Otherwise, return None.
  """
  symmetric_logs = extras.pop('symmetric_logs', None)
  if not symmetric_logs:
    return None

  if not isinstance(symmetric_logs, list):
    return None

  for sl in symmetric_logs:
    if not isinstance(sl, dict):
      return None

  return symmetric_logs


@intercept_log_context
def emit(level, message, exc_info=None, **extras):
  """Log in JSON."""
  logger = get_logger()
  if not logger:
    return

  # Include extras passed as an argument and default extras.
  all_extras = _default_extras.copy()
  all_extras.update(extras)
  if level >= logging.ERROR and 'stage_summary' not in all_extras:
    tracker = _current_stage_tracker()
    if tracker is not None:
      tracker.record_error(str(message))

  path_name, line_number, method_name = get_source_location()

  if environment.is_running_on_app_engine():
    if exc_info == (None, None, None):
      # Don't pass exc_info at all, as otherwise cloud logging will append
      # "NoneType: None" to the message.
      exc_info = None

    if level >= logging.ERROR:
      # App Engine only reports errors if there is an exception stacktrace, so
      # we generate one. We don't create an exception here and then format it,
      # as that will not include frames below this emit() call. We do [:-2] on
      # the stacktrace to exclude emit() and the logging function below it (e.g.
      # error).
      message = (
          message + '\n' + 'Traceback (most recent call last):\n' + ''.join(
              traceback.format_stack()[:-2]) + 'LogError: ' + message)

    _add_appengine_trace(all_extras)

  log_limit = STACKDRIVER_LOG_MESSAGE_LIMIT if _cloud_logging_enabled(
  ) else LOCAL_LOG_MESSAGE_LIMIT

  # Enable symmetric logs, i.e., multiple log entries from the same emit call
  # setting distinc values for labels in each entry.
  symmetric_logs = _parse_symmetric_logs(all_extras)
  symmetric_logs = [{}] if symmetric_logs is None else symmetric_logs
  for sym_extras in symmetric_logs:
    # Make a copy of the mutable params that can change in the logger call.
    all_extras_local = all_extras.copy()
    all_extras_local.update(sym_extras)
    message_truncated = truncate(message, log_limit)

    # We need to make a dict out of it because member of the dict becomes the
    # first class attributes of LogEntry. It is very tricky to identify the
    # extra attributes. Therefore, we wrap extra fields under the attribute
    # 'extras'.
    logger.log(
        level,
        message_truncated,
        exc_info=exc_info,
        extra={
            'extras': all_extras_local,
            'location': {
                'path': path_name,
                'line': line_number,
                'method': method_name
            }
        })


def info(message, **extras):
  """Logs the message to a given log file."""
  emit(logging.INFO, message, **extras)


def warning(message, **extras):
  """Logs the warning message."""
  emit(logging.WARN, message, exc_info=sys.exc_info(), **extras)


def debug(message, **extras):
  """Logs the debug message."""
  emit(logging.DEBUG, message, **extras)


def error(message, **extras):
  """Logs the error in the error log file."""
  exception = extras.pop('exception', None)
  if exception:
    try:
      raise exception
    except:
      emit(logging.ERROR, message, exc_info=sys.exc_info(), **extras)
  else:
    emit(logging.ERROR, message, exc_info=sys.exc_info(), **extras)
  _increment_error_count()


def log_fatal_and_exit(message, **extras):
  """Logs a fatal error and exits."""
  wait_before_exit = extras.pop('wait_before_exit', None)
  emit(logging.CRITICAL, message, exc_info=sys.exc_info(), **extras)
  _increment_error_count()
  if wait_before_exit:
    info('Waiting for %d seconds before exit.' % wait_before_exit)
    time.sleep(wait_before_exit)
  sys.exit(-1)


def get_common_log_context() -> dict[str, str]:
  """Return common context to be propagated by logs."""
  # Avoid circular imports on the top level.
  from clusterfuzz._internal.base import utils

  try:
    os_type = environment.platform()
    os_version = platform.release()
    instance_id = utils.get_instance_name()
    if not instance_id:
      instance_id = 'null'

    parsed_source_version = utils.parse_manifest_data(
        file_data=utils.current_source_version())
    if parsed_source_version:
      cf_version = parsed_source_version['cf_commit_sha']
      cf_config_version = parsed_source_version['cf_config_commit_sha']
    else:
      cf_version, cf_config_version = 'null', 'null'

    return {
        'clusterfuzz_version': cf_version,
        'clusterfuzz_config_version': cf_config_version,
        'instance_id': instance_id,
        'operating_system': os_type,
        'os_version': os_version
    }

  except Exception:
    warning('Failed setting common logs context.', ignore_context=True)
    return {}


def get_testcase_id(
    testcase: 'Testcase | TestcaseAttributes') -> int | str | None:
  """Return the ID for a testcase or testcase attributes object."""
  # Importing here as 3P libs becomes accessible during runtime, after modules
  # path search is resolved (and logs may be imported before that).
  from google.cloud import ndb

  if isinstance(testcase, ndb.Model):
    return testcase.key.id()  # type: ignore
  return getattr(testcase, 'id', None)


class GenericLogStruct(NamedTuple):
  pass


class CommonLogStruct(NamedTuple):
  clusterfuzz_version: str
  clusterfuzz_config_version: str
  instance_id: str
  operating_system: str
  os_version: str


class TaskLogStruct(NamedTuple):
  task_id: str
  task_name: str
  task_argument: str
  task_job_name: str
  stage: str


class CronLogStruct(NamedTuple):
  task_id: str
  task_name: str


class FuzzerLogStruct(NamedTuple):
  fuzz_target: str
  job: str
  fuzzer: str


class TestcaseLogStruct(NamedTuple):
  testcase_id: str
  testcase_group: str | int
  crash_state: str
  crash_type: str
  security_flag: bool
  one_time_crasher_flag: bool


class GrouperStruct(NamedTuple):
  # Represents the TestcaseLogStruct for each testcase being grouped.
  symmetric_logs: list[dict]


class LogContextType(enum.Enum):
  """Log context types.
  
  This is the way to define the context for a given entrypoint and this
  context is used for define the adicional labels to be added to the log.
  """
  COMMON = 'common'
  TASK = 'task'
  FUZZER = 'fuzzer'
  TESTCASE = 'testcase'
  CRON = 'cron'
  GROUPER = 'grouper'

  def setup(self) -> None:
    """Setup metadata needed for the context."""
    if self == LogContextType.COMMON:
      common_ctx = log_contexts.meta.get('common_ctx')
      if common_ctx is None:
        # Needed to avoid issues if a method used to get the common context
        # also tries to log.
        log_contexts.add_metadata('common_ctx', {})
        common_ctx = get_common_log_context()
        log_contexts.add_metadata('common_ctx', common_ctx)

  def get_extras(self) -> NamedTuple:
    """Get the structured log fields for a given context."""
    if self == LogContextType.COMMON:
      common_ctx = log_contexts.meta.get('common_ctx', {})
      return CommonLogStruct(
          clusterfuzz_version=common_ctx.get('clusterfuzz_version', 'null'),
          clusterfuzz_config_version=common_ctx.get(
              'clusterfuzz_config_version', 'null'),
          instance_id=common_ctx.get('instance_id', 'null'),
          operating_system=common_ctx.get('operating_system', 'null'),
          os_version=common_ctx.get('os_version', 'null'))

    if self == LogContextType.TASK:
      stage = log_contexts.meta.get('stage', Stage.UNKNOWN).value
      try:
        task_id = os.getenv('CF_TASK_ID', 'null')
        task_name = os.getenv('CF_TASK_NAME', 'null')
        task_argument = os.getenv('CF_TASK_ARGUMENT', 'null')
        task_job_name = os.getenv('CF_TASK_JOB_NAME', 'null')
        return TaskLogStruct(
            task_id=task_id,
            task_name=task_name,
            task_argument=task_argument,
            stage=stage,
            task_job_name=task_job_name)
      except:
        # This flag is necessary to avoid
        # infinite loop in this context verification.
        error('Error retrieving context for task logs.', ignore_context=True)
        return GenericLogStruct()

    if self == LogContextType.FUZZER:
      try:
        return FuzzerLogStruct(
            fuzzer=log_contexts.meta.get('fuzzer_name', 'null'),
            job=log_contexts.meta.get('job_type', 'null'),
            fuzz_target=log_contexts.meta.get('fuzz_target', 'null'))
      except:
        error(
            'Error retrieving context for fuzzer-based logs.',
            ignore_context=True)
        return GenericLogStruct()

    if self == LogContextType.TESTCASE:
      try:
        return TestcaseLogStruct(
            testcase_id=log_contexts.meta.get('testcase_id', 'null'),
            testcase_group=log_contexts.meta.get('testcase_group', 'null'),
            crash_state=log_contexts.meta.get('crash_state', 'null'),
            crash_type=log_contexts.meta.get('crash_type', 'null'),
            security_flag=log_contexts.meta.get('security_flag', 'null'),
            one_time_crasher_flag=log_contexts.meta.get('one_time_crasher_flag',
                                                        'null'))
      except:
        error(
            'Error retrieving context for testcase-based logs.',
            ignore_context=True)
        return GenericLogStruct()

    if self == LogContextType.CRON:
      try:
        return CronLogStruct(
            task_name=os.getenv('CF_TASK_NAME', 'null'),
            task_id=os.getenv('CF_TASK_ID', 'null'))
      except:
        error(
            'Error retrieving context for cron-based logs.',
            ignore_context=True)
        return GenericLogStruct()

    if self == LogContextType.GROUPER:
      try:
        symmetric_logs = []
        testcases_per_grouping = 2
        for i in range(1, testcases_per_grouping + 1):
          testcase_struct = TestcaseLogStruct(
              testcase_id=log_contexts.meta.get(f'testcase_{i}_id', 'null'),
              testcase_group=log_contexts.meta.get(f'testcase_{i}_group',
                                                   'null'),
              crash_type=log_contexts.meta.get(f'testcase_{i}_crash_type',
                                               'null'),
              crash_state=log_contexts.meta.get(f'testcase_{i}_crash_state',
                                                'null'),
              one_time_crasher_flag=log_contexts.meta.get(
                  f'testcase_{i}_one_time_crasher_flag', 'null'),
              security_flag=log_contexts.meta.get(f'testcase_{i}_security_flag',
                                                  'null'))
          fuzzer_struct = FuzzerLogStruct(
              job=log_contexts.meta.get(f'testcase_{i}_job_type', 'null'),
              fuzzer=log_contexts.meta.get(f'testcase_{i}_fuzzer_name', 'null'),
              fuzz_target='unknown')

          log_dict = testcase_struct._asdict()
          log_dict.update(fuzzer_struct._asdict())
          symmetric_logs.append(log_dict)
        return GrouperStruct(symmetric_logs=symmetric_logs)
      except:
        error(
            'Error retrieving context for grouper-based logs.',
            ignore_context=True)
        return GenericLogStruct()

    return GenericLogStruct()


class Stage(enum.Enum):
  PREPROCESS = 'preprocess'
  MAIN = 'main'
  POSTPROCESS = 'postprocess'
  UNKNOWN = 'unknown'
  SCHEDULER = 'scheduler'
  NA = 'n/a'


class Singleton(type):
  _instances = {}
  _lock = threading.Lock()

  def __call__(cls, *args, **kwargs):
    with cls._lock:
      if cls not in cls._instances:
        cls._instances[cls] = super().__call__(*args, **kwargs)
    return cls._instances[cls]


class LogContexts(metaclass=Singleton):
  """Class to keep the log contexts and metadata."""

  def __init__(self):
    self.contexts: list[LogContextType] = [LogContextType.COMMON]
    self.meta: dict[Any, Any] = {}
    self._data_lock = threading.Lock()

  def add(self, new_contexts: list[LogContextType]):
    with self._data_lock:
      self.contexts += new_contexts

  def add_metadata(self, key: Any, value: Any):
    with self._data_lock:
      self.meta[key] = value

  def delete(self, contexts: list[LogContextType]):
    with self._data_lock:
      for ctx in contexts:
        self.contexts.remove(ctx)

  def delete_metadata(self, key: Any):
    with self._data_lock:
      if key in self.meta:
        del self.meta[key]

  def clear(self):
    with self._data_lock:
      self.contexts = [LogContextType.COMMON]


log_contexts = LogContexts()


@contextlib.contextmanager
def wrap_log_context(contexts: list[LogContextType]):
  try:
    log_contexts.add(contexts)
    yield
  finally:
    log_contexts.delete(contexts)


@contextlib.contextmanager
def task_stage_context(stage: Stage):
  """Creates a task context for a given stage."""
  with wrap_log_context(contexts=[LogContextType.TASK]):
    try:
      log_contexts.add_metadata('stage', stage)
      yield
    except Exception as e:
      # TODO(vtcosta): This warning logs the location (line number/function) of
      # the contextlib module. Maybe we should have a better way to retrieve
      # the location in this case.
      warning(message='Error during task context.')
      raise e
    finally:
      log_contexts.delete_metadata('stage')


@contextlib.contextmanager
def fuzzer_log_context(fuzzer_name: str, job_type: str,
                       fuzz_target: 'FuzzTarget | None'):
  """Creates a fuzzer context for a given fuzzer, job, and target (optional)."""
  with wrap_log_context(contexts=[LogContextType.FUZZER]):
    try:
      if fuzz_target and fuzz_target.binary:
        fuzz_target_bin = fuzz_target.binary
      else:
        fuzz_target_bin = 'unknown'
      log_contexts.add_metadata('fuzz_target', fuzz_target_bin)
      log_contexts.add_metadata('fuzzer_name', fuzzer_name)
      log_contexts.add_metadata('job_type', job_type)
      tracker = _current_stage_tracker()
      if tracker is not None:
        tracker.snapshot_log_context()
      yield
    except Exception as e:
      warning(message='Error during fuzzer context.')
      raise e
    finally:
      tracker = _current_stage_tracker()
      if tracker is not None:
        tracker.snapshot_log_context()
      log_contexts.delete_metadata('fuzz_target')
      log_contexts.delete_metadata('fuzzer_name')
      log_contexts.delete_metadata('job_type')


@contextlib.contextmanager
def testcase_log_context(testcase: 'Testcase | TestcaseAttributes',
                         fuzz_target: 'FuzzTarget | None'):
  """Creates a testcase-based context for a given testcase.

  Fuzz target as an argument is needed since retrieving this entity depends on
  the task's stage. In trusted part, it can be retrieved by querying the DB,
  while in untrusted part is only accessible through the protobuf.
  """
  with wrap_log_context(
      contexts=[LogContextType.FUZZER, LogContextType.TESTCASE]):
    try:
      for field in TestcaseLogStruct._fields + ('job_type', 'fuzzer_name'):
        if field == 'testcase_id':
          log_contexts.add_metadata('testcase_id', get_testcase_id(testcase))
        elif field == 'testcase_group':
          log_contexts.add_metadata('testcase_group',
                                    getattr(testcase, 'group_id', None))
        else:
          log_contexts.add_metadata(field, getattr(testcase, field, None))

      if fuzz_target and fuzz_target.binary:
        fuzz_target_bin = fuzz_target.binary
      else:
        fuzz_target_bin = 'unknown' if not testcase else testcase.get_metadata(
            'fuzzer_binary_name', 'unknown')
      log_contexts.add_metadata('fuzz_target', fuzz_target_bin)
      tracker = _current_stage_tracker()
      if tracker is not None:
        tracker.snapshot_log_context()
      yield
    except Exception as e:
      # Logging as a warning because this error will be handled
      # in an upper level, and we would like to still have a way
      # to track it with the current context logs.
      warning(message='Error during testcase context.')
      raise e
    finally:
      tracker = _current_stage_tracker()
      if tracker is not None:
        tracker.snapshot_log_context()
      for field in TestcaseLogStruct._fields:
        log_contexts.delete_metadata(field)
      log_contexts.delete_metadata('fuzzer_name')
      log_contexts.delete_metadata('job_type')
      log_contexts.delete_metadata('fuzz_target')


@contextlib.contextmanager
def cron_log_context():
  """Creates a cronjob log context, mainly for triage/cleanup tasks."""
  with wrap_log_context(contexts=[LogContextType.CRON]):
    try:
      yield
    except Exception as e:
      warning(message='Error during cronjob context.')
      raise e


@contextlib.contextmanager
def grouper_log_context(testcase_1: 'Testcase | TestcaseAttributes',
                        testcase_2: 'Testcase | TestcaseAttributes'):
  """Creates a grouper context for a given pair of testcases."""
  with wrap_log_context(contexts=[LogContextType.GROUPER]):
    try:
      for field in TestcaseLogStruct._fields + ('job_type', 'fuzzer_name'):
        if field == 'testcase_id':
          log_contexts.add_metadata('testcase_1_id',
                                    get_testcase_id(testcase_1))
          log_contexts.add_metadata('testcase_2_id',
                                    get_testcase_id(testcase_2))
        elif field == 'testcase_group':
          log_contexts.add_metadata('testcase_1_group',
                                    getattr(testcase_1, 'group_id', None))
          log_contexts.add_metadata('testcase_2_group',
                                    getattr(testcase_2, 'group_id', None))
        else:
          log_contexts.add_metadata(f'testcase_1_{field}',
                                    getattr(testcase_1, field, None))
          log_contexts.add_metadata(f'testcase_2_{field}',
                                    getattr(testcase_2, field, None))

      yield
    except Exception as e:
      warning(message='Error during grouper context.')
      raise e
    finally:
      for field in TestcaseLogStruct._fields + ('job_type', 'fuzzer_name'):
        if field == 'testcase_id':
          log_contexts.delete_metadata('testcase_1_id')
          log_contexts.delete_metadata('testcase_2_id')
        elif field == 'testcase_group':
          log_contexts.delete_metadata('testcase_1_group')
          log_contexts.delete_metadata('testcase_2_group')
        else:
          log_contexts.delete_metadata(f'testcase_1_{field}')
          log_contexts.delete_metadata(f'testcase_2_{field}')


_STAGE_TRACKER_LOCAL = threading.local()


def _extract_step_reason(reason: Any) -> str | None:
  """Extracts a concise human-readable reason string from a step outcome."""
  if reason is None:
    return None
  if isinstance(reason, str):
    cleaned = reason.strip().splitlines()[0] if reason.strip() else ''
    return cleaned[:500] or None

  error_message = getattr(reason, 'error_message', None)
  if error_message:
    cleaned = str(error_message).strip().splitlines()[0]
    if cleaned:
      return cleaned[:500]

  error_type = getattr(reason, 'error_type', None)
  if isinstance(error_type, int) and error_type != 0:
    try:
      from clusterfuzz._internal.protos import uworker_msg_pb2
      return uworker_msg_pb2.ErrorType.Name(error_type)  # pylint: disable=no-member
    except Exception:
      return str(error_type)

  cleaned = str(reason).strip().splitlines()[0] if str(reason).strip() else ''
  return cleaned[:500] or None


class _StepHandle:
  """Handle for a numbered stage step supporting both flat and `with` usage."""

  def __init__(self, n: int, name: str):
    self.n = n
    self.name = name
    self.start_time_ns = time.time_ns()
    self.status = 'ok'
    self.reason: str | None = None
    self.duration_s = 0.0
    self.terminal = False
    self.tracker: StageSummaryTracker | None = None
    self.finished = False

  def skip(self, reason: Any = None) -> None:
    """Marks this step as skipped with an optional reason."""
    if self.status != 'failed':
      self.status = 'skipped'
    resolved = _extract_step_reason(reason)
    if resolved:
      self.reason = resolved

  def fail(self, reason: Any = None) -> None:
    """Marks this step as failed with an optional reason or Output protobuf."""
    self.status = 'failed'
    resolved = _extract_step_reason(reason)
    if resolved:
      self.reason = resolved

  def complete_stage(self, reason: Any = None, *, skip: bool = False) -> None:
    """Marks this step as a legitimate early termination of the stage."""
    self.terminal = True
    if self.tracker is not None:
      self.tracker.terminal = True
    resolved = _extract_step_reason(reason)
    if skip and self.status != 'failed':
      self.status = 'skipped'
    if resolved:
      self.reason = resolved

  def finish(self, end_time_ns: int | None = None) -> None:
    """Finalizes step timing and registers the step on the active tracker."""
    if self.finished:
      return
    self.finished = True
    if self.tracker is not None:
      self.tracker.finish_step(self, end_time_ns=end_time_ns)

  def __enter__(self) -> '_StepHandle':
    return self

  def __exit__(self, exc_type, exc_value, traceback_obj) -> None:
    del traceback_obj
    if exc_type is not None and self.status != 'failed':
      msg = str(exc_value).strip().splitlines()[0] if exc_value else ''
      self.fail(f'{exc_type.__name__}: {msg}' if msg else exc_type.__name__)
    self.finish()

  def to_dict(self) -> dict[str, Any]:
    """Serializes the step record for `jsonPayload.extras.stage_summary`."""
    data: dict[str, Any] = {
        'n': self.n,
        'name': self.name,
        'status': self.status,
        'duration_s': self.duration_s,
    }
    if self.reason:
      data['reason'] = self.reason
    return data


_STATUS_PRIORITY = {'ok': 0, 'skipped': 1, 'failed': 2}


class StageSummaryTracker:
  """Accumulates structured step telemetry for a single task stage."""

  def __init__(self, stage: Stage | str, start_time_ns: int | None = None):
    self.stage = stage.value if isinstance(stage, Stage) else str(stage)
    self.start_time_ns = (
        start_time_ns if start_time_ns is not None else time.time_ns())
    self.variant: str | None = None
    self.steps: list[dict[str, Any]] = []
    self.terminal = False
    self.last_error: str | None = None
    self.error_type: str | None = None
    self.main_error_type: str | None = None
    self.context_extras: dict[str, Any] = {}
    self.active_step: _StepHandle | None = None

  def start_step(self, handle: _StepHandle) -> None:
    """Marks a step as active, finishing any previously active step."""
    if self.active_step is not None and not self.active_step.finished:
      prev_ok = self.active_step.status == 'ok'
      self.active_step.finish(end_time_ns=handle.start_time_ns)
      if prev_ok:
        self.last_error = None
    handle.tracker = self
    self.active_step = handle

  def finish_step(self,
                  handle: _StepHandle,
                  end_time_ns: int | None = None) -> None:
    """Records step completion and merges repeated step entries."""
    end_ns = end_time_ns if end_time_ns is not None else time.time_ns()
    handle.duration_s = round(max(0, end_ns - handle.start_time_ns) / 10**9, 3)
    if handle.terminal:
      self.terminal = True
    if handle.status == 'failed' and not handle.reason and self.last_error:
      handle.reason = self.last_error
    step_dict = handle.to_dict()
    for existing in self.steps:
      if existing['n'] == handle.n and existing['name'] == handle.name:
        existing['duration_s'] = round(
            existing['duration_s'] + handle.duration_s, 3)
        if (_STATUS_PRIORITY.get(step_dict['status'], 0) >=
            _STATUS_PRIORITY.get(existing['status'], 0)):
          existing['status'] = step_dict['status']
        if 'reason' in step_dict:
          existing['reason'] = step_dict['reason']
        break
    else:
      self.steps.append(step_dict)
    if self.active_step is handle:
      self.active_step = None

  def record_error(self, message: str) -> None:
    """Records an error log message emitted while the stage is active."""
    first_line = str(message).strip().splitlines()[0][:500] if message else ''
    if not first_line:
      return
    if (self.last_error is None or
        first_line != 'No uworker_input returned from preprocess'):
      self.last_error = first_line

  def snapshot_log_context(self) -> None:
    """Snapshots active FUZZER and TESTCASE log context metadata."""
    for ctx_type in (LogContextType.FUZZER, LogContextType.TESTCASE):
      if ctx_type in log_contexts.contexts:
        for k, v in ctx_type.get_extras()._asdict().items():
          if v is not None and v != 'null':
            self.context_extras[k] = v

  def build_summary(self,
                    *,
                    end_time_ns: int | None = None,
                    failed: bool = False,
                    error_type: str | None = None,
                    main_error_type: str | None = None,
                    failure_reason: str | None = None) -> dict[str, Any]:
    """Builds the structured `stage_summary` dictionary."""
    end_ns = end_time_ns if end_time_ns is not None else time.time_ns()
    resolved_error_type = error_type or self.error_type
    resolved_main_error_type = main_error_type or self.main_error_type
    if self.active_step is not None and not self.active_step.finished:
      if failed and self.active_step.status == 'ok' and not self.terminal:
        self.active_step.fail(failure_reason or self.last_error or
                              resolved_error_type)
      self.active_step.finish(end_time_ns=end_ns)

    duration_s = round(max(0, end_ns - self.start_time_ns) / 10**9, 3)
    has_failed_step = any(s['status'] == 'failed' for s in self.steps)
    stage_failed = bool(failed or has_failed_step)

    if stage_failed and not has_failed_step and self.steps:
      last_step = self.steps[-1]
      was_skipped = last_step['status'] == 'skipped'
      last_step['status'] = 'failed'
      fallback_reason = (
          failure_reason or self.last_error or resolved_error_type)
      if fallback_reason and (not last_step.get('reason') or was_skipped):
        last_step['reason'] = fallback_reason

    status = 'failed' if stage_failed else 'ok'
    summary: dict[str, Any] = {
        'stage': self.stage,
        'status': status,
        'duration_s': duration_s,
        'steps': list(self.steps),
    }
    if self.variant:
      summary['variant'] = self.variant
    if self.terminal and status == 'ok':
      summary['terminal'] = True
    if resolved_error_type and resolved_error_type not in ('N/A', 'NO_ERROR'):
      summary['error_type'] = resolved_error_type
    if (resolved_main_error_type and
        resolved_main_error_type not in ('N/A', 'NO_ERROR')):
      summary['main_error_type'] = resolved_main_error_type

    if stage_failed:
      step_reason = next(
          (s.get('reason')
           for s in reversed(self.steps)
           if s.get('status') == 'failed' and s.get('reason')),
          None,
      )
      resolved_reason = (
          step_reason or failure_reason or self.last_error or
          resolved_error_type)
      if resolved_reason:
        summary['failure_reason'] = resolved_reason
    return summary

  to_dict = build_summary


def _stage_tracker_stack() -> list[StageSummaryTracker]:
  stack = getattr(_STAGE_TRACKER_LOCAL, 'stack', None)
  if stack is None:
    stack = []
    _STAGE_TRACKER_LOCAL.stack = stack
  return stack


def _current_stage_tracker() -> StageSummaryTracker | None:
  stack = _stage_tracker_stack()
  return stack[-1] if stack else None


def _clear_stage_tracker() -> None:
  """Clears all active stage trackers on the current thread."""
  _stage_tracker_stack().clear()


def push_stage_tracker(tracker: StageSummaryTracker) -> None:
  """Pushes a StageSummaryTracker onto the thread-local stack."""
  _stage_tracker_stack().append(tracker)


def pop_stage_tracker(tracker: StageSummaryTracker | None = None) -> None:
  """Pops the active StageSummaryTracker from the thread-local stack."""
  stack = _stage_tracker_stack()
  if not stack:
    return
  if tracker is None or stack[-1] is tracker:
    stack.pop()
  elif tracker in stack:
    stack.remove(tracker)


def set_stage_variant(variant: str) -> None:
  """Sets the execution variant (`cg`, `bb`, `lf`) on the active tracker."""
  tracker = _current_stage_tracker()
  if tracker is not None:
    tracker.variant = variant


def step(n: int, name: str) -> _StepHandle:
  """Starts a numbered task step, usable either flat or as a `with` block."""
  handle = _StepHandle(n, name)
  tracker = _current_stage_tracker()
  if tracker is not None:
    tracker.start_step(handle)
  return handle


def emit_stage_summary(tracker: StageSummaryTracker,
                       *,
                       end_time_ns: int | None = None,
                       failed: bool = False,
                       error_type: str | None = None,
                       main_error_type: str | None = None,
                       failure_reason: str | None = None) -> dict[str, Any]:
  """Emits the structured `stage_summary` log entry for `tracker`."""
  tracker.snapshot_log_context()
  summary = tracker.build_summary(
      end_time_ns=end_time_ns,
      failed=failed,
      error_type=error_type,
      main_error_type=main_error_type,
      failure_reason=failure_reason)
  info(
      f'Stage {tracker.stage} finished.',
      stage_summary=summary,
      **tracker.context_extras)
  return summary


class _StageSummaryContext:
  """Context manager that tracks steps and emits a `stage_summary` on exit."""

  def __init__(self,
               stage: Stage | str,
               *,
               start_time_ns: int | None = None,
               emit_log: bool = True):
    self._stage_enum = stage if isinstance(stage, Stage) else None
    self._tracker = StageSummaryTracker(stage, start_time_ns=start_time_ns)
    self._emit_log = emit_log
    self._prev_stage = None
    self._had_stage = False

  def __enter__(self) -> StageSummaryTracker:
    if self._stage_enum is not None:
      self._had_stage = 'stage' in log_contexts.meta
      self._prev_stage = log_contexts.meta.get('stage')
      log_contexts.add_metadata('stage', self._stage_enum)
    push_stage_tracker(self._tracker)
    return self._tracker

  def __exit__(self, exc_type, exc_value, traceback_obj) -> None:
    del traceback_obj
    exc_failed = exc_type is not None
    exc_error_type = exc_type.__name__ if exc_type is not None else None
    exc_reason = None
    if exc_type is not None:
      lines = str(exc_value).strip().splitlines() if exc_value else []
      msg = lines[0] if lines else ''
      exc_reason = f'{exc_type.__name__}: {msg}' if msg else exc_type.__name__
      if (self._tracker.active_step is not None and
          not self._tracker.active_step.finished):
        self._tracker.active_step.fail(exc_reason)
    try:
      if self._emit_log:
        emit_stage_summary(
            self._tracker,
            failed=exc_failed,
            error_type=exc_error_type,
            failure_reason=exc_reason)
      else:
        self._tracker.build_summary(
            failed=exc_failed,
            error_type=exc_error_type,
            failure_reason=exc_reason)
    finally:
      pop_stage_tracker(self._tracker)
      if self._stage_enum is not None:
        if self._had_stage:
          log_contexts.add_metadata('stage', self._prev_stage)
        else:
          log_contexts.delete_metadata('stage')


def stage_summary_context(stage: Stage | str,
                          *,
                          start_time_ns: int | None = None,
                          emit_log: bool = True) -> _StageSummaryContext:
  """Returns a context manager that tracks steps and emits `stage_summary`."""
  return _StageSummaryContext(
      stage, start_time_ns=start_time_ns, emit_log=emit_log)
