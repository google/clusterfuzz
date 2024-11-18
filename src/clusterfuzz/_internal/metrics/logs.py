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

import datetime
import json
import logging
from logging import config
import os
import socket
import sys
import time
import traceback
from typing import Any

STACKDRIVER_LOG_MESSAGE_LIMIT = 80000  # Allowed log entry size is 100 KB.
LOCAL_LOG_MESSAGE_LIMIT = 100000
LOCAL_LOG_LIMIT = 500000
_logger = None
_is_already_handling_uncaught = False
_default_extras = {}


def _is_running_on_k8s():
  """Returns whether or not we're running on K8s."""
  # We do this here to avoid circular imports with environment.
  return os.getenv('IS_K8S_ENV') == 'true'


def _increment_error_count():
  """"Increment the error count metric."""
  if _is_running_on_k8s():
    task_name = 'k8s'
  elif _is_running_on_app_engine():
    task_name = 'appengine'
  else:
    task_name = os.getenv('TASK_NAME', 'unknown')

  from clusterfuzz._internal.metrics import monitoring_metrics
  monitoring_metrics.LOG_ERROR_COUNT.increment({'task_name': task_name})


def _is_local():
  """Return whether or not in a local development environment."""
  return (bool(os.getenv('LOCAL_DEVELOPMENT')) or
          os.getenv('SERVER_SOFTWARE', '').startswith('Development/'))


def _is_running_on_app_engine():
  """Return whether or not we're running on App Engine (production or
  development)."""
  return os.getenv('GAE_ENV') or (
      os.getenv('SERVER_SOFTWARE') and
      (os.getenv('SERVER_SOFTWARE').startswith('Development/') or
       os.getenv('SERVER_SOFTWARE').startswith('Google App Engine/')))


def _console_logging_enabled():
  """Return bool on where console logging is enabled, usually for tests."""
  return bool(os.getenv('LOG_TO_CONSOLE'))


# TODO(pmeuleman) Revert the changeset that added these once
# https://github.com/google/clusterfuzz/pull/3422 lands.
def _file_logging_enabled():
  """Return bool True when logging to files (bot/logs/*.log) is enabled.
  This is enabled by default.
  This is disabled if we are running in app engine or kubernetes as these have
    their dedicated loggers, see configure_appengine() and configure_k8s().
  """
  return bool(os.getenv(
      'LOG_TO_FILE',
      'True')) and not _is_running_on_app_engine() and not _is_running_on_k8s()


def _fluentd_logging_enabled():
  """Return bool True where fluentd logging is enabled.
  This is enabled by default.
  This is disabled for local development and if we are running in app engine or
    kubernetes as these have their dedicated loggers, see configure_appengine()
    and configure_k8s()."""
  return bool(os.getenv('LOG_TO_FLUENTD', 'True')) and not _is_local(
  ) and not _is_running_on_app_engine() and not _is_running_on_k8s()


def _cloud_logging_enabled():
  """Return bool True where Google Cloud Logging is enabled.
  This is disabled for local development and if we are running in a app engine
    or kubernetes as these have their dedicated loggers, see
    configure_appengine() and configure_k8s()."""
  return bool(os.getenv('LOG_TO_GCP')) and not _is_local(
  ) and not _is_running_on_app_engine() and not _is_running_on_k8s()


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
      'level': logging.INFO,
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


def truncate(msg, limit):
  """We need to truncate the message in the middle if it gets too long."""
  if len(msg) <= limit:
    return msg

  half = limit // 2
  return '\n'.join([
      msg[:half],
      '...%d characters truncated...' % (len(msg) - limit), msg[-half:]
  ])


def format_record(record: logging.LogRecord) -> str:
  """Format LogEntry into JSON string."""
  entry = {
      'message':
          truncate(record.getMessage(), STACKDRIVER_LOG_MESSAGE_LIMIT),
      'created': (
          datetime.datetime.utcfromtimestamp(record.created).isoformat() + 'Z'),
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
      'task_id':
          os.getenv('CF_TASK_ID', 'null'),
  }

  initial_payload = os.getenv('INITIAL_TASK_PAYLOAD')
  if initial_payload:
    entry['actual_task_payload'] = entry['task_payload']
    entry['task_payload'] = initial_payload

  entry['location'] = getattr(record, 'location', {'error': True})
  entry['extras'] = getattr(record, 'extras', {})
  update_entry_with_exc(entry, record.exc_info)

  if not entry['extras']:
    del entry['extras']

  worker_bot_name = os.environ.get('WORKER_BOT_NAME')
  if worker_bot_name:
    entry['worker_bot_name'] = worker_bot_name

  fuzz_target = os.getenv('FUZZ_TARGET')
  if fuzz_target:
    entry['fuzz_target'] = fuzz_target

  # Log bot shutdown cases as WARNINGs since this is expected for preemptibles.
  if (entry['severity'] in ['ERROR', 'CRITICAL'] and
      'IOError: [Errno 4] Interrupted function call' in entry['message']):
    entry['severity'] = 'WARNING'

  return json.dumps(entry, default=_handle_unserializable)


def _handle_unserializable(unserializable: Any) -> str:
  try:
    return str(unserializable, 'utf-8')
  except TypeError:
    return str(unserializable)


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
    entry['message'] += '\n' + ''.join(
        traceback.format_exception(exc_info[0], exc_info[1], exc_info[2]))
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


class JsonSocketHandler(logging.handlers.SocketHandler):
  """Format log into JSON string before sending it to fluentd. We need this
    because SocketHandler doesn't respect the formatter attribute."""

  def makePickle(self, record: logging.LogRecord):
    """Format LogEntry into JSON string."""
    # \n is the recognized delimiter by fluentd's in_tcp. Don't remove.
    return (format_record(record) + '\n').encode('utf-8')


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


def configure_appengine():
  """Configure logging for App Engine."""
  logging.getLogger().setLevel(logging.INFO)

  if os.getenv('LOCAL_DEVELOPMENT') or os.getenv('PY_UNITTESTS'):
    return

  import google.cloud.logging
  client = google.cloud.logging.Client()
  handler = client.get_default_handler()
  logging.getLogger().addHandler(handler)


def configure_k8s():
  """Configure logging for K8S and reporting errors."""
  import google.cloud.logging
  client = google.cloud.logging.Client()
  client.setup_logging()
  old_factory = logging.getLogRecordFactory()

  def record_factory(*args, **kwargs):
    """Insert jsonPayload fields to all logs."""

    record = old_factory(*args, **kwargs)
    if not hasattr(record, 'json_fields'):
      record.json_fields = {}

    # Add jsonPayload fields to logs that don't contain stack traces to enable
    # capturing and grouping by error reporting.
    # https://cloud.google.com/error-reporting/docs/formatting-error-messages#log-text
    if record.levelno >= logging.ERROR and not record.exc_info:
      record.json_fields.update({
          '@type':
              'type.googleapis.com/google.devtools.clouderrorreporting.v1beta1.ReportedErrorEvent',  # pylint: disable=line-too-long
          'serviceContext': {
              'service': 'k8s',
          },
          'context': {
              'reportLocation': {
                  'filePath': record.pathname,
                  'lineNumber': record.lineno,
                  'functionName': record.funcName,
              }
          },
      })

    return record

  logging.setLogRecordFactory(record_factory)
  logging.getLogger().setLevel(logging.INFO)


def configure_fluentd_logging():
  fluentd_handler = JsonSocketHandler(
      host='127.0.0.1',
      port=5170,
  )
  fluentd_handler.setLevel(logging.INFO)
  logging.getLogger().addHandler(fluentd_handler)


def configure_cloud_logging():
  """ Configure Google cloud logging, for bots not running on appengine nor k8s.
  """
  import google.cloud.logging

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
      'bot_name': os.getenv('BOT_NAME'),
  }
  handler = client.get_default_handler(labels=labels)

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
            json.dumps(
                getattr(record, 'extras', {}), default=_handle_unserializable),
        'location':
            json.dumps(
                getattr(record, 'location', {'Error': True}),
                default=_handle_unserializable),
    })
    return True

  handler.addFilter(cloud_label_filter)
  handler.setLevel(logging.INFO)

  logging.getLogger().addHandler(handler)


def configure(name, extras=None):
  """Set logger. See the list of loggers in bot/config/logging.yaml.
  Also configures the process to log any uncaught exceptions as an error.
  |extras| will be included by emit() in log messages."""
  suppress_unwanted_warnings()

  if _is_running_on_k8s():
    configure_k8s()
    return

  if _is_running_on_app_engine():
    configure_appengine()
    return

  if _console_logging_enabled():
    logging.basicConfig(level=logging.INFO)
  if _file_logging_enabled():
    config.dictConfig(get_logging_config_dict(name))
  if _fluentd_logging_enabled():
    configure_fluentd_logging()
  if _cloud_logging_enabled():
    configure_cloud_logging()
  logger = logging.getLogger(name)
  logger.setLevel(logging.INFO)
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

  if _is_running_on_app_engine() or _is_running_on_k8s():
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
  if not _is_running_on_app_engine():
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


def emit(level, message, exc_info=None, **extras):
  """Log in JSON."""
  logger = get_logger()
  if not logger:
    return

  # Include extras passed as an argument and default extras.
  all_extras = _default_extras.copy()
  all_extras.update(extras)

  path_name, line_number, method_name = get_source_location()

  if _is_running_on_app_engine():
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

  # We need to make a dict out of it because member of the dict becomes the
  # first class attributes of LogEntry. It is very tricky to identify the extra
  # attributes. Therefore, we wrap extra fields under the attribute 'extras'.
  logger.log(
      level,
      truncate(message, log_limit),
      exc_info=exc_info,
      extra={
          'extras': all_extras,
          'location': {
              'path': path_name,
              'line': line_number,
              'method': method_name
          },
          'release': os.environ.get('CLUSTERFUZZ_RELEASE', 'prod'),
          'docker_image': os.environ.get('DOCKER_IMAGE', '')
      })


def info(message, **extras):
  """Logs the message to a given log file."""
  emit(logging.INFO, message, **extras)


def warning(message, **extras):
  """Logs the warning message."""
  emit(logging.WARN, message, exc_info=sys.exc_info(), **extras)


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
