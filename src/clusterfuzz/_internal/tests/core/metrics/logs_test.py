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
"""logs test."""
import datetime
import inspect
import json
import logging
import os
import sys
import unittest
from unittest import mock

from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.tests.test_libs import helpers


class GetSourceLocationTest(unittest.TestCase):
  """Test get_source_location."""

  def setUp(self):
    self.statement_line = None

  def _nested(self):
    self.statement_line = inspect.currentframe().f_lineno + 1
    return logs.get_source_location()

  def test_get(self):
    """Test get."""
    pathname, lineno, func_name = self._nested()
    self.assertTrue(
        pathname.endswith(
            'src/clusterfuzz/_internal/tests/core/metrics/logs_test.py'))
    # The line number of _dummy_emit() invocation.
    self.assertEqual(self.statement_line, lineno)
    self.assertEqual('_nested', func_name)


class UpdateEntryWithExc(unittest.TestCase):
  """Test update_entry_with_exc."""

  def test_empty(self):
    """Test empty exc_info."""
    entry = {}
    logs.update_entry_with_exc(entry, None)
    self.assertEqual({}, entry)

  def test_none_exc(self):
    """Test exc_info is (None, None, None)."""
    entry = {
        'task_payload': 'task',
        'extras': {
            'test': 'value'
        },
        'message': 'original',
        'serviceContext': {
            'service': 'bots'
        },
        'location': {
            'path': 'source_path',
            'line': 1234,
            'method': 'new_method'
        }
    }
    exc_info = sys.exc_info()  # expected to be (None, None, None).

    logs.update_entry_with_exc(entry, exc_info)

    self.assertEqual({
        'extras': {
            'test': 'value'
        },
        'task_payload': 'task',
        'message': 'original',
        'serviceContext': {
            'service': 'bots'
        },
        'location': {
            'path': 'source_path',
            'line': 1234,
            'method': 'new_method'
        },
        'context': {
            'reportLocation': {
                'filePath': 'source_path',
                'lineNumber': 1234,
                'functionName': 'new_method'
            }
        }
    }, entry)

  def test_exc(self):
    """Test exception."""
    entry = {'extras': {}, 'message': 'original'}
    exception = Exception('ex message')
    exception.extras = {'test': 'value', 'task_payload': 'task'}

    try:
      statement_line = inspect.currentframe().f_lineno + 1
      raise exception
    except:
      # We do this because we need the traceback instance.
      exc_info = sys.exc_info()

    logs.update_entry_with_exc(entry, exc_info)  # pylint: disable=used-before-assignment
    self.maxDiff = None

    self.assertEqual({
        'extras': {
            'test': 'value'
        },
        'task_payload':
            'task',
        'serviceContext': {
            'service': 'bots'
        },
        'message':
            ('original\n'
             'Traceback (most recent call last):\n'
             '  File "%s", line %d, in test_exc\n'
             '    raise exception\n'
             'Exception: ex message\n') % (__file__.strip('c'), statement_line)
    }, entry)


class FormatRecordTest(unittest.TestCase):
  """Test format method of JsonFormatter."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.metrics.logs.update_entry_with_exc', 'os.getpid'
    ])
    helpers.patch_environ(self)
    os.environ['CF_TASK_ID'] = 'job-1337'
    self.maxDiff = None
    self.mock.getpid.return_value = 1337

  def get_record(self):
    """Make a fake record."""
    os.environ['BOT_NAME'] = 'linux-bot'
    os.environ['TASK_PAYLOAD'] = 'fuzz fuzzer1 job1'
    record = mock.Mock(
        specset=logging.LogRecord,
        levelname='INFO',
        exc_info='exc_info',
        created=10,
        location={
            'path': 'path',
            'line': 123,
            'method': 'func'
        })
    record.name = 'logger_name'
    record.getMessage.return_value = 'log message'
    return record

  def test_format_record(self):
    """Test format a LogRecord into JSON string."""
    os.environ['FUZZ_TARGET'] = 'fuzz_target1'
    record = self.get_record()
    record.extras = {'a': 1}
    self.assertEqual({
        'message': 'log message',
        'created': '1970-01-01T00:00:10Z',
        'severity': 'INFO',
        'bot_name': 'linux-bot',
        'task_payload': 'fuzz fuzzer1 job1',
        'fuzz_target': 'fuzz_target1',
        'name': 'logger_name',
        'pid': 1337,
        'task_id': 'job-1337',
        'extras': {
            'a': 1,
        },
        'location': {
            'path': 'path',
            'line': 123,
            'method': 'func'
        }
    }, json.loads(logs.JsonFormatter().format(record)))

    self.mock.update_entry_with_exc.assert_called_once_with(
        mock.ANY, 'exc_info')

  def test_no_extras(self):
    """Test format record with no extras."""
    record = self.get_record()
    record.extras = None
    self.assertEqual({
        'message': 'log message',
        'created': '1970-01-01T00:00:10Z',
        'severity': 'INFO',
        'bot_name': 'linux-bot',
        'task_payload': 'fuzz fuzzer1 job1',
        'name': 'logger_name',
        'task_id': 'job-1337',
        'pid': 1337,
        'location': {
            'path': 'path',
            'line': 123,
            'method': 'func'
        }
    }, json.loads(logs.JsonFormatter().format(record)))
    self.mock.update_entry_with_exc.assert_called_once_with(
        mock.ANY, 'exc_info')

  def test_worker_bot_name(self):
    """Test format record with a worker bot name."""
    os.environ['WORKER_BOT_NAME'] = 'worker'
    record = self.get_record()
    record.extras = None

    self.assertEqual({
        'message': 'log message',
        'created': '1970-01-01T00:00:10Z',
        'severity': 'INFO',
        'bot_name': 'linux-bot',
        'worker_bot_name': 'worker',
        'task_payload': 'fuzz fuzzer1 job1',
        'name': 'logger_name',
        'task_id': 'job-1337',
        'pid': 1337,
        'location': {
            'path': 'path',
            'line': 123,
            'method': 'func'
        }
    }, json.loads(logs.JsonFormatter().format(record)))
    self.mock.update_entry_with_exc.assert_called_once_with(
        mock.ANY, 'exc_info')


class JsonFormatterTest(unittest.TestCase):
  """Test JsonFormatter class."""

  def setUp(self):
    self.formatter = logging.getLoggerClass().manager.loggerDict = {}
    self.formatter = logging.getLogger('test_logger')
    self.formatter.setLevel(logging.DEBUG)
    self.log_record = logging.LogRecord(
        name='test_logger',
        level=logging.INFO,
        pathname='test.py',
        lineno=10,
        msg='Test message',
        args=(),
        exc_info=None,
        func='test_func',
        sinfo=None,
    )
    self.log_record.created = datetime.datetime(2023, 10, 26, 12, 0,
                                                0).timestamp()

    self.original_env = dict(os.environ)

  def tearDown(self):
    os.environ.clear()
    os.environ.update(self.original_env)

  def test_format_basic(self):
    """Tests basic formatting of the log record."""
    formatter = logs.JsonFormatter()
    result = formatter.format(self.log_record)
    json_result = json.loads(result)

    self.assertEqual(json_result['message'], 'Test message')
    self.assertEqual(json_result['created'], '2023-10-26T12:00:00Z')
    self.assertEqual(json_result['severity'], 'INFO')
    self.assertEqual(json_result['name'], 'test_logger')
    self.assertEqual(json_result['pid'], os.getpid())
    self.assertEqual(json_result['task_id'], 'null')
    self.assertTrue('location' in json_result)
    self.assertFalse('extras' in json_result)

  def test_format_with_env_vars(self):
    """Tests formatting with environment variables."""
    os.environ['BOT_NAME'] = 'test_bot'
    os.environ['TASK_PAYLOAD'] = 'test_payload'
    os.environ['CF_TASK_ID'] = '123'
    formatter = logs.JsonFormatter()
    result = formatter.format(self.log_record)
    json_result = json.loads(result)

    self.assertEqual(json_result['bot_name'], 'test_bot')
    self.assertEqual(json_result['task_payload'], 'test_payload')
    self.assertEqual(json_result['task_id'], '123')

  def test_format_with_initial_payload(self):
    """Tests formatting with initial task payload."""
    os.environ['TASK_PAYLOAD'] = 'current_payload'
    os.environ['INITIAL_TASK_PAYLOAD'] = 'initial_payload'
    formatter = logs.JsonFormatter()
    result = formatter.format(self.log_record)
    json_result = json.loads(result)

    self.assertEqual(json_result['task_payload'], 'initial_payload')
    self.assertEqual(json_result['actual_task_payload'], 'current_payload')

  def test_format_with_location_and_extras(self):
    """Tests formatting with location and extras."""
    self.log_record.location = {'file': 'test.py', 'line': 20}
    self.log_record.extras = {'key': 'value'}
    formatter = logs.JsonFormatter()
    result = formatter.format(self.log_record)
    json_result = json.loads(result)

    self.assertEqual(json_result['location'], {'file': 'test.py', 'line': 20})
    self.assertEqual(json_result['extras'], {'key': 'value'})

  def test_format_truncate_message(self):
    """Tests formatting with message truncation."""
    n_chars_truncated = 10
    long_message = 'a' * (
        logs.STACKDRIVER_LOG_MESSAGE_LIMIT + n_chars_truncated)
    self.log_record.msg = long_message
    formatter = logs.JsonFormatter()
    result = formatter.format(self.log_record)
    json_result = json.loads(result)
    self.assertIn(f'{n_chars_truncated} characters truncated',
                  json_result['message'])

  def test_format_worker_bot_name(self):
    """Tests formatting with worker bot name."""
    os.environ['WORKER_BOT_NAME'] = 'test_worker'
    formatter = logs.JsonFormatter()
    result = formatter.format(self.log_record)
    json_result = json.loads(result)

    self.assertEqual(json_result['worker_bot_name'], 'test_worker')

  def test_format_fuzz_target(self):
    """Tests formatting with fuzz target."""
    os.environ['FUZZ_TARGET'] = 'test_fuzz'
    formatter = logs.JsonFormatter()
    result = formatter.format(self.log_record)
    json_result = json.loads(result)

    self.assertEqual(json_result['fuzz_target'], 'test_fuzz')

  def test_format_ioerror_interrupted(self):
    """Tests formatting of IOError interrupted function call."""
    self.log_record.levelname = 'ERROR'
    self.log_record.msg = 'IOError: [Errno 4] Interrupted function call'
    formatter = logs.JsonFormatter()
    result = formatter.format(self.log_record)
    json_result = json.loads(result)

    self.assertEqual(json_result['severity'], 'WARNING')


class ConfigureTest(unittest.TestCase):
  """Test configure."""

  def setUp(self):
    helpers.patch_environ(self)
    helpers.patch(self, [
        'clusterfuzz._internal.metrics.logs.get_logging_config_dict',
        'clusterfuzz._internal.metrics.logs.set_logger',
        'logging.config.dictConfig',
        'logging.getLogger',
        'clusterfuzz._internal.metrics.logs._is_running_on_app_engine',
        'clusterfuzz._internal.metrics.logs.suppress_unwanted_warnings',
        'google.cloud.logging.Client',
    ])

  def test_configure(self):
    """Test configure."""
    self.mock._is_running_on_app_engine.return_value = False  # pylint: disable=protected-access
    logs._logger = None  # pylint: disable=protected-access
    logger = mock.MagicMock()
    self.mock.getLogger.return_value = logger

    logs.configure('test')

    self.mock.set_logger.assert_called_with(logger)
    self.mock.get_logging_config_dict.assert_called_once_with('test')
    self.mock.getLogger.assert_called_with('test')
    self.mock.dictConfig.assert_called_once_with(
        self.mock.get_logging_config_dict.return_value)

  def test_configure_appengine(self):
    """Test configure on App Engine."""
    self.mock._is_running_on_app_engine.return_value = True  # pylint: disable=protected-access
    logs.configure('test')
    self.assertEqual(0, self.mock.dictConfig.call_count)


class EmitTest(unittest.TestCase):
  """Test emit."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.metrics.logs.get_logger',
        'clusterfuzz._internal.metrics.logs._is_running_on_app_engine'
    ])
    # Reset default extras as it may be modified during other test runs.
    logs._default_extras = {}  # pylint: disable=protected-access
    self.mock._is_running_on_app_engine.return_value = False  # pylint: disable=protected-access

  def test_no_logger(self):
    """Test no logger."""
    self.mock.get_logger.return_value = None
    logs.emit(logging.INFO, 'message')

  def test_info(self):
    """Test info."""
    logger = mock.MagicMock()
    self.mock.get_logger.return_value = logger

    statement_line = inspect.currentframe().f_lineno + 1
    logs.emit(logging.INFO, 'msg', target='bot', test='yes')

    logger.log.assert_called_once_with(
        logging.INFO,
        'msg',
        exc_info=None,
        extra={
            'extras': {
                'target': 'bot',
                'test': 'yes'
            },
            'release': 'prod',
            'docker_image': '',
            'location': {
                'path': os.path.abspath(__file__).rstrip('c'),
                'line': statement_line,
                'method': 'test_info'
            }
        })

  def test_error(self):
    """Test log error."""
    logger = mock.MagicMock()
    self.mock.get_logger.return_value = logger

    statement_line = inspect.currentframe().f_lineno + 1
    logs.emit(logging.ERROR, 'msg', exc_info='ex', target='bot', test='yes')

    logger.log.assert_called_once_with(
        logging.ERROR,
        'msg',
        exc_info='ex',
        extra={
            'extras': {
                'target': 'bot',
                'test': 'yes'
            },
            'release': 'prod',
            'docker_image': '',
            'location': {
                'path': os.path.abspath(__file__).rstrip('c'),
                'line': statement_line,
                'method': 'test_error'
            }
        })


class TruncateTest(unittest.TestCase):
  """Test truncate."""

  def test_not_truncate(self):
    """Test msg is not too long."""
    self.assertEqual('abcd', logs.truncate('abcd', 4))

  def test_truncate(self):
    """Test truncate because msh is too long."""
    self.assertEqual('abc\n...5 characters truncated...\nijk',
                     logs.truncate('abcdefghijk', 6))


class ErrorTest(unittest.TestCase):
  """Tests error."""

  def setUp(self):
    helpers.patch(self,
                  ['clusterfuzz._internal.metrics.logs.emit', 'sys.exc_info'])

  def test_no_exception(self):
    """Tests no exception."""
    self.mock.exc_info.return_value = 'err'
    logs.error('test', hello='1')
    self.mock.emit.assert_called_once_with(
        logging.ERROR, 'test', exc_info='err', hello='1')

  def test_exception(self):
    """Tests exception."""
    self.mock.exc_info.return_value = 'err'
    logs.error('test', exception='exception', hello='1')
    self.mock.emit.assert_called_once_with(
        logging.ERROR, 'test', exc_info='err', hello='1')
