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
import inspect
import json
import logging
import os
import sys
import unittest

import mock

from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.tests.test_libs import helpers


class GetSourceLocationTest(unittest.TestCase):
  """Test get_source_location."""

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

    logs.update_entry_with_exc(entry, exc_info)
    self.maxDiff = None  # pylint: disable=invalid-name

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
  """Test format_record."""

  def setUp(self):
    helpers.patch(self,
                  ['clusterfuzz._internal.metrics.logs.update_entry_with_exc'])
    helpers.patch_environ(self)

    self.maxDiff = None  # pylint: disable=invalid-name

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
        'extras': {
            'a': 1,
        },
        'location': {
            'path': 'path',
            'line': 123,
            'method': 'func'
        }
    }, json.loads(logs.format_record(record)))

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
        'location': {
            'path': 'path',
            'line': 123,
            'method': 'func'
        }
    }, json.loads(logs.format_record(record)))
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
        'location': {
            'path': 'path',
            'line': 123,
            'method': 'func'
        }
    }, json.loads(logs.format_record(record)))
    self.mock.update_entry_with_exc.assert_called_once_with(
        mock.ANY, 'exc_info')


class JsonSocketHandler(unittest.TestCase):
  """Test JsonSocketHandler."""

  def setUp(self):
    helpers.patch(self, ['clusterfuzz._internal.metrics.logs.format_record'])

  def test_make_pickle(self):
    """Test makePickle."""
    self.mock.format_record.return_value = 'json'

    record = mock.Mock()
    handler = logs.JsonSocketHandler(None, None)
    self.assertEqual(b'json\n', handler.makePickle(record))

    self.mock.format_record.assert_called_once_with(record)


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

  def test_log_info(self):
    """Test log info."""
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
            'location': {
                'path': os.path.abspath(__file__).rstrip('c'),
                'line': statement_line,
                'method': 'test_log_info'
            }
        })

  def test_log_error(self):
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
            'location': {
                'path': os.path.abspath(__file__).rstrip('c'),
                'line': statement_line,
                'method': 'test_log_error'
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


class LogErrorTest(unittest.TestCase):
  """Tests log_error."""

  def setUp(self):
    helpers.patch(self,
                  ['clusterfuzz._internal.metrics.logs.emit', 'sys.exc_info'])

  def test_no_exception(self):
    """Tests no exception."""
    self.mock.exc_info.return_value = 'err'
    logs.log_error('test', hello='1')
    self.mock.emit.assert_called_once_with(
        logging.ERROR, 'test', exc_info='err', hello='1')

  def test_exception(self):
    """Tests exception."""
    self.mock.exc_info.return_value = 'err'
    logs.log_error('test', exception='exception', hello='1')
    self.mock.emit.assert_called_once_with(
        logging.ERROR, 'test', exc_info='err', hello='1')
