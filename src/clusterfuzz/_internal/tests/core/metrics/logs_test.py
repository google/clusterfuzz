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
import dataclasses
import datetime
import inspect
import json
import logging
import os
import platform
import re
import sys
import unittest
from unittest import mock

from parameterized import parameterized

from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils


@dataclasses.dataclass
class SimpleDataclass:
  """A simple dataclass for testing `logs.truncate`."""
  name: str
  value: int
  active: bool


@dataclasses.dataclass
class NestedDataclass:
  """A nested dataclass for testing `logs.truncate`."""
  id: int
  data: SimpleDataclass
  extra: list


class CustomObject:
  """A custom object to test coercion to string of `logs.truncate`."""

  def __init__(self, content):
    self.content = content

  def __str__(self):
    return f'CustomObject content: {self.content}'


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

  @mock.patch(
      'clusterfuzz._internal.metrics.logs.STACKDRIVER_LOG_MESSAGE_LIMIT', 20)
  def test_truncated_exc(self):
    """Test long exception that needs to be truncated."""
    entry = {'extras': {}, 'message': 'original'}
    long_exc_message = 'a' * logs.STACKDRIVER_LOG_MESSAGE_LIMIT
    exception = Exception(long_exc_message)
    exception.extras = {'test': 'value', 'task_payload': 'task'}

    try:
      raise exception
    except:
      # We do this because we need the traceback instance.
      exc_info = sys.exc_info()

    logs.update_entry_with_exc(entry, exc_info)  # pylint: disable=used-before-assignment
    self.maxDiff = None

    self.assertRegex(
        entry['message'],
        r'original\nTraceback \n\.\.\.\d+ characters truncated\.\.\.\naaaaaaaaa\n',
        re.DOTALL)
    del entry['message']

    self.assertEqual({
        'extras': {
            'test': 'value'
        },
        'task_payload': 'task',
        'serviceContext': {
            'service': 'bots'
        }
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
        # This extras field is needed because the call
        # getattr(record, 'extras', {}) returns None and not the
        # default for the case of running against a mock
        extras={},
        location={
            'path': 'path',
            'line': 123,
            'method': 'func'
        })
    record.name = 'logger_name'
    record.getMessage.return_value = 'log message'
    return record

  @parameterized.expand([
      (
          'simple_extras',
          {
              'a': 1
          },  # input_extras
          {
              'a': 1
          },  # expected_extras_json
      ),
      (
          'no_extras',
          {},
          None,
      ),
      (
          'complex_extras',
          {
              'b': 'string',
              'c': [1, 2],
              'd': {
                  'nested': True
              }
          },
          {
              'b': 'string',
              'c': [1, 2],
              'd': {
                  'nested': True
              }
          },
      ),
      (
          'truncated_extra',
          {
              'long': 'x' * 23
          },
          {
              'long': 'x' * 10 + '\n...3 characters truncated...\n' + 'x' * 10
          },
      ),
      ('dataclass_extra', {
          'my_dataclass':
              SimpleDataclass(name='a' * 25, value=123, active=False)
      }, {
          'my_dataclass': {
              'active': False,
              'name': 'a' * 10 + '\n...5 characters truncated...\n' + 'a' * 10,
              'value': 123,
          }
      }),
  ])
  @mock.patch(
      'clusterfuzz._internal.metrics.logs.STACKDRIVER_LOG_MESSAGE_LIMIT', 20)
  def test_format_record(self, _, input_extras, expected_extras_json):
    """Test formatting a LogRecord with different 'extras' payloads."""
    os.environ['FUZZ_TARGET'] = 'fuzz_target1'
    record = self.get_record()
    record.extras = input_extras

    expected_output = {
        'message': 'log message',
        'created': '1970-01-01T00:00:10Z',
        'docker_image': '',
        'severity': 'INFO',
        'bot_name': 'linux-bot',
        'task_payload': 'fuzz fuzzer1 job1',
        'fuzz_target': 'fuzz_target1',
        'name': 'logger_name',
        'pid': 1337,
        'release': 'prod',
        'location': {
            'path': 'path',
            'line': 123,
            'method': 'func'
        }
    }

    if expected_extras_json is not None:
      expected_output['extras'] = expected_extras_json

    result_json_str = logs.JsonFormatter().format(record)
    actual_output = json.loads(result_json_str)

    self.assertEqual(expected_output, actual_output)
    self.mock.update_entry_with_exc.assert_called_once_with(
        mock.ANY, 'exc_info')

  def test_no_extras(self):
    """Test format record with no extras."""
    record = self.get_record()
    self.assertEqual({
        'message': 'log message',
        'created': '1970-01-01T00:00:10Z',
        'docker_image': '',
        'severity': 'INFO',
        'bot_name': 'linux-bot',
        'task_payload': 'fuzz fuzzer1 job1',
        'name': 'logger_name',
        'pid': 1337,
        'release': 'prod',
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

    self.assertEqual({
        'docker_image': '',
        'message': 'log message',
        'created': '1970-01-01T00:00:10Z',
        'severity': 'INFO',
        'bot_name': 'linux-bot',
        'worker_bot_name': 'worker',
        'task_payload': 'fuzz fuzzer1 job1',
        'name': 'logger_name',
        'pid': 1337,
        'release': 'prod',
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


@test_utils.with_cloud_emulators('datastore')
class EmitTest(unittest.TestCase):
  """Test emit."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.metrics.logs.get_logger',
        'clusterfuzz._internal.metrics.logs._is_running_on_app_engine',
        'clusterfuzz._internal.datastore.data_types.Testcase.get_fuzz_target',
        'clusterfuzz._internal.base.utils.get_instance_name',
    ])
    self.original_env = dict(os.environ)

    os.environ['CF_TASK_ID'] = 'f61826c3-ca9a-4b97-9c1e-9e6f4e4f8868'
    os.environ['CF_TASK_NAME'] = 'fuzz'
    os.environ['CF_TASK_ARGUMENT'] = 'libFuzzer'
    os.environ['CF_TASK_JOB_NAME'] = 'libfuzzer_asan_gopacket'

    os.environ['OS_OVERRIDE'] = 'linux'
    # Override reading the manifest file for the source version.
    os.environ['SOURCE_VERSION_OVERRIDE'] = ('20250402153042-utc-40773ac0-user'
                                             '-cad6977-prod')
    self.mock.get_instance_name.return_value = 'linux-bot'
    # Common metadata used for every log entry.
    self.common_context = {
        'clusterfuzz_version': '40773ac0',
        'clusterfuzz_config_version': 'cad6977',
        'instance_id': 'linux-bot',
        'operating_system': 'LINUX',
        'os_version': platform.release()
    }
    # Reset default extras as it may be modified during other test runs.
    logs._default_extras = {}  # pylint: disable=protected-access
    # Reset the `common_ctx` metadata as it may be setted by other test runs.
    logs.log_contexts.delete_metadata('common_ctx')
    logs.log_contexts.clear()
    self.mock._is_running_on_app_engine.return_value = False  # pylint: disable=protected-access

  def tearDown(self):
    os.environ.clear()
    os.environ.update(self.original_env)
    return super().tearDown()

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
    logs_extra = {'target': 'bot', 'test': 'yes'}
    logs_extra.update(self.common_context)

    logger.log.assert_called_once_with(
        logging.INFO,
        'msg',
        exc_info=None,
        extra={
            'extras': logs_extra,
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
    logs_extra = {'target': 'bot', 'test': 'yes'}
    logs_extra.update(self.common_context)

    logger.log.assert_called_once_with(
        logging.ERROR,
        'msg',
        exc_info='ex',
        extra={
            'extras': logs_extra,
            'location': {
                'path': os.path.abspath(__file__).rstrip('c'),
                'line': statement_line,
                'method': 'test_error'
            }
        })

  def test_symmetric_logs(self):
    """Test symmetric logs emit."""
    logger = mock.MagicMock()
    self.mock.get_logger.return_value = logger

    symmetric_logs = [{
        'label1': 'first_sym',
        'label2': 0
    }, {
        'label1': 'second_sym',
        'label2': 1
    }, {
        'label1': 'third_sym',
        'label2': 2,
        'label3': True
    }]

    statement_line = inspect.currentframe().f_lineno + 1
    logs.emit(
        logging.ERROR,
        'msg',
        exc_info='ex',
        target='bot',
        test='yes',
        symmetric_logs=symmetric_logs)
    logs_extra = {'target': 'bot', 'test': 'yes'}
    logs_extra.update(self.common_context)

    logs_extra_sym1 = logs_extra.copy()
    logs_extra_sym1.update({'label1': 'first_sym', 'label2': 0})
    logger.log.assert_any_call(
        logging.ERROR,
        'msg',
        exc_info='ex',
        extra={
            'extras': logs_extra_sym1,
            'location': {
                'path': os.path.abspath(__file__).rstrip('c'),
                'line': statement_line,
                'method': 'test_symmetric_logs'
            }
        })

    logs_extra_sym2 = logs_extra.copy()
    logs_extra_sym2.update({'label1': 'second_sym', 'label2': 1})
    logger.log.assert_any_call(
        logging.ERROR,
        'msg',
        exc_info='ex',
        extra={
            'extras': logs_extra_sym2,
            'location': {
                'path': os.path.abspath(__file__).rstrip('c'),
                'line': statement_line,
                'method': 'test_symmetric_logs'
            }
        })

    logs_extra_sym3 = logs_extra.copy()
    logs_extra_sym3.update({'label1': 'third_sym', 'label2': 2, 'label3': True})
    logger.log.assert_any_call(
        logging.ERROR,
        'msg',
        exc_info='ex',
        extra={
            'extras': logs_extra_sym3,
            'location': {
                'path': os.path.abspath(__file__).rstrip('c'),
                'line': statement_line,
                'method': 'test_symmetric_logs'
            }
        })

  def test_common_context_logs(self):
    """Test that logs common context is instanced once for distinct modules."""
    logger = mock.MagicMock()
    self.mock.get_logger.return_value = logger

    self.assertEqual(logs.log_contexts.contexts, [logs.LogContextType.COMMON])
    self.assertEqual(logs.log_contexts.meta, {})
    logs.info('msg')
    self.assertEqual(logs.log_contexts.meta,
                     {'common_ctx': self.common_context})
    from python.bot.startup.run_bot import logs as logs_from_run_bot
    self.assertEqual(logs_from_run_bot.log_contexts.meta,
                     {'common_ctx': self.common_context})

  @logs.task_stage_context(logs.Stage.PREPROCESS)
  def test_task_log_context(self):
    """Test that the logger is called with the correct arguments considering
    the task-based log context and metadata.
    """
    logger = mock.MagicMock()
    self.mock.get_logger.return_value = logger
    self.assertEqual(logs.log_contexts.contexts,
                     [logs.LogContextType.COMMON, logs.LogContextType.TASK])
    self.assertEqual(logs.log_contexts.meta, {'stage': logs.Stage.PREPROCESS})
    logs_extra = {'target': 'bot', 'test': 'yes'}
    logs_extra.update(self.common_context)
    logs_extra.update({
        'task_id': 'f61826c3-ca9a-4b97-9c1e-9e6f4e4f8868',
        'task_name': 'fuzz',
        'task_argument': 'libFuzzer',
        'task_job_name': 'libfuzzer_asan_gopacket',
        'stage': 'preprocess'
    })
    statement_line = inspect.currentframe().f_lineno + 1
    logs.emit(logging.ERROR, 'msg', exc_info='ex', target='bot', test='yes')
    # Assert that the common context was added after the first logs call.
    self.assertEqual(logs.log_contexts.meta, {
        'common_ctx': self.common_context,
        'stage': logs.Stage.PREPROCESS
    })
    logger.log.assert_called_once_with(
        logging.ERROR,
        'msg',
        exc_info='ex',
        extra={
            'extras': logs_extra,
            'location': {
                'path': os.path.abspath(__file__).rstrip('c'),
                'line': statement_line,
                'method': 'test_task_log_context'
            },
        })

  def test_testcase_log_context(self):
    """Test that the logger is called with the correct arguments considering
    a testcase-based task context and metadata.
    """
    from clusterfuzz._internal.datastore import data_types
    logger = mock.MagicMock()
    self.mock.get_logger.return_value = logger
    fuzz_target = data_types.FuzzTarget(
        id='libFuzzer_abc', engine='libFuzzer', binary='abc')
    fuzz_target.put()
    testcase = data_types.Testcase(
        fuzzer_name="test_fuzzer", job_type='test_job')
    testcase.put()

    with logs.testcase_log_context(testcase, fuzz_target):
      self.assertEqual(logs.log_contexts.contexts, [
          logs.LogContextType.COMMON, logs.LogContextType.FUZZER,
          logs.LogContextType.TESTCASE
      ])
      statement_line = inspect.currentframe().f_lineno + 1
      logs.emit(logging.ERROR, 'msg', exc_info='ex', target='bot', test='yes')
      # Assert metadata after emit to ensure that `common_ctx` has been added.
      self.assertEqual(
          logs.log_contexts.meta, {
              'common_ctx': self.common_context,
              'testcase': testcase,
              'testcase_id': 1,
              'testcase_group': 0,
              'fuzz_target': fuzz_target.binary,
              'fuzzer_name': testcase.fuzzer_name,
              'job_type': testcase.job_type
          })

    logs_extra = {'target': 'bot', 'test': 'yes'}
    logs_extra.update(self.common_context)
    logs_extra.update({
        'testcase_id': 1,
        'testcase_group': 0,
        'fuzz_target': 'abc',
        'job': 'test_job',
        'fuzzer': 'test_fuzzer'
    })
    logger.log.assert_called_with(
        logging.ERROR,
        'msg',
        exc_info='ex',
        extra={
            'extras': logs_extra,
            'location': {
                'path': os.path.abspath(__file__).rstrip('c'),
                'line': statement_line,
                'method': 'test_testcase_log_context'
            },
        })

  def test_task_context_logs_during_exception(self):
    """Checks that the task_stage_context logs the correct error context in
    the decorated scope.
    """
    logger = mock.MagicMock()
    self.mock.get_logger.return_value = logger
    logs_extras = {
        'task_id': 'f61826c3-ca9a-4b97-9c1e-9e6f4e4f8868',
        'task_name': 'fuzz',
        'task_argument': 'libFuzzer',
        'task_job_name': 'libfuzzer_asan_gopacket',
        'stage': 'preprocess'
    }
    logs_extras.update(self.common_context)

    with logs.task_stage_context(logs.Stage.PREPROCESS):
      try:
        exception = Exception('msg')
        raise exception
      except Exception:
        statement_line = inspect.currentframe().f_lineno + 1
        logs.error('xpto')
        logger.log.assert_called_once_with(
            logging.ERROR,
            'xpto',
            exc_info=sys.exc_info(),
            extra={
                'extras': logs_extras,
                'location': {
                    'path': os.path.abspath(__file__).rstrip('c'),
                    'line': statement_line,
                    'method': 'test_task_context_logs_during_exception'
                },
            })

  def test_task_context_catches_and_logs_exception(self):
    """Checks that the task_stage_context catches and logs the error raised in
    the decorated scope."""
    logger = mock.MagicMock()
    self.mock.get_logger.return_value = logger

    helpers.patch(self,
                  ['clusterfuzz._internal.metrics.logs.get_source_location'])
    path_name = '/lib/contextlib.py'
    line_number = 123
    method_name = '__exit__'
    self.mock.get_source_location.return_value = (path_name, line_number,
                                                  method_name)
    logs_extras = {
        'task_id': 'f61826c3-ca9a-4b97-9c1e-9e6f4e4f8868',
        'task_name': 'fuzz',
        'task_argument': 'libFuzzer',
        'task_job_name': 'libfuzzer_asan_gopacket',
        'stage': 'preprocess'
    }
    logs_extras.update(self.common_context)

    try:
      with logs.task_stage_context(logs.Stage.PREPROCESS):
        exception = Exception('msg')
        raise exception
    except Exception:
      logger.log.assert_called_once_with(
          logging.WARNING,
          'Error during task context.',
          exc_info=mock.ANY,
          extra={
              'extras': logs_extras,
              'location': {
                  'path': path_name,
                  'line': line_number,
                  'method': method_name
              },
          })

  @logs.task_stage_context(logs.Stage.PREPROCESS)
  def test_log_ignore_context(self):
    """Test that the emit interceptor ignores context when passed the
    ignore_context flag.
    """
    logger = mock.MagicMock()
    self.mock.get_logger.return_value = logger

    self.assertEqual(logs.log_contexts.contexts,
                     [logs.LogContextType.COMMON, logs.LogContextType.TASK])
    self.assertEqual(logs.log_contexts.meta, {'stage': logs.Stage.PREPROCESS})
    statement_line = inspect.currentframe().f_lineno + 1
    logs.emit(
        logging.ERROR,
        'msg',
        exc_info='ex',
        target='bot',
        test='yes',
        ignore_context=True)

    logs_extra = {'target': 'bot', 'test': 'yes'}
    logger.log.assert_called_once_with(
        logging.ERROR,
        'msg',
        exc_info='ex',
        extra={
            'extras': logs_extra,
            'location': {
                'path': os.path.abspath(__file__).rstrip('c'),
                'line': statement_line,
                'method': 'test_log_ignore_context'
            },
        })

  def test_missing_fuzz_target_in_testcase_context(self):
    """Test the testcase-based log context when the fuzz target is missing."""
    from clusterfuzz._internal.datastore import data_types
    logger = mock.MagicMock()
    self.mock.get_logger.return_value = logger
    testcase = data_types.Testcase(
        fuzzer_name='test_fuzzer', job_type='test_job')
    # Set this metadata to be used instead of the fuzz_target entity.
    testcase.set_metadata('fuzzer_binary_name', 'fuzz_abc')
    testcase.put()

    logs_extra = {'target': 'bot', 'test': 'yes'}
    logs_extra.update({
        'testcase_id': 1,
        'testcase_group': 0,
        'fuzz_target': 'fuzz_abc',
        'job': 'test_job',
        'fuzzer': 'test_fuzzer'
    })
    logs_extra.update(self.common_context)

    with logs.testcase_log_context(testcase, None):
      self.assertEqual(logs.log_contexts.contexts, [
          logs.LogContextType.COMMON, logs.LogContextType.FUZZER,
          logs.LogContextType.TESTCASE
      ])
      statement_line = inspect.currentframe().f_lineno + 1
      logs.emit(logging.ERROR, 'msg', exc_info='ex', target='bot', test='yes')
      self.assertEqual(
          logs.log_contexts.meta, {
              'common_ctx': self.common_context,
              'testcase': testcase,
              'testcase_id': 1,
              'testcase_group': 0,
              'fuzz_target': testcase.get_metadata('fuzzer_binary_name'),
              'fuzzer_name': testcase.fuzzer_name,
              'job_type': testcase.job_type
          })

    logger.log.assert_called_with(
        logging.ERROR,
        'msg',
        exc_info='ex',
        extra={
            'extras': logs_extra,
            'location': {
                'path': os.path.abspath(__file__).rstrip('c'),
                'line': statement_line,
                'method': 'test_missing_fuzz_target_in_testcase_context'
            },
        })

  def test_fuzzer_log_context(self):
    """Test the correct logger call for the fuzzer-based log context."""
    from clusterfuzz._internal.datastore import data_types
    logger = mock.MagicMock()
    self.mock.get_logger.return_value = logger

    fuzz_target = data_types.FuzzTarget(
        id='libFuzzer_abc', engine='libFuzzer', binary='abc')
    fuzz_target.put()
    fuzzer_name = 'test_fuzzer'
    job_type = 'test_job'

    with logs.fuzzer_log_context(fuzzer_name, job_type, fuzz_target):
      self.assertEqual(logs.log_contexts.contexts,
                       [logs.LogContextType.COMMON, logs.LogContextType.FUZZER])
      statement_line = inspect.currentframe().f_lineno + 1
      logs.emit(logging.ERROR, 'msg', exc_info='ex', target='bot', test='yes')
      # Assert metadata after emit to ensure that `common_ctx` has been added.
      self.assertEqual(
          logs.log_contexts.meta, {
              'common_ctx': self.common_context,
              'fuzz_target': fuzz_target.binary,
              'fuzzer_name': fuzzer_name,
              'job_type': job_type
          })

    logs_extra = {'target': 'bot', 'test': 'yes'}
    logs_extra.update(self.common_context)
    logs_extra.update({
        'fuzz_target': 'abc',
        'job': 'test_job',
        'fuzzer': 'test_fuzzer'
    })
    logger.log.assert_called_with(
        logging.ERROR,
        'msg',
        exc_info='ex',
        extra={
            'extras': logs_extra,
            'location': {
                'path': os.path.abspath(__file__).rstrip('c'),
                'line': statement_line,
                'method': 'test_fuzzer_log_context'
            },
        })

  @logs.cron_log_context()
  def test_cron_log_context(self):
    """Test the correct logger call for the cron-based log context."""
    from clusterfuzz._internal.system.environment import set_task_id_vars
    task_name = 'cleanup'
    task_id = '12345-6789'
    set_task_id_vars(task_name, task_id)

    logger = mock.MagicMock()
    self.mock.get_logger.return_value = logger
    self.assertEqual(logs.log_contexts.contexts,
                     [logs.LogContextType.COMMON, logs.LogContextType.CRON])
    logs_extra = {'target': 'bot', 'test': 'yes'}
    logs_extra.update(self.common_context)
    logs_extra.update({
        'task_id': task_id,
        'task_name': task_name,
    })
    statement_line = inspect.currentframe().f_lineno + 1
    logs.emit(logging.ERROR, 'msg', exc_info='ex', target='bot', test='yes')
    # Assert that the common context was added after the first logs call.
    self.assertEqual(logs.log_contexts.meta, {
        'common_ctx': self.common_context,
    })
    logger.log.assert_called_once_with(
        logging.ERROR,
        'msg',
        exc_info='ex',
        extra={
            'extras': logs_extra,
            'location': {
                'path': os.path.abspath(__file__).rstrip('c'),
                'line': statement_line,
                'method': 'test_cron_log_context'
            },
        })

  @logs.cron_log_context()
  def test_grouper_log_context(self):
    """Test the logger call and metadata for a grouper-based context."""
    from clusterfuzz._internal.cron.grouper import TestcaseAttributes
    from clusterfuzz._internal.datastore import data_types
    from clusterfuzz._internal.system.environment import set_task_id_vars
    task_name = 'triage'
    task_id = 'abcd-12345'
    set_task_id_vars(task_name, task_id)

    testcase_1 = data_types.Testcase()
    testcase_2 = data_types.Testcase(group_id=112233)
    testcase_1.put()
    testcase_2.put()

    testcase_1_attr = TestcaseAttributes(testcase_1.key.id())
    testcase_1_attr.group_id = testcase_1.group_id
    testcase_2_attr = TestcaseAttributes(testcase_2.key.id())
    testcase_2_attr.group_id = testcase_2.group_id

    logger = mock.MagicMock()
    self.mock.get_logger.return_value = logger

    with logs.grouper_log_context(testcase_1_attr, testcase_2_attr):
      self.assertEqual(logs.log_contexts.contexts, [
          logs.LogContextType.COMMON, logs.LogContextType.CRON,
          logs.LogContextType.GROUPER
      ])
      statement_line = inspect.currentframe().f_lineno + 1
      logs.emit(logging.ERROR, 'msg', exc_info='ex', target='bot', test='yes')
      # Assert metadata after emit to ensure that `common_ctx` has been added.
      self.assertEqual(
          logs.log_contexts.meta, {
              'common_ctx': self.common_context,
              'testcase_1_id': 1,
              'testcase_2_id': 2,
              'testcase_1_group': 0,
              'testcase_2_group': 112233
          })

    logs_extra = {'target': 'bot', 'test': 'yes'}
    logs_extra.update(self.common_context)
    logs_extra.update({
        'task_id': task_id,
        'task_name': task_name,
    })

    # Logger call with testcase 1
    logs_extra.update({
        'testcase_id': 1,
        'testcase_group': 0,
    })
    logger.log.assert_any_call(
        logging.ERROR,
        'msg',
        exc_info='ex',
        extra={
            'extras': logs_extra,
            'location': {
                'path': os.path.abspath(__file__).rstrip('c'),
                'line': statement_line,
                'method': 'test_grouper_log_context'
            },
        })

    # Logger call with testcase 2
    logs_extra.update({
        'testcase_id': 2,
        'testcase_group': 112233,
    })
    logger.log.assert_any_call(
        logging.ERROR,
        'msg',
        exc_info='ex',
        extra={
            'extras': logs_extra,
            'location': {
                'path': os.path.abspath(__file__).rstrip('c'),
                'line': statement_line,
                'method': 'test_grouper_log_context'
            },
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

  def test_no_truncation_if_unnecessary(self):
    """Tests that no truncation occurs for a short string."""
    self.assertEqual('hello world', logs.truncate('hello world', 20))
    self.assertEqual('hello world', logs.truncate('hello world', 11))

  def test_no_truncation_for_non_truncatable_types(self):
    """Tests that specific primitive types are returned as-is."""
    self.assertEqual(12345, logs.truncate(12345, 4))
    self.assertIs(12345, logs.truncate(12345, 4))
    self.assertEqual(123.45, logs.truncate(123.45, 5))
    self.assertIs(123.45, logs.truncate(123.45, 5))
    self.assertTrue(logs.truncate(True, 1))
    self.assertIs(True, logs.truncate(True, 1))
    self.assertIsNone(logs.truncate(None, 1))

  def test_simple_string_truncation(self):
    """Tests basic truncation of a long string with an even limit."""
    long_string = 'abcdefghijklmnopqrstuvwxyz'
    limit = 10

    # half = 5, first 5 chars are 'abcde', last 5 are 'vwxyz'
    expected = 'abcde\n...16 characters truncated...\nvwxyz'

    self.assertEqual(expected, logs.truncate(long_string, limit))

  def test_string_truncation_with_odd_limit(self):
    """Tests truncation with an odd limit value."""
    long_string = 'abcdefghijklmnopqrstuvwxyz'
    limit = 11

    # half = 5, first 5 chars are 'abcde', last 5 are 'vwxyz'
    expected = 'abcde\n...15 characters truncated...\nvwxyz'

    self.assertEqual(expected, logs.truncate(long_string, limit))

  def test_object_coercion_and_truncation(self):
    """Tests that custom objects are coerced to string and then truncated."""
    limit = 30
    obj = CustomObject('x' * 50)

    expected = 'CustomObject co\n...42 characters truncated...\nxxxxxxxxxxxxxxx'

    self.assertEqual(expected, logs.truncate(obj, limit))

  def test_list_truncation(self):
    """Tests recursive truncation within a list."""
    limit = 20
    input_list = ['a' * 30, 'b' * 5, 'c' * 33, 123]

    expected_list = [
        'aaaaaaaaaa\n...10 characters truncated...\naaaaaaaaaa', 'b' * 5,
        'cccccccccc\n...13 characters truncated...\ncccccccccc', 123
    ]

    result = logs.truncate(input_list, limit)
    self.assertIsInstance(result, list)
    self.assertEqual(expected_list, result)

  def test_tuple_truncation(self):
    """Tests recursive truncation within a tuple, preserving type."""
    limit = 20
    input_tuple = ('a' * 30, 'c' * 5, True, None)

    expected_tuple = ('aaaaaaaaaa\n...10 characters truncated...\naaaaaaaaaa',
                      'c' * 5, True, None)

    result = logs.truncate(input_tuple, limit)
    self.assertIsInstance(result, tuple)
    self.assertEqual(expected_tuple, result)

  def test_namedtuple_truncation(self):
    """Tests namedtuple truncation worked properly"""
    import collections
    BatchWorkloadSpec = collections.namedtuple('BatchWorkloadSpec', [
        'clusterfuzz_release',
        'disk_size_gb',
        'disk_type',
        'docker_image',
        'user_data',
        'service_account_email',
        'subnetwork',
        'preemptible',
        'project',
        'machine_type',
        'network',
        'gce_region',
        'priority',
        'max_run_duration',
        'retry',
    ])
    limit = 20
    spec = BatchWorkloadSpec(
        docker_image='a' * 100,
        disk_size_gb=1,
        disk_type='x',
        user_data='foo',
        service_account_email='bar',
        preemptible=True,
        machine_type='xpto',
        gce_region='region',
        network='brisanet',
        subnetwork='brisa',
        project='cf',
        clusterfuzz_release='1.0',
        priority='high',
        max_run_duration=10,
        retry=False,
    )
    result = logs.truncate(spec, limit)
    expected = {
        'clusterfuzz_release':
            '1.0',
        'disk_size_gb':
            1,
        'disk_type':
            'x',
        'docker_image':
            'aaaaaaaaaa\n...80 characters truncated...\naaaaaaaaaa',
        'user_data':
            'foo',
        'service_account_email':
            'bar',
        'subnetwork':
            'brisa',
        'preemptible':
            True,
        'project':
            'cf',
        'machine_type':
            'xpto',
        'network':
            'brisanet',
        'gce_region':
            'region',
        'priority':
            'high',
        'max_run_duration':
            10,
        'retry':
            False
    }
    self.assertEqual(expected, result)

  def test_dict_truncation(self):
    """Tests recursive truncation of dictionary values."""
    limit = 7
    input_dict = {
        'long_key': 'a' * 40,
        'short_key': 'b' * 5,
        'numeric_key': 99,
        'nested_list': ['keep', 'c' * 20],
        'another_long_string_key': 'd' * 30,
    }

    expected_dict = {
        'long_key': 'aaa\n...33 characters truncated...\naaa',
        'short_key': 'bbbbb',
        'numeric_key': 99,
        'nested_list': ['keep', 'ccc\n...13 characters truncated...\nccc'],
        'another_long_string_key': 'ddd\n...23 characters truncated...\nddd',
    }

    result = logs.truncate(input_dict, limit)
    self.assertIsInstance(result, dict)
    self.assertEqual(expected_dict, result)

  def test_dataclass_truncation(self):
    """Tests truncation of fields within a simple dataclass."""
    limit = 30
    dc_instance = SimpleDataclass(
        name='This is a very long dataclass name that must be truncated',
        value=100,
        active=True)

    # Dataclass is converted to dict for truncation.
    expected_result = {
        'name':
            'This is a very \n...27 characters truncated...\nst be truncated',
        'value':
            100,
        'active':
            True
    }

    self.assertEqual(expected_result, logs.truncate(dc_instance, limit))

  def test_nested_dataclass_truncation(self):
    """Tests truncation within a complex, nested dataclass structure."""
    limit = 20
    nested_dc_instance = NestedDataclass(
        id=123,
        data=SimpleDataclass(
            name='A very long name for the inner simple dataclass object',
            value=200,
            active=False),
        extra=['short_item', 'z' * 50, 42])

    expected_result = {
        'id':
            123,
        'data': {
            'name': 'A very lon\n...34 characters truncated...\nass object',
            'value': 200,
            'active': False
        },
        'extra': [
            'short_item',
            'zzzzzzzzzz\n...30 characters truncated...\nzzzzzzzzzz', 42
        ]
    }

    self.assertEqual(expected_result, logs.truncate(nested_dc_instance, limit))

  def test_empty_collections(self):
    """Tests that empty collections are handled correctly."""
    self.assertEqual([], logs.truncate([], 10))
    self.assertEqual((), logs.truncate((), 10))
    self.assertEqual({}, logs.truncate({}, 10))

  def test_complex_nested_structure(self):
    """Tests a complex mix of lists, dicts, and tuples."""
    limit = 12
    structure = [{
        'id': 1,
        'data': 'This is a long string that definitely needs to be cut.',
        'tags': ('tag1', 'a much much much longer tag value'),
        'metadata': {
            'source': 'Source name is extremely long and will be cut',
            'valid': True
        }
    }, 'Just a short string in the list', {
        'id': 2,
        'data': 'short data'
    }]

    expected_structure = [{
        'id': 1,
        'data': 'This i\n...42 characters truncated...\ne cut.',
        'tags': ('tag1', 'a much\n...21 characters truncated...\n value'),
        'metadata': {
            'source': 'Source\n...33 characters truncated...\nbe cut',
            'valid': True
        }
    }, 'Just a\n...19 characters truncated...\ne list', {
        'id': 2,
        'data': 'short data'
    }]

    result = logs.truncate(structure, limit)
    self.assertEqual(expected_structure, result)
    # Check that the nested tuple type was preserved.
    self.assertIsInstance(result[0]['tags'], tuple)

  def test_exception_during_dict_truncation(self):
    """Tests the try-catch block when some object operation fails."""

    class FailingDict(dict):
      """A dict subclass designed to fail during item iteration."""

      def items(self):
        raise ValueError('Intentionally failing item access')

      def __str__(self):
        return (
            'This is the string representation of a FailingDict object that is'
            ' very long')

    failing_dict = FailingDict({'key': 'value'})
    limit = 25
    result = logs.truncate(failing_dict, limit)

    self.assertIn('Exception during truncate: Intentionally failing ite',
                  result)  # Exception message is also limited.
    self.assertIn('...50 characters truncated...', result)


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


class TestLogContextSingleton(unittest.TestCase):
  """Tests for the log context singleton.

  It checks the singleton behavior works and is thread safe.
  """

  def test_is_same(self):
    """Test the singleton is the same instance for different module loads."""
    from clusterfuzz._internal.base.tasks.task_rate_limiting import \
        logs as logs_from_task_rate_limiting
    from python.bot.startup.run_bot import logs as logs_from_run_bot

    self.assertIs(logs_from_run_bot, logs_from_task_rate_limiting)
    self.assertIs(logs_from_run_bot.log_contexts,
                  logs_from_run_bot.LogContexts())
    logs_from_run_bot.log_contexts.add([logs_from_run_bot.LogContextType.TASK])

    self.assertEqual(logs_from_task_rate_limiting.log_contexts,
                     logs_from_run_bot.log_contexts)
    logs_from_run_bot.log_contexts.clear()

  def test_multi_threading(self):
    """Test multithread."""

    def incrementer():
      from python.bot.startup.run_bot import logs as run_bot_logs
      run_bot_logs.log_contexts.add([logs.LogContextType.TASK])

    import threading
    threads = []
    num_it = 5
    for _ in range(num_it):
      thread = threading.Thread(target=incrementer)
      threads.append(thread)
      thread.start()

    for thread in threads:
      thread.join()

    from python.bot.startup.run_bot import logs as run_bot_logs

    # Number of increments plus the common context.
    self.assertEqual(len(run_bot_logs.log_contexts.contexts), num_it + 1)
