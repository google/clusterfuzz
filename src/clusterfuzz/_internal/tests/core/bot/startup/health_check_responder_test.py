# Copyright 2022 Google LLC
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
"""health check reposnser tests."""

from http.server import HTTPServer
import os
import threading
import unittest
from unittest import mock

import psutil
import requests

from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from python.bot.startup import health_check_responder
from python.bot.startup.health_check_responder import EXPECTED_SCRIPTS
from python.bot.startup.health_check_responder import RequestHandler
from python.bot.startup.health_check_responder import RESPONDER_IP
from python.bot.startup.health_check_responder import RESPONDER_PORT

RESPONDER_ADDR = f'http://{RESPONDER_IP}:{RESPONDER_PORT}'
HTTP_REQUEST_TIMEOUT = 15


class HealthCheckResponderTest(unittest.TestCase):
  """Test health check responder."""

  def setUp(self):
    """Prepare mock processes and start the responder server thread."""
    self.mock_run_process = mock.MagicMock()
    self.mock_run_process.cmdline.return_value = ['./' + EXPECTED_SCRIPTS[0]]
    self.mock_run_bot_process = mock.MagicMock()
    self.mock_run_bot_process.cmdline.return_value = [
        './' + EXPECTED_SCRIPTS[1]
    ]

    self.health_check_responder_server = HTTPServer(
        (RESPONDER_IP, RESPONDER_PORT), RequestHandler)
    server_thread = threading.Thread(
        target=self.health_check_responder_server.serve_forever)
    server_thread.start()

  def tearDown(self):
    self.health_check_responder_server.shutdown()
    self.health_check_responder_server.server_close()

  @mock.patch(
      'python.bot.startup.health_check_responder.process_handler.psutil')
  def test_healthy(self, mock_psutil):
    """Testcase for both scripts are running."""
    mock_psutil.process_iter.return_value = [
        self.mock_run_process, self.mock_run_bot_process
    ]

    self.assertEqual(
        200,
        requests.get(f'{RESPONDER_ADDR}',
                     timeout=HTTP_REQUEST_TIMEOUT).status_code)

  @mock.patch(
      'python.bot.startup.health_check_responder.process_handler.psutil')
  def test_run_terminated(self, mock_psutil):
    """Testcase for only the run script is running."""
    mock_psutil.process_iter.return_value = [self.mock_run_process]

    self.assertEqual(
        500,
        requests.get(f'{RESPONDER_ADDR}',
                     timeout=HTTP_REQUEST_TIMEOUT).status_code)

  @mock.patch(
      'python.bot.startup.health_check_responder.process_handler.psutil')
  def test_run_bot_terminated(self, mock_psutil):
    """Testcase for only the run_bot script is running."""
    mock_psutil.process_iter.return_value = [self.mock_run_bot_process]

    self.assertEqual(
        500,
        requests.get(f'{RESPONDER_ADDR}',
                     timeout=HTTP_REQUEST_TIMEOUT).status_code)

  @mock.patch(
      'python.bot.startup.health_check_responder.process_handler.psutil')
  def test_healthy_with_inaccessible_processes(self, mock_psutil):
    """Testcase for processes whose cmdline cannot be read being skipped."""
    mock_psutil.AccessDenied = psutil.AccessDenied
    mock_psutil.NoSuchProcess = psutil.NoSuchProcess

    mock_access_denied_process = mock.MagicMock()
    mock_access_denied_process.cmdline.side_effect = psutil.AccessDenied()
    mock_no_such_process = mock.MagicMock()
    mock_no_such_process.cmdline.side_effect = psutil.NoSuchProcess(pid=1)

    mock_psutil.process_iter.return_value = [
        mock_access_denied_process, self.mock_run_process, mock_no_such_process,
        self.mock_run_bot_process
    ]

    self.assertEqual(
        200,
        requests.get(f'{RESPONDER_ADDR}',
                     timeout=HTTP_REQUEST_TIMEOUT).status_code)

  @mock.patch(
      'python.bot.startup.health_check_responder.process_handler.psutil')
  def test_both_terminated(self, mock_psutil):
    """Testcase for neither script is running."""
    mock_psutil.process_iter.return_value = []
    self.assertEqual(
        500,
        requests.get(f'{RESPONDER_ADDR}',
                     timeout=HTTP_REQUEST_TIMEOUT).status_code)


class RunServerTest(unittest.TestCase):
  """Tests for health_check_responder.run_server() gating."""

  def setUp(self):
    test_helpers.patch_environ(self)
    for key in ('OS_OVERRIDE', 'QUEUE_OVERRIDE', 'ANDROID_SERIAL'):
      os.environ.pop(key, None)
    test_helpers.patch(self, [
        'python.bot.startup.health_check_responder.HTTPServer',
        'python.bot.startup.health_check_responder.threading.Thread',
    ])

  def test_skips_physical_android_fleets(self):
    """Physical Android fleets skip binding port 7123."""
    cases = [
        ('ANDROID', 'HT75A0200123'),
        ('ANDROID_MTE:PIXEL8', '38241FDJH0037B'),
        ('ANDROID_EMULATOR', 'HT75A0200123'),
    ]
    for os_override, serial in cases:
      with self.subTest(os_override=os_override, serial=serial):
        self.mock.HTTPServer.reset_mock()
        self.mock.Thread.reset_mock()
        os.environ['OS_OVERRIDE'] = os_override
        os.environ['ANDROID_SERIAL'] = serial

        health_check_responder.run_server()

        self.mock.HTTPServer.assert_not_called()
        self.mock.Thread.assert_not_called()

  def test_skips_oss_fuzz(self):
    """OSS-Fuzz instances skip binding port 7123."""
    os.environ['OS_OVERRIDE'] = 'LINUX'
    with mock.patch.object(
        health_check_responder.utils, 'is_oss_fuzz', return_value=True):
      health_check_responder.run_server()

    self.mock.HTTPServer.assert_not_called()
    self.mock.Thread.assert_not_called()

  def test_starts_server_on_non_android_and_virtual_android_fleets(self):
    """Non-Android and virtual Android fleets start the health check server."""
    cases = [
        ('LINUX', None),
        ('ANDROID_X86', None),
        ('ANDROID_EMULATOR', 'emulator-5554'),
    ]
    for os_override, serial in cases:
      with self.subTest(os_override=os_override, serial=serial):
        self.mock.HTTPServer.reset_mock()
        self.mock.Thread.reset_mock()
        os.environ['OS_OVERRIDE'] = os_override
        if serial is None:
          os.environ.pop('ANDROID_SERIAL', None)
        else:
          os.environ['ANDROID_SERIAL'] = serial

        health_check_responder.run_server()

        self.mock.HTTPServer.assert_called_once_with(
            (RESPONDER_IP, RESPONDER_PORT), RequestHandler)
        self.mock.Thread.return_value.start.assert_called_once()
