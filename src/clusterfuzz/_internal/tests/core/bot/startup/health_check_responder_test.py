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
import threading
import unittest

import mock
import requests

from python.bot.startup.health_check_responder import EXPECTED_SCRIPTS
from python.bot.startup.health_check_responder import RequestHandler
from python.bot.startup.health_check_responder import RESPONDER_IP
from python.bot.startup.health_check_responder import RESPONDER_PORT

RESPONDER_ADDR = f'http://{RESPONDER_IP}:{RESPONDER_PORT}'


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

    self.assertEqual(200, requests.get(f'{RESPONDER_ADDR}').status_code)

  @mock.patch(
      'python.bot.startup.health_check_responder.process_handler.psutil')
  def test_run_terminated(self, mock_psutil):
    """Testcase for only the run script is running."""
    mock_psutil.process_iter.return_value = [self.mock_run_process]

    self.assertEqual(500, requests.get(f'{RESPONDER_ADDR}').status_code)

  @mock.patch(
      'python.bot.startup.health_check_responder.process_handler.psutil')
  def test_run_bot_terminated(self, mock_psutil):
    """Testcase for only the run_bot script is running."""
    mock_psutil.process_iter.return_value = [self.mock_run_bot_process]

    self.assertEqual(500, requests.get(f'{RESPONDER_ADDR}').status_code)

  @mock.patch(
      'python.bot.startup.health_check_responder.process_handler.psutil')
  def test_both_terminated(self, mock_psutil):
    """Testcase for neither script is running."""
    mock_psutil.process_iter.return_value = []
    self.assertEqual(500, requests.get(f'{RESPONDER_ADDR}').status_code)
