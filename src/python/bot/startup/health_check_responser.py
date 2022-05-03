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
"""Health check responser that checks if all processes are running as expected
   and response to health checks."""

from http.server import BaseHTTPRequestHandler
from http.server import HTTPServer
import os

RESPONSER_IP = 'localhost'
RESPONSER_PORT = 7123
EXPECTED_PROCESSES = ['run.py', 'run_bot.py']

IS_HEALTHY = 200
NOT_HEALTHY = 500


class RequestHandler(BaseHTTPRequestHandler):
  """Handler for GET request form the health checker"""

  def _is_healthy(self):
    """Check if all processes are running as expected"""
    # Note: run_bot.py is expected to go down during source updates
    #   (which can take a few minutes)
    # Health checks should be resilient to this
    # and set a threshold / check interval to account for this.
    running_processes = os.popen("ps -eo command").read()
    for process in EXPECTED_PROCESSES:
      if process not in running_processes:
        return False
    return True

  def do_GET(self):  # pylint: disable=invalid-name
    """Handle a GET request"""
    response_code = IS_HEALTHY if self._is_healthy() else NOT_HEALTHY
    self.send_response(response_code)
    self.end_headers()


def run_server():
  health_check_responser_server = HTTPServer((RESPONSER_IP, RESPONSER_PORT),
                                             RequestHandler)
  health_check_responser_server.serve_forever()
