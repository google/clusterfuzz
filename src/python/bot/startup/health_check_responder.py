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
"""Health check responder that checks if all scripts are running as expected
   and responds to health checks."""

from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
from http.server import HTTPServer
import threading

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.system import process_handler

RESPONDER_IP = '0.0.0.0'
RESPONDER_PORT = 7123
EXPECTED_SCRIPTS = ['run.py', 'run_bot.py']


class RequestHandler(BaseHTTPRequestHandler):
  """Handler for GET request form the health checker."""

  def do_GET(self):  # pylint: disable=invalid-name
    """Handle a GET request."""
    if process_handler.scripts_are_running(EXPECTED_SCRIPTS):
      # Note: run_bot.py is expected to go down during source updates
      #   (which can take a few minutes)
      # Health checks should be resilient to this
      # and set a threshold / check interval to account for this.
      response_code = HTTPStatus.OK
    else:
      response_code = HTTPStatus.INTERNAL_SERVER_ERROR
    self.send_response(response_code)
    self.end_headers()


def run_server():
  """Start a HTTP server to respond to the health checker."""
  if utils.is_oss_fuzz():
    # OSS-Fuzz's multiple instances per host model isn't supported yet.
    return

  health_check_responder_server = HTTPServer((RESPONDER_IP, RESPONDER_PORT),
                                             RequestHandler)
  server_thread = threading.Thread(
      target=health_check_responder_server.serve_forever)
  server_thread.start()
