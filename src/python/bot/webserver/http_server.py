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
"""Runs http(s) server in the background."""

import http.server
import mimetypes
import os
import socket
import threading

from system import environment


def get_absolute_testcase_file(request_path):
  """Search the input directory and additional paths for the requested file."""
  # Gather the list of search path directories.
  current_working_directory = os.getcwd()
  data_directory = environment.get_value('FUZZ_DATA')
  input_directory = environment.get_value('INPUT_DIR')
  fuzzer_directory = environment.get_value('FUZZERS_DIR')
  layout_tests_directory = os.path.join(data_directory, 'LayoutTests')
  layout_tests_http_tests_directory = os.path.join(layout_tests_directory,
                                                   'http', 'tests')
  layout_tests_wpt_tests_directory = os.path.join(layout_tests_directory,
                                                  'external', 'wpt')

  # TODO(mbarbella): Add support for aliasing and directories from
  # https://cs.chromium.org/chromium/src/third_party/blink/tools/blinkpy/web_tests/servers/apache_http.py?q=apache_http.py&sq=package:chromium&dr&l=60

  # Check all search paths for the requested file.
  search_paths = [
      current_working_directory,
      fuzzer_directory,
      input_directory,
      layout_tests_directory,
      layout_tests_http_tests_directory,
      layout_tests_wpt_tests_directory,
  ]
  for search_path in search_paths:
    base_string = search_path + os.path.sep
    path = request_path.lstrip('/')
    if not path or path.endswith('/'):
      path += 'index.html'
    absolute_path = os.path.abspath(os.path.join(search_path, path))
    if (absolute_path.startswith(base_string) and
        os.path.exists(absolute_path) and not os.path.isdir(absolute_path)):
      return absolute_path

  return None


def guess_mime_type(filename):
  """Guess mime type based of file extension."""
  if not mimetypes.inited:
    mimetypes.init()

  return mimetypes.guess_type(filename)[0]


class BotHTTPServer(http.server.HTTPServer):
  """Host the bot's test case directories over HTTP."""

  def __init__(self, server_address, handler_class):
    http.server.HTTPServer.__init__(self, server_address, handler_class)

  def _handle_request_noblock(self):
    """Process a single http request."""
    try:
      request, client_address = self.get_request()
    except socket.error:
      return
    if self.verify_request(request, client_address):
      try:
        self.process_request(request, client_address)
      except:
        self.close_request(request)


class RequestHandler(http.server.BaseHTTPRequestHandler):
  """Handler for get requests to test cases."""

  def do_GET(self):  # pylint: disable=invalid-name
    """Handle a GET request."""
    absolute_path = get_absolute_testcase_file(self.path)
    if not absolute_path:
      self.send_response(404)
      self.end_headers()
      return

    try:
      with open(absolute_path) as file_handle:
        data = file_handle.read()
    except IOError:
      self.send_response(403)
      self.end_headers()
      return

    self.send_response(200, 'OK')

    # Send a content type header if applicable.
    mime_type = guess_mime_type(absolute_path)
    if mime_type:
      self.send_header('Content-type', mime_type)

    self.end_headers()
    self.wfile.write(data)

  def log_message(self, fmt, *args):  # pylint: disable=arguments-differ
    """Do not output a log entry to stderr for every request made."""


def run_server(host, port):
  """Run the HTTP server on the given port."""
  httpd = BotHTTPServer((host, port), RequestHandler)
  httpd.serve_forever()


def port_is_open(host, port):
  socket_handle = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  result = socket_handle.connect_ex((host, port))
  socket_handle.close()
  return result == 0


def start_server_thread(host, port):
  server = threading.Thread(target=run_server, args=(host, port))
  server.daemon = True
  server.start()


def start():
  """Initialize the HTTP server on the specified ports."""
  http_host = 'localhost'
  http_port_1 = environment.get_value('HTTP_PORT_1', 8000)
  http_port_2 = environment.get_value('HTTP_PORT_2', 8080)
  if not port_is_open(http_host, http_port_1):
    start_server_thread(http_host, http_port_1)
  if not port_is_open(http_host, http_port_2):
    start_server_thread(http_host, http_port_2)
