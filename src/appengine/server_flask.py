# Copyright 2020 Google LLC
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
"""server_flask.py initialises the appengine server for ClusterFuzz."""
# TODO(singharshdeep): Rename this file to server after flask migration.
from base import utils
from config import local_config
from flask import Flask
from google.cloud import ndb
from handlers import base_handler_flask
from handlers import configuration
from handlers import fuzzers
from handlers import jobs
from handlers import login
from metrics import logs
from system import environment

ndb_client = ndb.Client()


def ndb_wsgi_middleware(wsgi_app):
  """WSGI middleware for ndb_datastore context allocation to the app."""

  def middleware(environ, start_response):
    with ndb_client.context():
      return wsgi_app(environ, start_response)

  return middleware


def register_routes(flask_app, routes):
  """Utility function to register all routes to the flask app."""
  for route, handler in routes:
    flask_app.add_url_rule(route, view_func=handler.as_view(route))


# Add item to the navigation menu. Order is important.
base_handler_flask.add_menu('Testcases', '/testcases')
base_handler_flask.add_menu('Fuzzer Statistics', '/fuzzer-stats')
base_handler_flask.add_menu('Crash Statistics', '/crash-stats')
base_handler_flask.add_menu('Upload Testcase', '/upload-testcase')

_is_chromium = utils.is_chromium()
_is_oss_fuzz = utils.is_oss_fuzz()

if _is_chromium:
  base_handler_flask.add_menu('Crashes by range', '/commit-range')

if not _is_oss_fuzz:
  base_handler_flask.add_menu('Fuzzers', '/fuzzers')
  base_handler_flask.add_menu('Corpora', '/corpora')
  base_handler_flask.add_menu('Bots', '/bots')

base_handler_flask.add_menu('Jobs', '/jobs')
base_handler_flask.add_menu('Configuration', '/configuration')
base_handler_flask.add_menu('Report Bug', '/report-bug')
base_handler_flask.add_menu('Documentation', '/docs')

logs.configure('appengine')
config = local_config.GAEConfig()

handlers = [
    ('/configuration', configuration.Handler),
    ('/add-external-user-permission', configuration.AddExternalUserPermission),
    ('/delete-external-user-permission',
     configuration.DeleteExternalUserPermission),
    ('/fuzzers', fuzzers.Handler),
    ('/fuzzers/create', fuzzers.CreateHandler),
    ('/fuzzers/delete', fuzzers.DeleteHandler),
    ('/fuzzers/edit', fuzzers.EditHandler),
    ('/fuzzers/log/<fuzzer_name>', fuzzers.LogHandler),
    ('/jobs', jobs.Handler),
    ('/jobs/load', jobs.JsonHandler),
    ('/jobs/delete-job', jobs.DeleteJobHandler),
    ('/login', login.Handler),
    ('/logout', login.LogoutHandler),
    ('/session-login', login.SessionLoginHandler),
    ('/update-job', jobs.UpdateJob),
    ('/update-job-template', jobs.UpdateJobTemplate),
]

app = Flask(__name__)
# To also process trailing slash urls.
app.url_map.strict_slashes = False

if not environment.get_value('PY_UNITTESTS'):
  # Adding ndb context middleware when not running tests.
  app.wsgi_app = ndb_wsgi_middleware(app.wsgi_app)

register_routes(app, handlers)

if __name__ == '__main__':
  app.run()
