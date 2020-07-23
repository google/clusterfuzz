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
from base import utils
from config import local_config
from flask import Flask
from google.cloud import ndb
from handlers import base_handler
from handlers import jobs
from metrics import logs
from system import environment

_is_chromium = utils.is_chromium()
_is_oss_fuzz = utils.is_oss_fuzz()


def register_route(route, **kwargs):
  """
  This method registers routes and binds them to Method Views
  :param route:
  :param kwargs:
  :return:
  """
  app.add_url_rule(
      route, view_func=kwargs['handler'].as_view(kwargs.get('name', route)))


client = ndb.Client()


def ndb_wsgi_middleware(wsgi_app):

  def middleware(environ, start_response):
    with client.context():
      return wsgi_app(environ, start_response)

  return middleware


# Add item to the navigation menu. Order is important.
base_handler.add_menu('Testcases', '/testcases')
base_handler.add_menu('Fuzzer Statistics', '/fuzzer-stats')
base_handler.add_menu('Crash Statistics', '/crash-stats')
base_handler.add_menu('Upload Testcase', '/upload-testcase')

if _is_chromium:
  base_handler.add_menu('Crashes by range', '/commit-range')

if not _is_oss_fuzz:
  base_handler.add_menu('Fuzzers', '/fuzzers')
  base_handler.add_menu('Corpora', '/corpora')
  base_handler.add_menu('Bots', '/bots')

base_handler.add_menu('Jobs', '/flask/jobs')
base_handler.add_menu('Configuration', '/configuration')
base_handler.add_menu('Report Bug', '/report-bug')
base_handler.add_menu('Documentation', '/docs')

logs.configure('appengine')
config = local_config.GAEConfig()

app = Flask(__name__)
app.config["APPLICATION_ROOT"] = ""
if not environment.get_value('PY_UNITTESTS'):
  # Adding ndb context middleware when not running tests.
  app.wsgi_app = ndb_wsgi_middleware(app.wsgi_app)

register_route('/jobs', handler=jobs.Handler)
register_route('/jobs/load', handler=jobs.JsonHandler)
register_route('/jobs/delete-job', handler=jobs.DeleteJobHandler)
register_route('/update-job', handler=jobs.UpdateJob)
register_route('/update-job-template', handler=jobs.UpdateJobTemplate)

if __name__ == "__main__":
  app.run(debug=True)
