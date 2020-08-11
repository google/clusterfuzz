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
from handlers import bots
from handlers import configuration
from handlers import corpora
from handlers import crash_stats
from handlers import download
from handlers import fuzzers
from handlers import help_redirector
from handlers import home
from handlers import issue_redirector
from handlers import jobs
from handlers import login
from handlers import testcase_list
from handlers import upload_testcase
from handlers.testcase_detail import (crash_stats as crash_stats_on_testcase)
from handlers.testcase_detail import (show as show_testcase)
from handlers.testcase_detail import create_issue
from handlers.testcase_detail import delete
from handlers.testcase_detail import download_testcase
from handlers.testcase_detail import find_similar_issues
from handlers.testcase_detail import mark_fixed
from handlers.testcase_detail import mark_security
from handlers.testcase_detail import mark_unconfirmed
from handlers.testcase_detail import redo
from handlers.testcase_detail import remove_duplicate
from handlers.testcase_detail import remove_group
from handlers.testcase_detail import remove_issue
from handlers.testcase_detail import testcase_variants
from handlers.testcase_detail import update_from_trunk
from handlers.testcase_detail import update_issue
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

# We need to separate routes for cron to avoid redirection.
cron_routes = [
    ('/home-cache', home.RefreshCacheHandler),
    ('/testcases/cache', testcase_list.CacheHandler),
]

handlers = [
    ('/', home.Handler if _is_oss_fuzz else testcase_list.Handler),
    ('/bots', bots.Handler),
    ('/bots/dead', bots.DeadBotsHandler),
    ('/configuration', configuration.Handler),
    ('/add-external-user-permission', configuration.AddExternalUserPermission),
    ('/delete-external-user-permission',
     configuration.DeleteExternalUserPermission),
    ('/crash-stats/load', crash_stats.JsonHandler),
    ('/crash-stats', crash_stats.Handler),
    ('/corpora', corpora.Handler),
    ('/corpora/create', corpora.CreateHandler),
    ('/corpora/delete', corpora.DeleteHandler),
    ('/docs', help_redirector.DocumentationHandler),
    ('/download', download.Handler),
    ('/download/<resource>', download.Handler),
    ('/fuzzers', fuzzers.Handler),
    ('/fuzzers/create', fuzzers.CreateHandler),
    ('/fuzzers/delete', fuzzers.DeleteHandler),
    ('/fuzzers/edit', fuzzers.EditHandler),
    ('/fuzzers/log/<fuzzer_name>', fuzzers.LogHandler),
    ('/issue/<int:testcase_id>', issue_redirector.Handler),
    ('/jobs', jobs.Handler),
    ('/jobs/load', jobs.JsonHandler),
    ('/jobs/delete-job', jobs.DeleteJobHandler),
    ('/login', login.Handler),
    ('/logout', login.LogoutHandler),
    ('/report-bug', help_redirector.ReportBugHandler),
    ('/session-login', login.SessionLoginHandler),
    ('/testcase', show_testcase.DeprecatedHandler),
    ('/testcase-detail/<int:testcase_id>)', show_testcase.Handler),
    ('/testcase-detail/crash-stats', crash_stats_on_testcase.Handler),
    ('/testcase-detail/create-issue', create_issue.Handler),
    ('/testcase-detail/delete', delete.Handler),
    ('/testcase-detail/download-testcase', download_testcase.Handler),
    ('/testcase-detail/find-similar-issues', find_similar_issues.Handler),
    ('/testcase-detail/mark-fixed', mark_fixed.Handler),
    ('/testcase-detail/mark-security', mark_security.Handler),
    ('/testcase-detail/mark-unconfirmed', mark_unconfirmed.Handler),
    ('/testcase-detail/redo', redo.Handler),
    ('/testcase-detail/refresh', show_testcase.RefreshHandler),
    ('/testcase-detail/remove-duplicate', remove_duplicate.Handler),
    ('/testcase-detail/remove-issue', remove_issue.Handler),
    ('/testcase-detail/remove-group', remove_group.Handler),
    ('/testcase-detail/testcase-variants', testcase_variants.Handler),
    ('/testcase-detail/update-from-trunk', update_from_trunk.Handler),
    ('/testcase-detail/update-issue', update_issue.Handler),
    ('/testcases', testcase_list.Handler),
    ('/testcases/load', testcase_list.JsonHandler),
    ('/upload-testcase', upload_testcase.Handler),
    ('/upload-testcase/get-url-oauth', upload_testcase.UploadUrlHandlerOAuth),
    ('/upload-testcase/prepare', upload_testcase.PrepareUploadHandler),
    ('/upload-testcase/load', upload_testcase.JsonHandler),
    ('/upload-testcase/upload', upload_testcase.UploadHandler),
    ('/upload-testcase/upload-oauth', upload_testcase.UploadHandlerOAuth),
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
register_routes(app, cron_routes)

if __name__ == '__main__':
  app.run()
