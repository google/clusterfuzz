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
"""server.py initialises the appengine server for ClusterFuzz."""
import urllib
import webapp2
from webapp2_extras import routes

from base import utils
from config import local_config
from handlers import base_handler
from handlers import bots
from handlers import commit_range
from handlers import configuration
from handlers import corpora
from handlers import coverage_report
from handlers import crash_stats
from handlers import domain_verifier
from handlers import download
from handlers import fuzzer_stats
from handlers import fuzzers
from handlers import gcs_redirector
from handlers import help_redirector
from handlers import home
from handlers import issue_redirector
from handlers import jobs
from handlers import parse_stacktrace
from handlers import revisions_info
from handlers import testcase_list
from handlers import upload_testcase
from handlers import viewer
from handlers.cron import backup
from handlers.cron import build_crash_stats
from handlers.cron import cleanup
from handlers.cron import corpus_backup
from handlers.cron import fuzzer_weights
from handlers.cron import load_bigquery_stats
from handlers.cron import manage_vms
from handlers.cron import ml_train
from handlers.cron import oss_fuzz_apply_ccs
from handlers.cron import oss_fuzz_build_status
from handlers.cron import oss_fuzz_setup
from handlers.cron import predator_pull
from handlers.cron import recurring_tasks
from handlers.cron import schedule_corpus_pruning
from handlers.cron import triage
from handlers.performance_report import (show as show_performance_report)
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
from handlers.testcase_detail import update_from_trunk
from handlers.testcase_detail import update_issue


class _TrailingSlashRemover(webapp2.RequestHandler):

  def get(self, url):
    self.redirect(url)


# TODO(aarya): Remove after all /v2 links are deprecated.
class _V2Remover(webapp2.RequestHandler):

  def get(self, url):
    self.redirect('/%s?%s' % (url, urllib.urlencode(self.request.params)))


def redirect_to(to_domain):
  """Create a redirect handler to a domain."""

  class RedirectHandler(webapp2.RequestHandler):
    """Handler to redirect to domain."""

    def get(self, _):
      self.redirect(
          'https://' + to_domain + self.request.path_qs, permanent=True)

  return RedirectHandler


# Add item to the navigation menu. Order is important.
base_handler.add_menu('Testcases', '/testcases')
base_handler.add_menu('Fuzzer Statistics', '/fuzzer-stats')
base_handler.add_menu('Crash Statistics', '/crash-stats')
base_handler.add_menu('Upload Testcase', '/upload-testcase')

if utils.is_chromium():
  base_handler.add_menu('Crashes by range', '/commit-range')

if not utils.is_oss_fuzz():
  base_handler.add_menu('Fuzzers', '/fuzzers')
  base_handler.add_menu('Corpora', '/corpora')
  base_handler.add_menu('Bots', '/bots')

base_handler.add_menu('Jobs', '/jobs')
base_handler.add_menu('Configuration', '/configuration')
base_handler.add_menu('Report Bug', '/report-bug')
base_handler.add_menu('Documentation', '/docs')

# We need to separate routes for cron to avoid redirection.
_CRON_ROUTES = [
    ('/backup', backup.Handler),
    ('/build-crash-stats', build_crash_stats.Handler),
    ('/cleanup', cleanup.Handler),
    ('/corpus-backup/make-public', corpus_backup.MakePublicHandler),
    ('/fuzzer-stats/cache', fuzzer_stats.RefreshCacheHandler),
    ('/fuzzer-stats/preload', fuzzer_stats.PreloadHandler),
    ('/fuzzer-weights', fuzzer_weights.Handler),
    ('/home-cache', home.RefreshCacheHandler),
    ('/load-bigquery-stats', load_bigquery_stats.Handler),
    ('/manage-vms', manage_vms.Handler),
    ('/oss-fuzz-apply-ccs', oss_fuzz_apply_ccs.Handler),
    ('/oss-fuzz-build-status', oss_fuzz_build_status.Handler),
    ('/oss-fuzz-setup', oss_fuzz_setup.Handler),
    ('/predator-pull', predator_pull.Handler),
    ('/schedule-corpus-pruning', schedule_corpus_pruning.Handler),
    ('/schedule-impact-tasks', recurring_tasks.ImpactTasksScheduler),
    ('/schedule-ml-train-tasks', ml_train.Handler),
    ('/schedule-progression-tasks', recurring_tasks.ProgressionTasksScheduler),
    ('/schedule-upload-reports-tasks',
     recurring_tasks.UploadReportsTaskScheduler),
    ('/testcases/cache', testcase_list.CacheHandler),
    ('/triage', triage.Handler),
]

_ROUTES = [
    ('/', home.Handler),
    ('(.*)/$', _TrailingSlashRemover),
    ('/v2/(.*)', _V2Remover),
    (r'/(google.+\.html)$', domain_verifier.Handler),
    ('/bots', bots.Handler),
    ('/bots/dead', bots.DeadBotsHandler),
    ('/commit-range', commit_range.Handler),
    ('/commit-range/load', commit_range.JsonHandler),
    ('/configuration', configuration.Handler),
    ('/add-external-user-permission', configuration.AddExternalUserPermission),
    ('/delete-external-user-permission',
     configuration.DeleteExternalUserPermission),
    ('/coverage-report/([^/]+)/([^/]+)/([^/]+)(/.*)?', coverage_report.Handler),
    ('/crash-stats/load', crash_stats.JsonHandler),
    ('/crash-stats', crash_stats.Handler),
    ('/corpora', corpora.Handler),
    ('/corpora/create', corpora.CreateHandler),
    ('/corpora/delete', corpora.DeleteHandler),
    ('/docs', help_redirector.DocumentationHandler),
    ('/download/?([^/]+)?', download.Handler),
    ('/fuzzers', fuzzers.Handler),
    ('/fuzzers/create', fuzzers.CreateHandler),
    ('/fuzzers/delete', fuzzers.DeleteHandler),
    ('/fuzzers/edit', fuzzers.EditHandler),
    ('/fuzzers/log/([^/]+)', fuzzers.LogHandler),
    ('/fuzzer-stats/load', fuzzer_stats.LoadHandler),
    ('/fuzzer-stats', fuzzer_stats.Handler),
    ('/fuzzer-stats/.*', fuzzer_stats.Handler),
    ('/gcs-redirect', gcs_redirector.Handler),
    ('/issue/([0-9]+)/(.+)', issue_redirector.Handler),
    ('/jobs', jobs.Handler),
    ('/jobs/.*', jobs.Handler),
    ('/update-job', jobs.UpdateJob),
    ('/update-job-template', jobs.UpdateJobTemplate),
    ('/parse_stacktrace', parse_stacktrace.Handler),
    ('/performance-report/(.+)/(.+)/(.+)', show_performance_report.Handler),
    ('/testcase', show_testcase.DeprecatedHandler),
    ('/testcase-detail/([0-9]+)', show_testcase.Handler),
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
    ('/revisions', revisions_info.Handler),
    ('/report-bug', help_redirector.ReportBugHandler),
    ('/viewer', viewer.Handler),
]

config = local_config.GAEConfig()
main_domain = config.get('domains.main')
redirect_domains = config.get('domains.redirects')
_DOMAIN_ROUTES = []
if main_domain and redirect_domains:
  for redirect_domain in redirect_domains:
    _DOMAIN_ROUTES.append(
        routes.DomainRoute(redirect_domain, [
            webapp2.Route('<:.*>', redirect_to(main_domain)),
        ]))

app = webapp2.WSGIApplication(
    _CRON_ROUTES + _DOMAIN_ROUTES + _ROUTES, debug=True)
