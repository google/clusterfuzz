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
from __future__ import absolute_import

from webapp2_extras import routes
import webapp2

from base import utils
from config import local_config
from handlers import base_handler
from handlers import commit_range
from handlers import coverage_report
from handlers import domain_verifier
from handlers import fuzzer_stats
from handlers import gcs_redirector
from handlers import report_csp_failure
from handlers import revisions_info
from handlers import viewer
from handlers.cron import backup
from handlers.cron import batch_fuzzer_jobs
from handlers.cron import build_crash_stats
from handlers.cron import cleanup
from handlers.cron import corpus_backup
from handlers.cron import fuzz_strategy_selection
from handlers.cron import fuzzer_and_job_weights
from handlers.cron import fuzzer_coverage
from handlers.cron import load_bigquery_stats
from handlers.cron import manage_vms
from handlers.cron import ml_train
from handlers.cron import oss_fuzz_apply_ccs
from handlers.cron import oss_fuzz_build_status
from handlers.cron import oss_fuzz_generate_certs
from handlers.cron import predator_pull
from handlers.cron import project_setup
from handlers.cron import recurring_tasks
from handlers.cron import schedule_corpus_pruning
from handlers.cron import sync_admins
from handlers.cron import triage
from handlers.performance_report import (show as show_performance_report)
from handlers.reproduce_tool import get_config
from handlers.reproduce_tool import testcase_info
from metrics import logs

_is_chromium = utils.is_chromium()
_is_oss_fuzz = utils.is_oss_fuzz()


class _TrailingSlashRemover(webapp2.RequestHandler):

  def get(self, url):
    self.redirect(url)


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

if _is_chromium:
  base_handler.add_menu('Crashes by range', '/commit-range')

if not _is_oss_fuzz:
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
    ('/batch-fuzzer-jobs', batch_fuzzer_jobs.Handler),
    ('/build-crash-stats', build_crash_stats.Handler),
    ('/cleanup', cleanup.Handler),
    ('/corpus-backup/make-public', corpus_backup.MakePublicHandler),
    ('/fuzzer-coverage', fuzzer_coverage.Handler),
    ('/fuzzer-stats/cache', fuzzer_stats.RefreshCacheHandler),
    ('/fuzzer-stats/preload', fuzzer_stats.PreloadHandler),
    ('/fuzzer-and-job-weights', fuzzer_and_job_weights.Handler),
    ('/fuzz-strategy-selection', fuzz_strategy_selection.Handler),
    ('/load-bigquery-stats', load_bigquery_stats.Handler),
    ('/manage-vms', manage_vms.Handler),
    ('/oss-fuzz-apply-ccs', oss_fuzz_apply_ccs.Handler),
    ('/oss-fuzz-build-status', oss_fuzz_build_status.Handler),
    ('/oss-fuzz-generate-certs', oss_fuzz_generate_certs.Handler),
    ('/project-setup', project_setup.Handler),
    ('/predator-pull', predator_pull.Handler),
    ('/schedule-corpus-pruning', schedule_corpus_pruning.Handler),
    ('/schedule-impact-tasks', recurring_tasks.ImpactTasksScheduler),
    ('/schedule-ml-train-tasks', ml_train.Handler),
    ('/schedule-progression-tasks', recurring_tasks.ProgressionTasksScheduler),
    ('/schedule-upload-reports-tasks',
     recurring_tasks.UploadReportsTaskScheduler),
    ('/sync-admins', sync_admins.Handler),
    ('/triage', triage.Handler),
]

_ROUTES = [
    (r'(.*)/$', _TrailingSlashRemover),
    (r'/(google.+\.html)$', domain_verifier.Handler),
    ('/commit-range', commit_range.Handler),
    ('/commit-range/load', commit_range.JsonHandler),
    ('/coverage-report/([^/]+)/([^/]+)/([^/]+)(/.*)?', coverage_report.Handler),
    ('/fuzzer-stats/load', fuzzer_stats.LoadHandler),
    ('/fuzzer-stats/load-filters', fuzzer_stats.LoadFiltersHandler),
    ('/fuzzer-stats', fuzzer_stats.Handler),
    ('/fuzzer-stats/.*', fuzzer_stats.Handler),
    ('/gcs-redirect', gcs_redirector.Handler),
    ('/performance-report/(.+)/(.+)/(.+)', show_performance_report.Handler),
    ('/report-csp-failure', report_csp_failure.ReportCspFailureHandler),
    ('/reproduce-tool/get-config', get_config.Handler),
    ('/reproduce-tool/testcase-info', testcase_info.Handler),
    ('/revisions', revisions_info.Handler),
    ('/viewer', viewer.Handler),
]

logs.configure('appengine')

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
    _CRON_ROUTES + _DOMAIN_ROUTES + _ROUTES, debug=False)
