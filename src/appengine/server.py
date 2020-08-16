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
from handlers import domain_verifier
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

_ROUTES = [
    (r'(.*)/$', _TrailingSlashRemover),
    (r'/(google.+\.html)$', domain_verifier.Handler),
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
    _DOMAIN_ROUTES + _ROUTES, debug=False)
