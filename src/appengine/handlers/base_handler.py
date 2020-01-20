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
"""The superclass of all handlers."""
from builtins import object
from builtins import str
from future import standard_library
from future import utils as future_utils
standard_library.install_aliases()

import base64
import cgi
import datetime
import json
import logging
import os
import re
import sys
import traceback
import urllib.parse

from google.cloud import ndb
import jinja2
import webapp2

from base import utils
from config import db_config
from config import local_config
from datastore import ndb_init
from google_cloud_utils import storage
from libs import auth
from libs import form
from libs import helpers
from system import environment

# Pattern from
# https://github.com/google/closure-library/blob/
# 3037e09cc471bfe99cb8f0ee22d9366583a20c28/closure/goog/html/safeurl.js
_SAFE_URL_PATTERN = re.compile(
    r'^(?:(?:https?|mailto|ftp):|[^:/?#]*(?:[/?#]|$))', flags=re.IGNORECASE)


def add_jinja2_filter(name, fn):
  _JINJA_ENVIRONMENT.filters[name] = fn


class JsonEncoder(json.JSONEncoder):
  """Json encoder."""
  _EPOCH = datetime.datetime.utcfromtimestamp(0)

  def default(self, obj):  # pylint: disable=arguments-differ,method-hidden
    if isinstance(obj, ndb.Model):
      dict_obj = obj.to_dict()
      dict_obj['id'] = obj.key.id()
      return dict_obj
    elif isinstance(obj, datetime.datetime):
      return int((obj - self._EPOCH).total_seconds())
    elif hasattr(obj, 'to_dict'):
      return obj.to_dict()
    elif isinstance(obj, cgi.FieldStorage):
      return str(obj)
    else:
      raise Exception('Cannot serialise %s' % obj)


def format_time(dt):
  """Format datetime object for display."""
  return '{t.day} {t:%b} {t:%y} {t:%X} PDT'.format(t=dt)


def splitlines(text):
  """Split text into lines."""
  return text.splitlines()


def split_br(text):
  return re.split(r'\s*<br */>\s*', text, flags=re.IGNORECASE)


def encode_json(value):
  """Dump base64-encoded JSON string (to avoid XSS)."""
  return base64.b64encode(json.dumps(value, cls=JsonEncoder))


_JINJA_ENVIRONMENT = jinja2.Environment(
    loader=jinja2.FileSystemLoader(
        os.path.join(os.path.dirname(__file__), '..', 'templates')),
    extensions=['jinja2.ext.autoescape'],
    autoescape=True)
_MENU_ITEMS = []

add_jinja2_filter('json', encode_json)
add_jinja2_filter('format_time', format_time)
add_jinja2_filter('splitlines', splitlines)
add_jinja2_filter('split_br', split_br)
add_jinja2_filter('polymer_tag', lambda v: '{{%s}}' % v)


def add_menu(name, href):
  """Add menu item to the main navigation."""
  _MENU_ITEMS.append(_MenuItem(name, href))


def make_login_url(dest_url):
  """Make the switch account url."""
  return '/login?' + urllib.parse.urlencode({'dest': dest_url})


def make_logout_url(dest_url):
  """Make the switch account url."""
  return '/logout?' + urllib.parse.urlencode({
      'csrf_token': form.generate_csrf_token(),
      'dest': dest_url,
  })


def check_redirect_url(url):
  """Check redirect URL is safe."""
  if not _SAFE_URL_PATTERN.match(url):
    raise helpers.EarlyExitException('Invalid redirect.', 403)


class _MenuItem(object):
  """A menu item used for rendering an item in the main navigation."""

  def __init__(self, name, href):
    self.name = name
    self.href = href


class Handler(webapp2.RequestHandler):
  """A superclass for all handlers. It contains many convenient methods."""

  def is_cron(self):
    """Return true if the request is from a cron job."""
    return bool(self.request.headers.get('X-Appengine-Cron'))

  def render_forbidden(self, message):
    """Write HTML response for 403."""
    login_url = make_login_url(dest_url=self.request.url)
    user_email = helpers.get_user_email()
    if not user_email:
      self.redirect(login_url)
      return

    contact_string = db_config.get_value('contact_string')
    template_values = {
        'message': message,
        'user_email': helpers.get_user_email(),
        'login_url': login_url,
        'switch_account_url': login_url,
        'logout_url': make_logout_url(dest_url=self.request.url),
        'contact_string': contact_string,
    }
    self.render('error-403.html', template_values, 403)

  def _add_security_response_headers(self):
    """Add security-related headers to response."""
    self.response.headers['Strict-Transport-Security'] = (
        'max-age=2592000; includeSubdomains')
    self.response.headers['X-Content-Type-Options'] = 'nosniff'
    self.response.headers['X-Frame-Options'] = 'deny'

  def render(self, path, values=None, status=200):
    """Write HTML response."""
    if values is None:
      values = {}

    values['menu_items'] = _MENU_ITEMS
    values['is_oss_fuzz'] = utils.is_oss_fuzz()
    values['is_development'] = (
        environment.is_running_on_app_engine_development())
    values['is_logged_in'] = bool(helpers.get_user_email())

    # Only track analytics for non-admin users.
    values['ga_tracking_id'] = (
        local_config.GAEConfig().get('ga_tracking_id')
        if not auth.is_current_user_admin() else None)

    if values['is_logged_in']:
      values['switch_account_url'] = make_login_url(self.request.url)
      values['logout_url'] = make_logout_url(dest_url=self.request.url)

    template = _JINJA_ENVIRONMENT.get_template(path)

    self._add_security_response_headers()
    self.response.headers['Content-Type'] = 'text/html'
    self.response.out.write(template.render(values))
    self.response.set_status(status)

  def before_render_json(self, values, status):
    """A hook for modifying values before render_json."""

  def render_json(self, values, status=200):
    """Write JSON response."""
    self._add_security_response_headers()
    self.response.headers['Content-Type'] = 'application/json'
    self.before_render_json(values, status)
    self.response.out.write(json.dumps(values, cls=JsonEncoder))
    self.response.set_status(status)

  def handle_exception(self, exception, _):
    """Catch exception and format it properly."""
    try:

      status = 500
      values = {
          'message': exception.message,
          'email': helpers.get_user_email(),
          'traceDump': traceback.format_exc(),
          'status': status,
          'type': exception.__class__.__name__
      }
      if isinstance(exception, helpers.EarlyExitException):
        status = exception.status
        values = exception.to_dict()
      values['params'] = self.request.params.dict_of_lists()

      # 4XX is not our fault. Therefore, we hide the trace dump and log on
      # the INFO level.
      if 400 <= status <= 499:
        logging.info(json.dumps(values, cls=JsonEncoder))
        del values['traceDump']
      else:  # Other error codes should be logged with the EXCEPTION level.
        logging.exception(exception)

      if helpers.should_render_json(
          self.request.headers.get('accept', ''),
          self.response.headers.get('Content-Type')):
        self.render_json(values, status)
      else:
        if status == 403 or status == 401:
          self.render_forbidden(exception.message)
        else:
          self.render('error.html', values, status)
    except Exception:
      self.handle_exception_exception()

  def handle_exception_exception(self):
    """Catch exception in handle_exception and format it properly."""
    exception = sys.exc_info()[1]
    values = {'message': exception.message, 'traceDump': traceback.format_exc()}
    logging.exception(exception)
    if helpers.should_render_json(
        self.request.headers.get('accept', ''),
        self.response.headers.get('Content-Type')):
      self.render_json(values, 500)
    else:
      self.render('error.html', values, 500)

  def redirect(self, url, **kwargs):
    """Explicitly converts url to 'str', because webapp2.RequestHandler.redirect
    strongly requires 'str' but url might be an unicode string."""
    url = str(url)
    check_redirect_url(url)
    super(Handler, self).redirect(url, **kwargs)

  def dispatch(self):
    """Dispatch a request and postprocess."""
    # TODO(mbarbella): Delete this once the Python 3 migration is complete.
    @future_utils.as_native_str()
    def to_native_str(text):
      """Convert from future's newstr to a native str."""
      return text

    if environment.get_value('PY_UNITTESTS'):
      # Unit tests may not have NDB available.
      super(Handler, self).dispatch()
    else:
      with ndb_init.context():
        super(Handler, self).dispatch()

    # Replace header values with Python 2-style strings after dispatching. There
    # is an explicit type check against str that causes issues with newstr here.
    for key, value in self.response.headers.items():
      self.response.headers[key] = to_native_str(value)


class GcsUploadHandler(Handler):
  """A handler which uploads files to GCS."""

  def __init__(self, request, response):
    self.initialize(request, response)
    self.upload = None

  def get_upload(self):
    """Get uploads."""
    if self.upload:
      return self.upload

    upload_key = self.request.get('upload_key')
    if not upload_key:
      return None

    blob_info = storage.GcsBlobInfo.from_key(upload_key)
    if not blob_info:
      raise helpers.EarlyExitException('Failed to upload.', 500)

    self.upload = blob_info
    return self.upload
