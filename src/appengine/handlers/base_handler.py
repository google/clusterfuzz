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
"""The superclass of all handlers."""

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

from flask import redirect as flask_redirect
from flask import request
from flask import Response
from flask.views import MethodView
from google.cloud import ndb
import jinja2

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.config import db_config
from clusterfuzz._internal.config import local_config
from clusterfuzz._internal.google_cloud_utils import storage
from clusterfuzz._internal.system import environment
from libs import auth
from libs import form
from libs import helpers

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
    if isinstance(obj, datetime.datetime):
      return int((obj - self._EPOCH).total_seconds())
    if hasattr(obj, 'to_dict'):
      return obj.to_dict()
    if isinstance(obj, cgi.FieldStorage):
      return str(obj)
    if isinstance(obj, bytes):
      return obj.decode('utf-8')

    return json.JSONEncoder.default(self, obj)


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
  return base64.b64encode(json.dumps(
      value, cls=JsonEncoder).encode('utf-8')).decode('utf-8')


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


class Handler(MethodView):
  """A superclass for all handlers. It contains many convenient methods."""

  def is_cron(self):
    """Return true if the request is from a cron job."""
    return bool(request.headers.get('X-Appengine-Cron'))

  def should_render_json(self):
    return (self.is_json or
            'application/json' in request.headers.get('accept', ''))

  def render_forbidden(self, message):
    """Write HTML response for 403."""
    login_url = make_login_url(dest_url=request.url)
    user_email = helpers.get_user_email()
    if not user_email:
      return self.redirect(login_url)

    contact_string = db_config.get_value('contact_string')
    template_values = {
        'message': message,
        'user_email': helpers.get_user_email(),
        'login_url': login_url,
        'switch_account_url': login_url,
        'logout_url': make_logout_url(dest_url=request.url),
        'contact_string': contact_string,
    }
    return self.render('error-403.html', template_values, 403)

  def _add_security_response_headers(self, response):
    """Add security-related headers to response."""
    response.headers['Strict-Transport-Security'] = (
        'max-age=2592000; includeSubdomains')
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'deny'
    return response

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
      values['switch_account_url'] = make_login_url(request.url)
      values['logout_url'] = make_logout_url(dest_url=request.url)

    template = _JINJA_ENVIRONMENT.get_template(path)

    response = Response()
    response = self._add_security_response_headers(response)
    response.headers['Content-Type'] = 'text/html'
    response.data = template.render(values)
    response.status_code = status
    return response

  # pylint: disable=unused-argument
  def before_render_json(self, values, status):
    """A hook for modifying values before render_json."""

  def render_json(self, values, status=200):
    """Write JSON response."""
    response = Response()
    response = self._add_security_response_headers(response)
    response.headers['Content-Type'] = 'application/json'
    self.before_render_json(values, status)
    response.data = json.dumps(values, cls=JsonEncoder)
    response.status_code = status
    return response

  def handle_exception(self, exception):
    """Catch exception and format it properly."""
    try:
      status = 500
      values = {
          'message': str(exception),
          'email': helpers.get_user_email(),
          'traceDump': traceback.format_exc(),
          'status': status,
          'type': exception.__class__.__name__
      }
      if isinstance(exception, helpers.EarlyExitException):
        status = exception.status
        values = exception.to_dict()

      # 4XX is not our fault. Therefore, we hide the trace dump and log on
      # the INFO level.
      if 400 <= status <= 499:
        logging.info(json.dumps(values, cls=JsonEncoder))
        del values['traceDump']
      else:  # Other error codes should be logged with the EXCEPTION level.
        logging.exception(exception)

      if self.should_render_json():
        return self.render_json(values, status)
      if status in (403, 401):
        return self.render_forbidden(str(exception))
      return self.render('error.html', values, status)
    except Exception:
      self.handle_exception_exception()

    return None

  def handle_exception_exception(self):
    """Catch exception in handle_exception and format it properly."""
    exception = sys.exc_info()[1]
    values = {'message': str(exception), 'traceDump': traceback.format_exc()}
    logging.exception(exception)
    if self.should_render_json():
      return self.render_json(values, 500)
    return self.render('error.html', values, 500)

  def redirect(self, url, **kwargs):
    """Check vaid url and redirect to it, if valid."""
    url = str(url)
    check_redirect_url(url)
    return flask_redirect(url, **kwargs)

  def dispatch_request(self, *args, **kwargs):
    """Dispatch a request and postprocess."""
    self.is_json = False
    try:
      return super(Handler, self).dispatch_request(*args, **kwargs)
    except Exception as exception:
      return self.handle_exception(exception)


class GcsUploadHandler(Handler):
  """A handler which uploads files to GCS."""

  def dispatch_request(self, *args, **kwargs):
    """Dispatch a request and postprocess."""
    self.upload = None
    return super().dispatch_request(*args, **kwargs)

  def get_upload(self):
    """Get uploads."""
    if self.upload:
      return self.upload

    upload_key = request.get('upload_key')
    if not upload_key:
      return None

    blob_info = storage.GcsBlobInfo.from_key(upload_key)
    if not blob_info:
      raise helpers.EarlyExitException('Failed to upload.', 500)

    self.upload = blob_info
    return self.upload
