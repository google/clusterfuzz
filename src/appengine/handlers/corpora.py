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
"""Manage corpora."""

from flask import request
from google.cloud import ndb

from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from handlers import base_handler
from libs import form
from libs import handler
from libs import helpers


class Handler(base_handler.Handler):
  """Manage data bundles."""

  @handler.unsupported_on_local_server
  @handler.get(handler.HTML)
  @handler.check_admin_access_if_oss_fuzz
  @handler.check_user_access(need_privileged_access=False)
  def get(self):
    """Handle a get request."""
    data_bundles = list(data_types.DataBundle.query().order(
        data_types.DataBundle.name))

    template_values = {
        'corpora': data_bundles,
        'fieldValues': {
            'csrfToken': form.generate_csrf_token(),
            'createUrl': '/corpora/create',
            'deleteUrl': '/corpora/delete',
        },
    }
    return self.render('corpora.html', template_values)


class CreateHandler(base_handler.Handler):
  """Create a corpus."""

  @handler.post(handler.FORM, handler.HTML)
  @handler.check_user_access(need_privileged_access=True)
  @handler.require_csrf_token
  def post(self):
    """Handle a post request."""
    name = request.get('name')
    if not name:
      raise helpers.EarlyExitException('Please give this corpus a name!', 400)

    if not data_types.DataBundle.VALID_NAME_REGEX.match(name):
      raise helpers.EarlyExitException(
          'Name can only contain letters, numbers, dashes and underscores.',
          400)

    user_email = helpers.get_user_email()
    bucket_name = data_handler.get_data_bundle_bucket_name(name)
    bucket_url = data_handler.get_data_bundle_bucket_url(name)
    is_local = not request.get('nfs', False)

    if not data_handler.create_data_bundle_bucket_and_iams(name, [user_email]):
      raise helpers.EarlyExitException(
          'Failed to create bucket %s.' % bucket_name, 400)

    data_bundle = data_types.DataBundle.query(
        data_types.DataBundle.name == name).get()

    if not data_bundle:
      data_bundle = data_types.DataBundle()
    data_bundle.name = name
    data_bundle.bucket_name = bucket_name
    data_bundle.is_local = is_local
    data_bundle.put()

    template_values = {
        'title':
            'Success',
        'message': (
            'Upload data to the corpus using: '
            'gsutil -d -m rsync -r <local_corpus_directory> %s' % bucket_url),
    }
    return self.render('message.html', template_values)


class DeleteHandler(base_handler.Handler):
  """Delete a corpus."""

  @handler.post(handler.FORM, handler.HTML)
  @handler.check_user_access(need_privileged_access=True)
  @handler.require_csrf_token
  def post(self):
    """Handle a post request."""
    key = helpers.get_integer_key(request)

    data_bundle = ndb.Key(data_types.DataBundle, key).get()
    if not data_bundle:
      raise helpers.EarlyExitException('Corpus not found', 400)

    affected_fuzzers = data_types.Fuzzer.query(
        data_types.Fuzzer.data_bundle_name == data_bundle.name)
    for fuzzer in affected_fuzzers:
      fuzzer.data_bundle_name = None
      fuzzer.put()

    data_bundle.key.delete()

    template_values = {
        'title':
            'Success',
        'message': ('Corpus %s is successfully deleted. '
                    'Redirecting back to corpora page...') % data_bundle.name,
        'redirect_url':
            '/corpora',
    }
    return self.render('message.html', template_values)
