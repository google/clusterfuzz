# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""This application demonstrates how to construct a Signed URL for objects in
   Google Cloud Storage.

Originally from
https://github.com/GoogleCloudPlatform/python-docs-samples/blob/HEAD/storage/signed_urls/generate_signed_urls.py
"""

import binascii
import collections
import datetime
import hashlib
import urllib.parse

import six


def generate_signed_url(
    google_credentials,
    bucket_name,
    object_name,
    subresource=None,
    expiration=604800,
    http_method='GET',
    query_parameters=None,
    headers=None,
):
  """Signs a URL locally."""
  if expiration > 604800:
    raise ValueError(
        'Expiration time can\'t be longer than 604800 seconds (7 days).')

  escaped_object_name = urllib.parse.quote(
      six.ensure_binary(object_name), safe=b'/~')
  canonical_uri = f'/{escaped_object_name}'

  datetime_now = datetime.datetime.now(tz=datetime.timezone.utc)
  request_timestamp = datetime_now.strftime('%Y%m%dT%H%M%SZ')
  datestamp = datetime_now.strftime('%Y%m%d')

  client_email = google_credentials.service_account_email
  credential_scope = f'{datestamp}/auto/storage/goog4_request'
  credential = f'{client_email}/{credential_scope}'

  if headers is None:
    headers = {}
  host = f'{bucket_name}.storage.googleapis.com'
  headers['host'] = host

  canonical_headers = ''
  ordered_headers = collections.OrderedDict(sorted(headers.items()))
  for k, v in ordered_headers.items():
    lower_k = str(k).lower()
    strip_v = str(v).lower()
    canonical_headers += f'{lower_k}:{strip_v}\n'

  signed_headers = ''
  for k, _ in ordered_headers.items():
    lower_k = str(k).lower()
    signed_headers += f'{lower_k};'
  signed_headers = signed_headers[:-1]  # remove trailing ';'.

  if query_parameters is None:
    query_parameters = {}
  query_parameters['X-Goog-Algorithm'] = 'GOOG4-RSA-SHA256'
  query_parameters['X-Goog-Credential'] = credential
  query_parameters['X-Goog-Date'] = request_timestamp
  query_parameters['X-Goog-Expires'] = expiration
  query_parameters['X-Goog-SignedHeaders'] = signed_headers
  if subresource:
    query_parameters[subresource] = ''

  canonical_query_string = ''
  ordered_query_parameters = collections.OrderedDict(
      sorted(query_parameters.items()))
  for k, v in ordered_query_parameters.items():
    encoded_k = urllib.parse.quote(str(k), safe='')
    encoded_v = urllib.parse.quote(str(v), safe='')
    canonical_query_string += f'{encoded_k}={encoded_v}&'
  canonical_query_string = canonical_query_string[:-1]  # remove trailing '&'.

  canonical_request = '\n'.join([
      http_method,
      canonical_uri,
      canonical_query_string,
      canonical_headers,
      signed_headers,
      'UNSIGNED-PAYLOAD',
  ])

  canonical_request_hash = hashlib.sha256(
      canonical_request.encode()).hexdigest()

  string_to_sign = '\n'.join([
      'GOOG4-RSA-SHA256',
      request_timestamp,
      credential_scope,
      canonical_request_hash,
  ])

  # signer.sign() signs using RSA-SHA256 with PKCS1v15 padding
  signature = binascii.hexlify(
      google_credentials.signer.sign(string_to_sign)).decode()

  scheme_and_host = f'https://{host}'
  signed_url = '{}{}?{}&x-goog-signature={}'.format(
      scheme_and_host, canonical_uri, canonical_query_string, signature)

  return signed_url
