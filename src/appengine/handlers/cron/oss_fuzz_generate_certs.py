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
"""Cron to generate certs for OSS-Fuzz workers."""

from google.cloud import ndb

from clusterfuzz._internal.base import untrusted
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.metrics import logs
from handlers import base_handler
from libs import handler


def generate_cert(project_name):
  """Generate a self signed cerficate."""
  # Defer imports to avoid issues on Python 2.
  from OpenSSL import crypto

  key = crypto.PKey()
  key.generate_key(crypto.TYPE_RSA, 2048)

  cert = crypto.X509()
  cert.get_subject().C = 'US'
  cert.get_subject().CN = '*' + untrusted.internal_network_domain()
  cert.get_subject().O = project_name
  cert.set_serial_number(9001)
  cert.set_notBefore(b'20000101000000Z')
  cert.set_notAfter(b'21000101000000Z')
  cert.set_issuer(cert.get_subject())
  cert.set_pubkey(key)
  cert.sign(key, 'sha256')

  cert_contents = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
  key_contents = crypto.dump_privatekey(crypto.FILETYPE_PEM, key)
  return cert_contents, key_contents


class Handler(base_handler.Handler):
  """Generate OSS-Fuzz certs."""

  @handler.cron()
  def get(self):
    """Handles a get request."""
    for project in data_types.OssFuzzProject.query():
      tls_cert_key = ndb.Key(data_types.WorkerTlsCert, project.name)
      if tls_cert_key.get():
        # Already generated.
        continue

      logs.log('Generating cert for %s.' % project.name)
      cert_contents, key_contents = generate_cert(project.name)

      tls_cert = data_types.WorkerTlsCert(
          id=project.name,
          cert_contents=cert_contents,
          key_contents=key_contents)
      tls_cert.put()
