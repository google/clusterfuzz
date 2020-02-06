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
"""NDB initialization."""

import contextlib
import functools
import threading
import sys

from google.cloud import ndb
import grpc

from base import utils

_ndb_client = None
_ndb_client_lock = threading.Lock()


def _client():
  """Get or initialize the NDB client."""
  global _ndb_client

  if not _ndb_client:
    with _ndb_client_lock:
      if not _ndb_client:
        _ndb_client = ndb.Client(project=utils.get_application_id())
        # TODO(ochang): Remove hack once migration to Python 3 is done.
        if sys.version_info.major == 2:
          # NDB doesn't like newstrs. On Python 3, keeping this breaks because
          # the bytes gets propgated down to a DNS resolution on
          # "b'datastore.googleapis.com'" which doesn't work.
          _ndb_client.host = utils.newstr_to_native_str(_ndb_client.host)


  return _ndb_client


@contextlib.contextmanager
def context():
  """Get the NDB context."""
  with _client().context() as ndb_context:
    from google.cloud.ndb import _retry
    # Add an additional code to retry on.
    if grpc.StatusCode.UNKNOWN not in _retry.TRANSIENT_CODES:
      _retry.TRANSIENT_CODES = _retry.TRANSIENT_CODES + (
          grpc.StatusCode.UNKNOWN,)

    # Disable NDB caching, as NDB on GCE VMs do not use memcache and therefore
    # can't invalidate the memcache cache.
    ndb_context.set_memcache_policy(False)

    # Disable the in-context cache, as it can use up a lot of memory for
    # longer running tasks such as cron jobs.
    ndb_context.set_cache_policy(False)

    yield ndb_context


def thread_wrapper(func):
  """Wrapper for thread targets to initialize an NDB context, since contexts are
  thread local."""

  @functools.wraps(func)
  def _wrapper(*args, **kwargs):
    with context():
      return func(*args, **kwargs)

  return _wrapper
