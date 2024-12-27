# Copyright 2024 Google LLC
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
"""Tools for concurrency/parallelism."""
from concurrent import futures
import contextlib
import multiprocessing

from clusterfuzz._internal.system import environment

POOL_SIZE = multiprocessing.cpu_count()


@contextlib.contextmanager
def make_pool(pool_size=POOL_SIZE, max_pool_size=None):
  """Returns a pool that can (usually) execute tasks concurrently."""
  if max_pool_size is not None:
    pool_size = min(pool_size, max_pool_size)

  # Don't use processes on Windows and unittests to avoid hangs.
  if (environment.get_value('PY_UNITTESTS') or
      environment.platform() == 'WINDOWS'):
    yield futures.ThreadPoolExecutor(pool_size)
  else:
    yield futures.ProcessPoolExecutor(pool_size)


# TODO(metzman): Find out if batching makes things even faster.
