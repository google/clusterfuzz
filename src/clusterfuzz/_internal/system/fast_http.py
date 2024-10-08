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
"""Tools for fast HTTP operations."""
import asyncio
from concurrent import futures
import contextlib
import itertools
import multiprocessing
from typing import Optional
from typing import Tuple

import aiohttp

from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment

_POOL_SIZE = multiprocessing.cpu_count()


@contextlib.contextmanager
def _pool(pool_size=_POOL_SIZE):
  # TOOD(metzman): Move the multiprocessing code from _pool() in storage.py
  # over.
  # Don't use processes on Windows and unittests to avoid hangs.
  if (environment.get_value('PY_UNITTESTS') or
      environment.platform() == 'WINDOWS'):
    yield futures.ThreadPoolExecutor(pool_size)
  else:
    yield futures.ProcessPoolExecutor(pool_size)


def download_urls(urls: list[str], filepaths: list[str]) -> list[bool]:
  """Downloads multiple |urls| to |filepaths| in parallel and
  asynchronously. Tolerates errors. Returns a list of whether each
  download was successful."""
  assert len(urls) == len(filepaths)
  if len(urls) == 0:
    # Do this to avoid issues with the range function.
    return []
  url_batches = []
  url_batch_size = len(urls) // _POOL_SIZE

  # Avoid issues with range when urls is less than _POOL_SIZE.
  url_batch_size = max(url_batch_size, len(urls))

  urls_and_filepaths = list(zip(urls, filepaths))
  for idx in range(0, len(urls), url_batch_size):
    url_batch = urls_and_filepaths[idx:idx + url_batch_size]
    url_batches.append(url_batch)
  with _pool() as pool:
    return list(itertools.chain(*pool.map(_download_files, url_batches)))


def _download_files(urls_and_paths: list[Tuple[str, str]]) -> list[bool]:
  urls, paths = list(zip(*urls_and_paths))
  return asyncio.run(_async_download_files(list(urls), list(paths)))


async def _async_download_files(urls: list[str],
                                paths: list[str]) -> list[bool]:
  async with aiohttp.ClientSession() as session:
    tasks = [
        asyncio.create_task(_error_tolerant_download_file(session, url, path))
        for url, path in zip(urls, paths)
    ]
    return await asyncio.gather(*tasks)


async def _error_tolerant_download_file(session: aiohttp.ClientSession,
                                        url: str, path: str) -> bool:
  try:
    await _async_download_file(session, url, path)
    return True
  except:
    logs.warning(f'Failed to download {url}.')
    return False


async def _async_download_file(session: aiohttp.ClientSession, url: str,
                               path: str):
  async with session.get(url) as response:
    if response.status != 200:
      print(response.status, url)
      raise aiohttp.ClientResponseError(
          response.request_info,
          response.history,
          message=f'Failed to download. Code: {response.status}.',
          status=response.status,
      )
    with open(path, 'wb') as fp:
      while True:
        chunk = await response.content.read(1024)
        if not chunk:
          return
        fp.write(chunk)
