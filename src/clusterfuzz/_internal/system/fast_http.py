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
"""Tools for fast HTTP operations."""
import asyncio
import itertools
import multiprocessing
from typing import List

import aiohttp


def download_urls(pool: multiprocessing.Pool, urls: List[str],
                  filepaths: List[str], pool_size: int) -> str:
  """Downloads multiple |urls| to |filepaths| in parallel (using |pool|) and
  asynchronously. Tolerates errors. Returns a list of whether each download was
  successful."""
  # TOOD(metzman): Move the multiprocessing code over from storage.
  assert len(urls) == len(filepaths)
  chunks = []
  chunk_size = len(urls) // pool_size
  urls_and_filepaths = list(zip(urls, filepaths))
  for idx in range(0, len(all_urls), chunk_size):
    chunk = urls_and_file_paths[idx:idx + chunk_size]
    chunks.append(chunk)
  return list(itertools.chain(pool.starmap(download_files, chunks)))


def _download_files(urls: List[str], paths: List[str]) -> List[bool]:
  return asyncio.run(_async_download_files(urls, paths))


async def _async_download_files(urls: List[str],
                                paths: List[str]) -> List[bool]:
  async with aiohttp.ClientSession() as session:
    tasks = [
        asyncio.create_task(
            _error_tolerant_download_file(session, url, filename))
        for url, path in zip(urls, paths)
    ]
    return await asyncio.gather(*tasks)


def _error_tolerant_download_file(session: aiohttp.ClientSession, url: str,
                                  path: str) -> bool:
  try:
    return _async_download_file(session, url, path)
  except:
    return False


async def _async_download_file(session: aiohttp.ClientSession, url: str,
                               path: str) -> bool:
  async with session.get(url) as response, open(path, 'wb') as fp:
    while True:
      chunk = await response.content.read(1024)
      if not chunk:
        return True
      fp.write(chunk)
