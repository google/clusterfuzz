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
import itertools
from typing import List
from typing import Tuple
import urllib.parse

import aiohttp

from clusterfuzz._internal.base import concurrency
from clusterfuzz._internal.base import utils
from clusterfuzz._internal.metrics import logs

BATCH_DELETE_URL = 'https://storage.googleapis.com/batch/storage/v1'

MULTIPART_BOUNDARY = 'multi-part-boundary'


def download_urls(urls_and_filepaths: List[Tuple[str, str]]) -> List[bool]:
  """Downloads multiple urls to filepaths in parallel and asynchronously.
  Tolerates errors. Returns a list of whether each download was successful."""
  utils.python_gc()
  if len(urls_and_filepaths) == 0:
    # Do this to avoid issues with the range function.
    return []
  batches = []

  batch_size = len(urls_and_filepaths) // concurrency.POOL_SIZE
  # Avoid issues with range when urls is less than _POOL_SIZE.
  batch_size = max(batch_size, len(urls_and_filepaths))

  for idx in range(0, len(urls_and_filepaths), batch_size):
    batch = urls_and_filepaths[idx:idx + batch_size]
    batches.append(batch)
  with concurrency.make_pool() as pool:
    return list(itertools.chain(*pool.map(_download_files, batches)))


def _download_files(urls_and_paths: List[Tuple[str, str]]) -> List[bool]:
  urls, paths = list(zip(*urls_and_paths))
  return asyncio.run(_async_download_files(list(urls), list(paths)))


async def _async_download_files(urls: List[str],
                                paths: List[str]) -> List[bool]:
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
  """Asynchronously downloads |url| and writes it to |path|."""
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
      async for chunk in response.content.iter_any():
        fp.write(chunk)


async def delete_batch(session, bucket, blobs, token):
  headers = {
      'Authorization': f'Bearer {token}',
      'Content-Type': f'multipart/mixed; boundary={MULTIPART_BOUNDARY}'
  }
  # Build multipart body
  body = []
  bucket = urllib.parse.quote(bucket, safe='')
  for idx, blob in enumerate(blobs):
    path = urllib.parse.quote(blob['name'], safe='')
    body.append(f'--{MULTIPART_BOUNDARY}\r\n'
                'Content-Type: application/http\r\n'
                f'Content-ID: <item{idx+1}>\r\n\r\n'
                f'DELETE /storage/v1/b/{bucket}/o/{path} HTTP/1.1\r\n'
                'Content-Length: 0\r\n\r\n'
                'Host: storage.googleapis.com\r\n')
  body.append(f'--{MULTIPART_BOUNDARY}--\r\n')
  body = '\r\n'.join(body)

  try:
    async with session.post(
        BATCH_DELETE_URL, headers=headers, data=body, timeout=20) as response:
      response.raise_for_status()

      print('response', response.text, response, dir(response))
      content_type = response.headers['Content-Type']
      if 'multipart/mixed' not in content_type:
        raise ValueError('Unexpected response format')
      return True

  except Exception as e:
    logs.error(f'Batch delete failed: {e}')
    return False
