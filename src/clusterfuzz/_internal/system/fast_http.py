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
import google.api_core.exceptions

from clusterfuzz._internal.base import retry
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
      raise aiohttp.ClientResponseError(
          response.request_info,
          response.history,
          message=f'Failed to download. Code: {response.status}.',
          status=response.status,
      )
    with open(path, 'wb') as fp:
      async for chunk in response.content.iter_any():
        fp.write(chunk)



async def delete_blob_async(bucket_name, blob_name, session, auth_token):
  blob_name = urllib.parse.quote(blob_name, safe='')
  url = f'https://storage.googleapis.com/storage/v1/b/{bucket_name}/o/{blob_name}'
  headers = {'Authorization': f'Bearer {auth_token}',}
    
  try:    
    async with session.delete(url, headers=headers) as response:
      if response.status != 204:
        response_text = await response.text()
        logs.error(f'Failed to delete blob {blob_name}. Status code: {response.status} {response_text}')
  except Exception as e:
    logs.error(f'Error deleting {blob_name}: {e}')

    
async def list_blobs_async(bucket_name, path, auth_token):
  async with aiohttp.ClientSession() as session:
    url = f'https://storage.googleapis.com/storage/v1/b/{bucket_name}/o'
    params = {
      'prefix': path,
      'delimiter': '/',
      'fields': 'items(name,size,updated),nextPageToken'  # Need token and save space in response.
    }
    while True:
      async with session.get(url, headers={'Authorization': f'Bearer {auth_token}'}, params=params) as response:
        if response.status == 200:
          data = await response.json()
          items = data.get('items', [])
          for blob in items:
            yield {
              'size': int(blob['size']),
              'updated': blob['updated'],
              'name': blob['name'],
            }

          next_page_token = data.get('nextPageToken')
          if not next_page_token:
            break
          params['pageToken'] = next_page_token
        else:
          logs.error(f'No blobsm, tatus code: {response.status}')
          break        
