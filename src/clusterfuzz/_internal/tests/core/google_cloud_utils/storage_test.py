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
"""Storage tests."""
import datetime
import os
import unittest
from unittest import mock
import urllib.parse

from pyfakefs import fake_filesystem_unittest

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.google_cloud_utils import storage
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from clusterfuzz._internal.tests.test_libs import test_utils

_SIGNED_QUERY = '?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Signature=secret123'
_FLAT_BUNDLE_A_GCS_URL = 'gs://bundle-a.example.com'
_FLAT_BUNDLE_B_GCS_URL = 'gs://bundle-b.example.com'
_NESTED_BUNDLE_GCS_URL = 'gs://example.com'


class LifecycleConfigTest(unittest.TestCase):
  """Test lifecycle config generation."""

  def test_empty(self):
    """Test generation of an empty config."""
    config = storage.generate_life_cycle_config('')
    expected_config = {
        'rule': [{
            'action': {
                'type': '',
            },
            'condition': {},
        }],
    }
    self.assertEqual(config, expected_config)

  def test_delete_with_age(self):
    """Test generation of a config for deletion with age condition."""
    config = storage.generate_life_cycle_config('Delete', age=7)
    expected_config = {
        'rule': [{
            'action': {
                'type': 'Delete',
            },
            'condition': {
                'age': 7,
            },
        }],
    }
    self.assertEqual(config, expected_config)

  def test_delete_with_age_and_new_versions(self):
    """Test generation of a config for deletion with age and numNewerVersions
    condition."""
    config = storage.generate_life_cycle_config(
        'Delete', age=30, num_newer_versions=10)
    expected_config = {
        'rule': [{
            'action': {
                'type': 'Delete',
            },
            'condition': {
                'age': 30,
                'numNewerVersions': 10,
            },
        }],
    }
    self.assertEqual(config, expected_config)


class FileSystemProviderTests(fake_filesystem_unittest.TestCase):
  """Tests for FileSystemProvider."""

  def setUp(self):
    self.provider = storage.FileSystemProvider('/local')
    test_utils.set_up_pyfakefs(self)

  def test_create_bucket(self):
    """Test create_bucket."""
    self.provider.create_bucket('test-bucket', None, None, None)
    self.assertTrue(os.path.isdir('/local/test-bucket'))

  def test_get_bucket(self):
    """Test get_bucket."""
    self.fs.create_dir('/local/test-bucket')
    self.assertDictEqual({
        'name': 'test-bucket',
    }, self.provider.get_bucket('test-bucket'))

  def test_list_blobs(self):
    """Test list_blobs."""
    mtime = datetime.datetime(2019, 1, 1)
    mtime_seconds = utils.utc_datetime_to_timestamp(mtime)

    self.fs.create_file(
        '/local/test-bucket/objects/a', st_size=11).st_mtime = mtime_seconds
    self.fs.create_file(
        '/local/test-bucket/objects/b/c', st_size=22).st_mtime = mtime_seconds
    self.fs.create_file(
        '/local/test-bucket/objects/b/d/e', st_size=33).st_mtime = mtime_seconds
    self.fs.create_file(
        '/local/test-bucket/objects/f', st_size=44).st_mtime = mtime_seconds
    self.fs.create_file(
        '/local/test-bucket/metadata/b/c',
        contents='{"key":"value"}').st_mtime = mtime_seconds

    result = list(self.provider.list_blobs('gs://test-bucket'))
    self.assertCountEqual([{
        'bucket': 'test-bucket',
        'name': 'a',
        'updated': mtime,
        'size': 11,
        'metadata': {}
    }, {
        'bucket': 'test-bucket',
        'name': 'f',
        'updated': mtime,
        'size': 44,
        'metadata': {}
    }, {
        'bucket': 'test-bucket',
        'name': 'b/c',
        'updated': mtime,
        'size': 22,
        'metadata': {
            'key': 'value'
        }
    }, {
        'bucket': 'test-bucket',
        'name': 'b/d/e',
        'updated': mtime,
        'size': 33,
        'metadata': {}
    }], result)

    result = list(self.provider.list_blobs('gs://test-bucket/b'))
    self.assertCountEqual([{
        'bucket': 'test-bucket',
        'name': 'b/c',
        'updated': mtime,
        'size': 22,
        'metadata': {
            'key': 'value'
        }
    }, {
        'bucket': 'test-bucket',
        'name': 'b/d/e',
        'updated': mtime,
        'size': 33,
        'metadata': {}
    }], result)

    result = list(self.provider.list_blobs('gs://test-bucket/b/d'))
    self.assertCountEqual([{
        'bucket': 'test-bucket',
        'name': 'b/d/e',
        'updated': mtime,
        'size': 33,
        'metadata': {}
    }], result)

    result = list(
        self.provider.list_blobs('gs://test-bucket/', recursive=False))
    self.assertCountEqual([{
        'bucket': 'test-bucket',
        'name': 'a',
        'updated': mtime,
        'size': 11,
        'metadata': {}
    }, {
        'bucket': 'test-bucket',
        'name': 'f',
        'updated': mtime,
        'size': 44,
        'metadata': {}
    }, {
        'bucket': 'test-bucket',
        'name': 'b',
    }], result)

  def test_copy_file_from(self):
    """Test copy_file_from."""
    self.fs.create_file('/local/test-bucket/objects/a', contents='a')
    self.provider.copy_file_from('gs://test-bucket/a', '/a')
    with open('/a') as f:
      self.assertEqual('a', f.read())

  def test_copy_file_to(self):
    """Test copy_file_to."""
    self.fs.create_file('/a', contents='a')
    self.fs.create_dir('/local/test-bucket')

    self.provider.copy_file_to(
        '/a', 'gs://test-bucket/subdir/a', metadata={'key': 'value'})
    with open('/local/test-bucket/objects/subdir/a') as f:
      self.assertEqual('a', f.read())

    with open('/local/test-bucket/metadata/subdir/a') as f:
      self.assertEqual('{"key": "value"}', f.read())

  def test_copy_blob(self):
    """Test copy_blob."""
    self.fs.create_file('/local/test-bucket/objects/a', contents='a')

    self.provider.copy_blob('gs://test-bucket/a', 'gs://test-bucket/copy/a')
    with open('/local/test-bucket/objects/copy/a') as f:
      self.assertEqual('a', f.read())

  def test_read_data(self):
    """Test copy_blob."""
    self.fs.create_file('/local/test-bucket/objects/a', contents='a')
    self.assertEqual(b'a', self.provider.read_data('gs://test-bucket/a'))

  def test_write_data(self):
    """Test copy_blob."""
    self.fs.create_dir('/local/test-bucket')
    self.provider.write_data(
        b'a', 'gs://test-bucket/subdir/a', metadata={'key': 'value'})
    with open('/local/test-bucket/objects/subdir/a') as f:
      self.assertEqual('a', f.read())

    with open('/local/test-bucket/metadata/subdir/a') as f:
      self.assertEqual('{"key": "value"}', f.read())

    self.provider.write_data('b', 'gs://test-bucket/subdir/b')
    with open('/local/test-bucket/objects/subdir/b') as f:
      self.assertEqual('b', f.read())

  def test_get(self):
    """Test get."""
    mtime = datetime.datetime(2019, 1, 1)
    mtime_seconds = utils.utc_datetime_to_timestamp(mtime)

    self.fs.create_file(
        '/local/test-bucket/objects/a', contents='a').st_mtime = mtime_seconds
    self.fs.create_file(
        '/local/test-bucket/metadata/a', contents='{"key": "value"}')

    self.assertDictEqual({
        'bucket': 'test-bucket',
        'name': 'a',
        'size': 1,
        'updated': mtime,
        'metadata': {
            'key': 'value'
        },
    }, self.provider.get('gs://test-bucket/a'))

  def test_delete(self):
    """Test get."""
    self.fs.create_file('/local/test-bucket/objects/a', contents='a')
    self.fs.create_file(
        '/local/test-bucket/metadata/a', contents='{"key": "value"}')

    self.provider.delete('gs://test-bucket/a')
    self.assertFalse(os.path.exists('/local/test-bucket/objects/a'))
    self.assertFalse(os.path.exists('/local/test-bucket/metadata/a'))

  def test_sign_upload_url(self):
    """Tests sign_upload_url."""
    url = 'gs://test-bucket/upload'
    return self.assertEqual(self.provider.sign_upload_url(url), url)

  def test_sign_download_url(self):
    """Tests sign_download_url."""
    url = 'gs://test-bucket/download'
    return self.assertEqual(self.provider.sign_download_url(url), url)

  def test_download_signed_url(self):
    """Tests download_signed_url."""
    contents = b'aa'
    self.fs.create_file('/local/test-bucket/objects/a', contents=contents)
    return self.assertEqual(
        self.provider.download_signed_url('gs://test-bucket/a'), contents)

  def test_upload_signed_url(self):
    """Tests upload_signed_url."""
    contents = b'aa'
    self.provider.create_bucket('test-bucket', None, None, None)
    self.provider.upload_signed_url(contents, 'gs://test-bucket/a')
    with open('/local/test-bucket/objects/a', 'rb') as fp:
      return self.assertEqual(fp.read(), contents)


class StrToBytesTest(unittest.TestCase):

  def test_str(self):
    self.assertEqual(storage.str_to_bytes('\x00A'), b'\x00A')

  def test_bytes(self):
    self.assertEqual(storage.str_to_bytes(b'\x00A'), b'\x00A')


class SignedUrlDownloadTest(fake_filesystem_unittest.TestCase):
  """Tests for downloading signed URLs to local files."""

  def setUp(self):
    test_utils.set_up_pyfakefs(self)
    self.fs.create_dir('/bundle')
    self.provider = storage.FileSystemProvider('/gcs')
    test_helpers.patch(self, [
        'clusterfuzz._internal.google_cloud_utils.storage._provider',
        'clusterfuzz._internal.google_cloud_utils.storage.use_async_http',
    ])
    self.mock._provider.return_value = self.provider  # pylint: disable=protected-access
    self.mock.use_async_http.return_value = False

  def test_failed_download_does_not_open_or_leave_empty_file(self):
    """If download_signed_url raises, the destination file is never opened or
    created."""
    filepath = '/bundle/data.db'

    with mock.patch.object(
        storage, 'download_signed_url', side_effect=RuntimeError('boom')), \
         mock.patch('builtins.open', wraps=open) as mocked_open:
      self.assertFalse(
          storage._error_tolerant_download_signed_url_to_file(  # pylint: disable=protected-access
              ('https://storage.googleapis.com/b/data.db', filepath)))
      mocked_open.assert_not_called()

    self.assertFalse(os.path.exists(filepath))

  def test_valid_bundle_paths(self):
    """Valid relative paths resolve under the bundle directory."""
    paths = [
        'data.db',
        'list.csv',
        'tests/graphics/css3/svg/res/2.0/images/textures/texture.jpg',
        'tests/browser/img/example logo.jpg',
        'tests/mobile/images/+.png',
        "tests/mobile/images/it's & .png",
        'demos/animations/layer.css',
    ]

    for path in paths:
      self.assertEqual(
          storage._get_safe_download_path('/bundle', path),  # pylint: disable=protected-access
          os.path.join('/bundle', *path.split('/')))

  def test_folder_placeholder_returns_none_without_error(self):
    """GCS folder placeholder objects ending with '/' are silently skipped."""
    with mock.patch.object(storage.logs, 'error') as mock_error:
      self.assertIsNone(storage._get_safe_download_path('/bundle', 'tests/'))  # pylint: disable=protected-access
      self.assertIsNone(storage._get_safe_download_path('/bundle', ''))  # pylint: disable=protected-access
      mock_error.assert_not_called()

  def test_traversal_and_reserved_names_rejected(self):
    """Traversal segments and reserved bundle metadata names are rejected."""
    for bad in ('../x', 'a/../../x', 'a//b', './x', '/abs', '.sync',
                'files.info'):
      with mock.patch.object(storage.logs, 'error') as mock_error:
        self.assertIsNone(storage._get_safe_download_path('/bundle', bad))  # pylint: disable=protected-access
        mock_error.assert_called_once()

  def test_windows_escaping_and_reserved_names(self):
    """Escapes Windows-forbidden characters, trailing dots/spaces, and reserved
    device names on WINDOWS while leaving them unchanged on LINUX."""
    windows_safe_names = [
        'tests/browser/img/example logo.jpg',
        'tests/mobile/images/+.png',
        'tests/mobile/images/a & b.png',
        "tests/mobile/images/it's here.png",
    ]
    with mock.patch.object(
        storage.environment, 'platform', return_value='WINDOWS'):
      for rel in windows_safe_names:
        self.assertEqual(
            storage._get_safe_download_path('/bundle', rel),  # pylint: disable=protected-access
            os.path.join('/bundle', *rel.split('/')))

    synthetic_cases = [
        ('a:b.js', 'a%3Ab.js'),
        ('x?.txt', 'x%3F.txt'),
        (r'a\..\x', 'a%5C..%5Cx'),
        ('trailing.', 'trailing%2E'),
        ('trailing ', 'trailing%20'),
        ('CON', '%43ON'),
        ('con.txt', '%63on.txt'),
        ('NUL.txt', '%4EUL.txt'),
        ('COM1.log', '%43OM1.log'),
        ('LPT9', '%4CPT9'),
        ('CONSOLE.txt', 'CONSOLE.txt'),
        ('icon.png', 'icon.png'),
    ]
    for raw_name, expected_win in synthetic_cases:
      with mock.patch.object(
          storage.environment, 'platform', return_value='WINDOWS'):
        self.assertEqual(
            storage._get_safe_download_path('/bundle', raw_name),  # pylint: disable=protected-access
            os.path.join('/bundle', expected_win))
      with mock.patch.object(
          storage.environment, 'platform', return_value='LINUX'):
        self.assertEqual(
            storage._get_safe_download_path('/bundle', raw_name),  # pylint: disable=protected-access
            os.path.join('/bundle', raw_name))

  def _seed_blobs(self, bucket, blobs):
    self.provider.create_bucket(bucket, None, None, None)
    for rel_path, data in blobs.items():
      self.provider.write_data(data, f'gs://{bucket}/{rel_path}')

  def test_no_prefix_uses_uuid_names(self):
    """download_signed_urls uses flat <uuid>-<idx> names, even for nested
    object names. This preserves the behavior for coverage guided corpora.
    """
    self._seed_blobs('engine-bucket', {'sub/input1': b'111', 'input2': b'222'})
    urls = ['gs://engine-bucket/sub/input1', 'gs://engine-bucket/input2']
    results = storage.download_signed_urls(urls, '/engine_dir')
    self.assertEqual(len(results), 2)
    for idx, res in enumerate(results):
      self.assertEqual(os.path.dirname(res.filepath), '/engine_dir')
      self.assertTrue(res.filepath.endswith(f'-{idx}'))

  def test_preserve_paths_sync_and_async(self):
    """Preserves filenames and nested directory trees for both download paths."""
    blobs = {
        'data.db': b'sqlite',
        'tests/browser/img/example logo.jpg': b'jpg',
        'tests/mobile/images/+.png': b'png',
        'demos/animations/layer.css': b'css',
    }
    bucket = 'example.com'
    self._seed_blobs(bucket, blobs)
    urls = [
        'https://storage.googleapis.com/'
        f'{bucket}/{urllib.parse.quote(rel)}{_SIGNED_QUERY}' for rel in blobs
    ]

    with mock.patch.object(
        storage,
        'download_signed_url',
        side_effect=lambda u: blobs[storage._get_relative_path_from_signed_url(  # pylint: disable=protected-access
            u, f'gs://{bucket}')]):
      sync_results = storage.download_signed_urls_preserving_paths(
          urls, '/sync_bundle', f'gs://{bucket}')

    self.assertEqual(len(sync_results), len(blobs))
    for rel, expected_bytes in blobs.items():
      full_path = os.path.join('/sync_bundle', *rel.split('/'))
      self.assertTrue(os.path.isfile(full_path), msg=f'Missing {full_path}')
      with open(full_path, 'rb') as fp:
        self.assertEqual(fp.read(), expected_bytes)

    def fake_fast_http_download(urls_and_paths):
      for _, dest_path in urls_and_paths:
        # Parent directories must already exist before fast_http runs.
        self.assertTrue(os.path.isdir(os.path.dirname(dest_path)))
        with open(dest_path, 'wb') as fp:
          fp.write(b'async')
      return [True] * len(urls_and_paths)

    self.mock.use_async_http.return_value = True
    with mock.patch.object(
        storage.fast_http, 'download_urls',
        side_effect=fake_fast_http_download):
      async_results = storage.download_signed_urls_preserving_paths(
          urls, '/async_bundle', f'gs://{bucket}')

    self.assertEqual(len(async_results), len(blobs))
    for rel in blobs:
      self.assertTrue(
          os.path.isfile(os.path.join('/async_bundle', *rel.split('/'))))

  def test_fallback_on_underivable_url_redacts_signature(self):
    """An underivable URL falls back to a uuid name and redacts the query."""
    bad_url = 'https://custom.host.example/bucket/data.db' + _SIGNED_QUERY

    with mock.patch.object(
        storage, 'download_signed_url', return_value=b'content'), \
         mock.patch.object(storage.logs, 'error') as mock_error:
      results = storage.download_signed_urls_preserving_paths(
          [bad_url], '/fallback_dir', 'gs://bucket')

    self.assertEqual(len(results), 1)
    self.assertTrue(results[0].filepath.endswith('-0'))
    mock_error.assert_called_once()
    logged_msg = mock_error.call_args[0][0]
    self.assertNotIn('secret123', logged_msg)
    self.assertNotIn('X-Goog-Signature', logged_msg)

  def test_bucket_root_url_skipped(self):
    """A bucket-root URL is logged and skipped, not downloaded."""
    root_url = 'https://storage.googleapis.com/b/' + _SIGNED_QUERY
    good_url = 'https://storage.googleapis.com/b/data.db' + _SIGNED_QUERY

    with mock.patch.object(
        storage, 'download_signed_url', return_value=b'data') as mock_download, \
         mock.patch.object(storage.logs, 'error') as mock_error:
      results = storage.download_signed_urls_preserving_paths(
          [root_url, good_url], '/root_dir', 'gs://b')

    mock_download.assert_called_once_with(good_url)
    self.assertEqual([r.filepath for r in results], ['/root_dir/data.db'])
    self.assertEqual(os.listdir('/root_dir'), ['data.db'])

    mock_error.assert_called_once()
    logged_msg = mock_error.call_args[0][0]
    self.assertIn('Signed URL does not reference an object', logged_msg)
    self.assertNotIn('X-Goog-Signature', logged_msg)

  def test_duplicate_path_skipped_before_pool(self):
    """Two URLs mapping to the same local path only dispatch the first."""
    u1 = 'https://storage.googleapis.com/b/data.db?X-Goog-Signature=one'
    u2 = 'https://storage.googleapis.com/b/data.db?X-Goog-Signature=two'
    dispatched = []

    def record_download(urls_and_paths):
      dispatched.extend(urls_and_paths)
      return [True] * len(urls_and_paths)

    self.mock.use_async_http.return_value = True
    with mock.patch.object(
        storage.fast_http, 'download_urls', side_effect=record_download), \
         mock.patch.object(storage.logs, 'error') as mock_error:
      storage.download_signed_urls_preserving_paths([u1, u2], '/dup_dir',
                                                    'gs://b')

    self.assertEqual(dispatched, [(u1, '/dup_dir/data.db')])
    mock_error.assert_called_once()

  def test_windows_case_and_escaping_collisions_skipped(self):
    """On Windows, case-only duplicates and escaping collisions are skipped
    before reaching the pool; on Linux, case-only differences both download."""
    urls = [
        'https://storage.googleapis.com/b/js/A.js?X-Goog-Signature=1',
        'https://storage.googleapis.com/b/js/a.js?X-Goog-Signature=2',
        'https://storage.googleapis.com/b/a%3Ab.js?X-Goog-Signature=3',
        'https://storage.googleapis.com/b/a%253Ab.js?X-Goog-Signature=4',
    ]
    self.mock.use_async_http.return_value = True

    win_dispatched = []
    with mock.patch.object(
        storage.environment, 'platform', return_value='WINDOWS'), \
         mock.patch.object(
             storage.os.path, 'normcase', side_effect=lambda p: p.lower()), \
         mock.patch.object(
             storage.fast_http,
             'download_urls',
             side_effect=lambda pairs: (
                 win_dispatched.extend(pairs) or [True] * len(pairs))):
      storage.download_signed_urls_preserving_paths(urls, '/win_dir', 'gs://b')

    self.assertEqual([p for _, p in win_dispatched],
                     ['/win_dir/js/A.js', '/win_dir/a%3Ab.js'])

    linux_dispatched = []
    with mock.patch.object(
        storage.environment, 'platform', return_value='LINUX'), \
         mock.patch.object(
             storage.fast_http,
             'download_urls',
             side_effect=lambda pairs: (
                 linux_dispatched.extend(pairs) or [True] * len(pairs))):
      storage.download_signed_urls_preserving_paths(urls[:2], '/linux_dir',
                                                    'gs://b')

    self.assertEqual([p for _, p in linux_dispatched],
                     ['/linux_dir/js/A.js', '/linux_dir/js/a.js'])


class GetRelativePathFromSignedUrlTest(unittest.TestCase):
  """Tests for _get_relative_path_from_signed_url."""

  def test_flat_bundles(self):
    """Flat data bundles derive their exact filename."""
    url_a = ('https://storage.googleapis.com/bundle-a.example.com/'
             'data.db' + _SIGNED_QUERY)
    self.assertEqual(
        storage._get_relative_path_from_signed_url(  # pylint: disable=protected-access
            url_a, _FLAT_BUNDLE_A_GCS_URL),
        'data.db')

    url_b = ('https://storage.googleapis.com/bundle-b.example.com/'
             'list.csv' + _SIGNED_QUERY)
    self.assertEqual(
        storage._get_relative_path_from_signed_url(  # pylint: disable=protected-access
            url_b, _FLAT_BUNDLE_B_GCS_URL),
        'list.csv')

  def test_nested_paths_and_special_characters(self):
    """Nested paths and percent-encoded spaces, '+', '&', and \"'\"."""
    cases = [
        ('tests/graphics/css3/svg/res/2.0/images/textures/texture.jpg',
         'tests/graphics/css3/svg/res/2.0/images/textures/texture.jpg'),
        ('tests/browser/img/example%20logo.jpg',
         'tests/browser/img/example logo.jpg'),
        ('tests/mobile/images/%2B.png', 'tests/mobile/images/+.png'),
        ('tests/mobile/images/400%2B%20number.png',
         'tests/mobile/images/400+ number.png'),
        ('tests/mobile/images/a%20%26%20b.png',
         'tests/mobile/images/a & b.png'),
        ('tests/mobile/images/it%27s%20a%20-%20b%27s%20c.png',
         "tests/mobile/images/it's a - b's c.png"),
        ("tests/mobile/images/it's%20here.png",
         "tests/mobile/images/it's here.png"),
        ('demos/animations/layer.css', 'demos/animations/layer.css'),
    ]
    for encoded_path, expected in cases:
      url = ('https://storage.googleapis.com/'
             f'example.com/{encoded_path}' + _SIGNED_QUERY)
      self.assertEqual(
          storage._get_relative_path_from_signed_url(  # pylint: disable=protected-access
              url, _NESTED_BUNDLE_GCS_URL),
          expected,
          msg=f'Failed for {encoded_path}')

  def test_gs_urls_used_as_is_without_unquoting(self):
    """gs:// URLs from FileSystemProvider are not percent-decoded."""
    self.assertEqual(
        storage._get_relative_path_from_signed_url(  # pylint: disable=protected-access
            f'{_NESTED_BUNDLE_GCS_URL}/tests/browser/images/'
            'New Presentation.pptx', _NESTED_BUNDLE_GCS_URL),
        'tests/browser/images/New Presentation.pptx')
    self.assertEqual(
        storage._get_relative_path_from_signed_url(  # pylint: disable=protected-access
            'gs://b/100%25.txt', 'gs://b'),
        '100%25.txt')

  def test_prefix_stripping_and_mismatches(self):
    """Strips non-empty prefixes and returns None on bucket/host mismatch."""
    self.assertEqual(
        storage._get_relative_path_from_signed_url(  # pylint: disable=protected-access
            'gs://b/pre/x/y', 'gs://b/pre'),
        'x/y')
    self.assertIsNone(
        storage._get_relative_path_from_signed_url(  # pylint: disable=protected-access
            f'{_NESTED_BUNDLE_GCS_URL}/tests/a.svg', _FLAT_BUNDLE_B_GCS_URL))
    self.assertIsNone(
        storage._get_relative_path_from_signed_url(  # pylint: disable=protected-access
            'https://b.storage.googleapis.com/x' + _SIGNED_QUERY, 'gs://b'))

  def test_bucket_root_raises(self):
    """URLs that reference a bucket root rather than an object raise."""
    bucket_root_urls = [
        'https://storage.googleapis.com/' + _SIGNED_QUERY,
        'https://storage.googleapis.com' + _SIGNED_QUERY,
        'https://storage.googleapis.com/b' + _SIGNED_QUERY,
        'https://storage.googleapis.com/b/' + _SIGNED_QUERY,
        'gs://b',
        'gs://b/',
    ]
    for url in bucket_root_urls:
      with self.subTest(url=url):
        with self.assertRaises(storage.BucketRootSignedUrlError) as ctx:
          storage._get_relative_path_from_signed_url(  # pylint: disable=protected-access
              url, 'gs://b')
        self.assertNotIn('X-Goog-Signature', str(ctx.exception))
