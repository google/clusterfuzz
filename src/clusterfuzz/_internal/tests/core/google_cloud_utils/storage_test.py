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

from pyfakefs import fake_filesystem_unittest
import six

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.google_cloud_utils import storage
from clusterfuzz._internal.tests.test_libs import test_utils


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
    self.provider.create_bucket('test-bucket', None, None)
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
    six.assertCountEqual(self, [{
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
    six.assertCountEqual(self, [{
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
    six.assertCountEqual(self, [{
        'bucket': 'test-bucket',
        'name': 'b/d/e',
        'updated': mtime,
        'size': 33,
        'metadata': {}
    }], result)

    result = list(
        self.provider.list_blobs('gs://test-bucket/', recursive=False))
    six.assertCountEqual(self, [{
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
