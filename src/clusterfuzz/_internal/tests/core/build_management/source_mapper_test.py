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
"""source_mapper tests."""
import unittest

from clusterfuzz._internal.build_management import source_mapper


class GetComponentSourceAndRelativePathTest(unittest.TestCase):
  """Tests for get_component_source_and_relative_path."""

  def test_get_component_source_and_relative_path_chromium(self):
    """Test get component source and relative path for chromium."""
    revisions_dict = {
        '/src': {
            'url': 'https://chromium.googlesource.com/chromium/src.git',
            'rev': '1d783bc2a3629b94c963debfa3feaee27092dd92',
        },
        'src/v8': {
            'url': 'https://chromium.googlesource.com/v8/v8.git',
            'rev': '7fb2c3b6db3f889ea95851ca11dcb731b07a7925',
        }
    }

    self.assertEqual(
        source_mapper.get_component_source_and_relative_path(
            r'content/common.h', revisions_dict),
        source_mapper.ComponentPath('/src', 'content/common.h',
                                    'content/common.h'))
    self.assertEqual(
        source_mapper.get_component_source_and_relative_path(
            r'content\common.h', revisions_dict),
        source_mapper.ComponentPath('/src', 'content/common.h',
                                    'content/common.h'))
    self.assertEqual(
        source_mapper.get_component_source_and_relative_path(
            r'c:\build\src\content\common.h', revisions_dict),
        source_mapper.ComponentPath('/src', 'content/common.h',
                                    'content/common.h'))
    self.assertEqual(
        source_mapper.get_component_source_and_relative_path(
            r'/mnt/build/src/content/common.h', revisions_dict),
        source_mapper.ComponentPath('/src', 'content/common.h',
                                    'content/common.h'))
    self.assertEqual(
        source_mapper.get_component_source_and_relative_path(
            r'../../third_party/WebKit/Source/platform/heap/Member.h',
            revisions_dict),
        source_mapper.ComponentPath(
            '/src', 'third_party/WebKit/Source/platform/heap/Member.h',
            'third_party/WebKit/Source/platform/heap/Member.h'))
    self.assertEqual(
        source_mapper.get_component_source_and_relative_path(
            r'v8/src/api.cc', revisions_dict),
        source_mapper.ComponentPath('src/v8', 'src/api.cc', 'v8/src/api.cc'))
    self.assertEqual(
        source_mapper.get_component_source_and_relative_path(
            r'v8\src\api.cc', revisions_dict),
        source_mapper.ComponentPath('src/v8', 'src/api.cc', 'v8/src/api.cc'))
    self.assertEqual(
        source_mapper.get_component_source_and_relative_path(
            r'c:\build\src\v8\src\api.cc', revisions_dict),
        source_mapper.ComponentPath('src/v8', 'src/api.cc', 'v8/src/api.cc'))
    self.assertEqual(
        source_mapper.get_component_source_and_relative_path(
            r'/mnt/build/src/v8/src/api.cc', revisions_dict),
        source_mapper.ComponentPath('src/v8', 'src/api.cc', 'v8/src/api.cc'))
    self.assertEqual(
        source_mapper.get_component_source_and_relative_path(
            r'/mnt/build/src/v8_overrides/init.cc', revisions_dict),
        source_mapper.ComponentPath('/src', 'v8_overrides/init.cc',
                                    'v8_overrides/init.cc'))
    self.assertEqual(
        source_mapper.get_component_source_and_relative_path(
            r'/mnt/build/non_existent', revisions_dict),
        source_mapper.ComponentPath())
    self.assertEqual(
        source_mapper.get_component_source_and_relative_path(
            r'c:\build\non_existent', revisions_dict),
        source_mapper.ComponentPath())

  def test_get_component_source_and_relative_path_oss_fuzz(self):
    """Test get comnponent source and relative path for OSS-Fuzz."""
    revisions_dict = {
        '/src/libass': {
            'url': 'https://github.com/libass/libass.git',
            'rev': '35dc4dd0e14e3afb4a2c7e319a3f4110e20c7cf2',
            'type': 'git'
        },
        '/src/fribidi': {
            'url': 'https://github.com/behdad/fribidi.git',
            'rev': '881b8d891cc61989ab8811b74d0e721f72bf913b',
            'type': 'git'
        }
    }

    self.assertEqual(
        source_mapper.get_component_source_and_relative_path(
            r'/src/libass/test/test.c', revisions_dict),
        source_mapper.ComponentPath('/src/libass', 'test/test.c',
                                    'libass/test/test.c'))
    self.assertEqual(
        source_mapper.get_component_source_and_relative_path(
            r'/src/fribidi/lib/common.h', revisions_dict),
        source_mapper.ComponentPath('/src/fribidi', 'lib/common.h',
                                    'fribidi/lib/common.h'))
    self.assertEqual(
        source_mapper.get_component_source_and_relative_path(
            r'/src/not_existent', revisions_dict),
        source_mapper.ComponentPath())


class NormalizeSourcePathTest(unittest.TestCase):
  """Tests for normalize_source_path."""

  def test_normalize_source_path(self):
    """Test normalizing source path."""
    self.assertEqual(
        source_mapper.normalize_source_path(r'c:\build\src\heap\compact.cc'),
        'heap/compact.cc')
    self.assertEqual(
        source_mapper.normalize_source_path('/mnt/build/src/heap/compact.cc'),
        'heap/compact.cc')
    self.assertEqual(
        source_mapper.normalize_source_path('/mnt/build/heap/compact.cc'), None)
    self.assertEqual(
        source_mapper.normalize_source_path('src/heap/compact.cc'),
        'src/heap/compact.cc')
    self.assertEqual(
        source_mapper.normalize_source_path('heap/compact.cc'),
        'heap/compact.cc')
    self.assertEqual(
        source_mapper.normalize_source_path('/proc/self/cwd/heap/compact.cc'),
        'heap/compact.cc')
    self.assertEqual(
        source_mapper.normalize_source_path(
            '../../third_party/WebKit/Source/platform/heap/Member.h'),
        'third_party/WebKit/Source/platform/heap/Member.h')


class VCSViewerTest(unittest.TestCase):
  """Tests for VCSViewer."""

  def test_get_vcs_viewer_for_url(self):
    """Test that VCS recognition logic from source_mapper.py works correctly."""
    vcs = source_mapper.get_vcs_viewer_for_url(
        'https://anongit.freedesktop.org/git/gstreamer/gstreamer.git')
    self.assertIsInstance(vcs, source_mapper.FreeDesktopVCS)

    vcs = source_mapper.get_vcs_viewer_for_url(
        'https://github.com/imagemagick/imagemagick.git')
    self.assertIsInstance(vcs, source_mapper.GitHubVCS)

    vcs = source_mapper.get_vcs_viewer_for_url(
        'https://gitlab.com/libidn/libidn2.git')
    self.assertIsInstance(vcs, source_mapper.GitLabVCS)

    vcs = source_mapper.get_vcs_viewer_for_url(
        'https://gitlab.gnome.org/GNOME/libxml2.git')
    self.assertIsInstance(vcs, source_mapper.GitLabVCS)

    vcs = source_mapper.get_vcs_viewer_for_url(
        'https://chromium.googlesource.com/webm/libwebp.git')
    self.assertIsInstance(vcs, source_mapper.GoogleSourceVCS)

    vcs = source_mapper.get_vcs_viewer_for_url('//dir1/dir2')
    self.assertIsInstance(vcs, source_mapper.GoogleVCS)

    vcs = source_mapper.get_vcs_viewer_for_url(
        'http://hg.code.sf.net/p/graphicsmagick/code')
    self.assertIsInstance(vcs, source_mapper.MercurialVCS)

  def test_google_vcs(self):
    vcs = source_mapper.GoogleVCS('//dir1/dir2')
    self.assertEqual('https://cs.corp.google.com/dir1/dir2/?rcl=1337',
                     vcs.get_source_url_for_revision(1337))
    self.assertEqual(None, vcs.get_source_url_for_revision_diff(1337, 1338))
    self.assertEqual(
        'https://cs.corp.google.com'
        '/dir1/dir2/dir3/dir4/file1.txt?rcl=1337&l=10',
        vcs.get_source_url_for_revision_path_and_line(
            1337, 'dir3/dir4/file1.txt', 10))
