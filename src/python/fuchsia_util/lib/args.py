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

# Copyright 2019 The Fuchsia Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""Argument parsing utils for Fuchsia."""

import argparse


class Args(object):
  """CIPD argument parser."""

  @classmethod
  def make_parser(cls, description, name_required=True, label_present=False):
    """Makes a CIPD argument parser."""
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument(
        '-d',
        '--device',
        help='Name of device, only needed when multiple devices are present.')
    parser.add_argument(
        '-f',
        '--foreground',
        action='store_true',
        help='If true, display fuzzer output.')
    parser.add_argument(
        '-n',
        '--no-cipd',
        action='store_true',
        help='Skip steps which involve transferring packages to or from CIPD')
    parser.add_argument(
        '-o', '--output', help='Path under which to store results.')
    parser.add_argument(
        '-s',
        '--staging',
        help='Host directory to use for un/packing corpus bundles.' +
        ' Defaults to a temporary directory.')
    name_help = ('Fuzzer name to match.  This can be part of the package and/or'
                 + ' target name, e.g. "foo", "bar", and "foo/bar" all match' +
                 ' "foo_package/bar_target".')
    if name_required:
      parser.add_argument('name', help=name_help)
    else:
      parser.add_argument('name', nargs='?', help=name_help)
    if label_present:
      parser.add_argument(
          'label',
          nargs='?',
          default='latest',
          help='If a directory, installs a corpus from that location. ' +
          'Otherwise installs the labeled version from CIPD. In this case, ' +
          '"label" may be either a "ref" or a key:value "tag"  as described ' +
          'in `cipd help`. By default, corpora are uploaded with the ' +
          '"latest" ref and a tag of "integration:<git-revision>" ' +
          'corresponding to current revision of the //integration repository.')
    return parser
