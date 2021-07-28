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
"""Utilities for fetching build info from OmahaProxy."""

import json
import re

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment

BUILD_INFO_PATTERN = ('([a-z]+),([a-z]+),([0-9.]+),'
                      '[^,]*,[^,]*,[^,]*,[^,]*,[^,]*,'
                      '([0-9a-f]+),.*')
BUILD_INFO_URL = 'https://omahaproxy.appspot.com/all?csv=1'
BUILD_INFO_URL_CD = ('https://chromiumdash.appspot.com/fetch_releases?'
                     'num=1&platform={platform}')


class BuildInfo(object):
  """BuildInfo holds build metadata pulled from OmahaProxy."""

  def __init__(self, platform, build_type, version, revision):
    self.platform = platform
    self.build_type = build_type
    self.version = version
    self.revision = revision


def _convert_platform_to_omahaproxy_platform(platform):
  """Converts platform to omahaproxy platform for use in
  get_production_builds_info."""
  platform_lower = platform.lower()
  if platform_lower == 'windows':
    return 'win'
  return platform_lower


def _convert_platform_to_chromiumdash_platform(platform):
  """Converts platform to Chromium Dash platform.
  Note that Windows in Chromium Dash is win64 and we only want win32."""
  platform_lower = platform.lower()
  if platform_lower == 'windows':
    return 'Win32'
  return platform_lower.capitalize()


def _fetch_releases_from_chromiumdash(platform, channel=None):
  """Makes a Call to chromiumdash's fetch_releases api,
  and returns its json array response."""
  chromiumdash_platform = _convert_platform_to_chromiumdash_platform(platform)
  query_url = BUILD_INFO_URL_CD.format(platform=chromiumdash_platform)
  if channel:
    query_url = query_url + '&channel=' + channel

  build_info = utils.fetch_url(query_url)
  if not build_info:
    logs.log_error('Failed to fetch build info from %s' % query_url)
    return []

  try:
    build_info_json = json.loads(build_info)
    if not build_info_json:
      logs.log_error('Empty response from %s' % query_url)
      return []
  except Exception:
    logs.log_error('Malformed response from %s' % query_url)
    return []

  return build_info_json


def get_production_builds_info(platform):
  """Gets the build information for production builds.

  Omits platforms containing digits, namely, win64.
  Omits channels containing underscore, namely, canary_asan.
  Platform is e.g. ANDROID, LINUX, MAC, WIN.
  """
  builds_metadata = []
  omahaproxy_platform = _convert_platform_to_omahaproxy_platform(platform)

  build_info = utils.fetch_url(BUILD_INFO_URL)
  if not build_info:
    logs.log_error('Failed to fetch build info from %s' % BUILD_INFO_URL)
    return []

  for line in build_info.splitlines():
    match = re.match(BUILD_INFO_PATTERN, line)
    if not match:
      continue

    platform_type = match.group(1)
    if platform_type != omahaproxy_platform:
      continue

    build_type = match.group(2)
    version = match.group(3)
    revision = match.group(4)
    builds_metadata.append(BuildInfo(platform, build_type, version, revision))

  return builds_metadata


def get_production_builds_info_from_cd(platform):
  """Gets the build information from Chromium Dash for production builds.

  Omits platforms containing digits, namely, win64.
  Omits channels containing underscore, namely, canary_asan.
  Platform is e.g. ANDROID, LINUX, MAC, WINDOWS.
  """
  builds_metadata = []
  build_info_json = _fetch_releases_from_chromiumdash(platform)
  for info in build_info_json:
    build_type = info['channel'].lower()
    if build_type == 'extended':
      build_type = 'extended_stable'

    version = info['version']
    revision = info['hashes']['chromium']
    builds_metadata.append(BuildInfo(platform, build_type, version, revision))

  # Hack: pretend Windows extended stable info to be Linux extended stable info.
  # Because Linux doesn't have extended stable channel.
  if platform.lower() == 'linux':
    es_info = _fetch_releases_from_chromiumdash(
        'WINDOWS', channel='Extended')[0]
    builds_metadata.append(
        BuildInfo(platform, 'extended_stable', es_info['version'],
                  es_info['hashes']['chromium']))

  return builds_metadata


def get_release_milestone(build_type, platform):
  """Return milestone for a particular release."""
  if build_type == 'head':
    actual_build_type = 'canary'
  else:
    actual_build_type = build_type

  builds_metadata = get_production_builds_info_from_cd(platform)
  for build_metadata in builds_metadata:
    if build_metadata.build_type == actual_build_type:
      version_parts = build_metadata.version.split('.')
      milestone = version_parts[0]
      if milestone and milestone.isdigit():
        return int(milestone)

  if actual_build_type == 'canary':
    # If there is no canary for that platform, just return canary from windows.
    return get_release_milestone('canary', 'windows')

  return None


def get_build_to_revision_mappings(platform=None):
  """Gets the build information."""
  if not platform:
    platform = environment.platform()

  result = {}
  build_info_json = _fetch_releases_from_chromiumdash(platform)

  for info in build_info_json:
    build_type = info['channel'].lower()
    if build_type == 'extended':
      build_type = 'extended_stable'

    version = info['version']
    revision = str(info['chromium_main_branch_position'])
    result[build_type] = {'revision': revision, 'version': version}

  # Hack: pretend Windows extended stable info to be Linux extended stable info.
  # Because Linux doesn't have extended stable channel.
  if platform.lower() == 'linux':
    es_info = _fetch_releases_from_chromiumdash(
        'WINDOWS', channel='Extended')[0]
    result['extended_stable'] = {
        'revision': str(es_info['chromium_main_branch_position']),
        'version': es_info['version']
    }

  return result
