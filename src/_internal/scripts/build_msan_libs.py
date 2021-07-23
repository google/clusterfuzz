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
"""Build MSan instrumented libs on Google Container Builder."""
# Usage:
# 1. build_msan_libs.py [--no-track-origins] build_packages
# 2. Wait for builds to complete on
# https://console.cloud.google.com/gcr/builds?project=google.com:clusterfuzz
# 3. Once all builds have succeeded, run:
#    build_msan_libs.py [--no-track-origins] merge

import argparse
import datetime

from googleapiclient.discovery import build

UPLOAD_BUCKET = 'clusterfuzz-chromium-msan-libs'
DISTRO_VERSION = '16.04'

BUILD_TIMEOUT = 2 * 60 * 60

# For Chromium on Ubuntu 16.04
PACKAGES = [
    'libappindicator3-1',
    'libasound2',
    'libatk1.0-0',
    'libatk-bridge2.0-0',
    'libatspi2.0-0',
    'libavahi-client3',
    'libavahi-common3',
    'libcairo2',
    'libcairo-gobject2',
    'libcap2',
    'libcomerr2',
    'libcroco3',
    'libcups2',
    'libdatrie1',
    'libdbus-1-3',
    'libdbusmenu-glib4',
    'libdbusmenu-gtk3-4',
    'libepoxy0',
    'libexpat1',
    'libffi6',
    'libfontconfig1',
    'libfreetype6',
    'libgcrypt20',
    'libgdk-pixbuf2.0-0',
    'libglib2.0-0',
    'libgmp10',
    'libgnutls30',
    'libgpg-error0',
    'libgraphite2-3',
    'libgssapi-krb5-2',
    'libgtk-3-0',
    'libharfbuzz0b',
    'libhogweed4',
    'libidn11',
    'libido3-0.1-0',
    'libindicator3-7',
    'libk5crypto3',
    'libkeyutils1',
    'libkrb5-3',
    'libkrb5support0',
    'liblz4-1',
    'liblzma5',
    'libnettle6',
    'libnspr4',
    'libnss3',
    'libp11-kit0',
    'libpango-1.0-0',
    'libpangocairo-1.0-0',
    'libpangoft2-1.0-0',
    'libpci3',
    'libpcre3',
    'libpixman-1-0',
    'libpng12-0',
    'libpulse0',
    'librsvg2-2',
    'libselinux1',
    'libsqlite3-0',
    'libsystemd0',
    'libtasn1-6',
    'libthai0',
    'libudev1',
    'libwayland-client0',
    'libwayland-cursor0',
    'libx11-6',
    'libx11-xcb1',
    'libxau6',
    'libxcb1',
    'libxcb-render0',
    'libxcb-shm0',
    'libxcomposite1',
    'libxcursor1',
    'libxdamage1',
    'libxdmcp6',
    'libxext6',
    'libxfixes3',
    'libxi6',
    'libxinerama1',
    'libxkbcommon0',
    'libxml2',
    'libxrandr2',
    'libxrender1',
    'libxss1',
    'libxtst6',
    'zlib1g',
]


def bucket_path(no_track_origins):
  """Return the bucket path to upload to."""
  if no_track_origins:
    subdir = 'no-origins'
  else:
    subdir = 'chained-origins'

  return 'gs://%s/%s/%s' % (UPLOAD_BUCKET, DISTRO_VERSION, subdir)


def build_steps(package_name, no_track_origins=False):
  """Return build steps for a package."""
  zip_name = package_name + '.zip'
  build_args = ['msan_build.py', '--no-build-deps', package_name, '/workspace']

  if no_track_origins:
    build_args.append('--no-track-origins')

  return [
      {
          # Build package.
          'args': build_args,
          # Use OSS-Fuzz's MSan builder.
          'name': 'gcr.io/oss-fuzz-base/base-msan-builder',
      },
      {
          # Zip results.
          'args': ['zip', '-r', '-y', zip_name, '.'],
          'name': 'gcr.io/oss-fuzz-base/base-msan-builder',
      },
      {
          # Upload.
          'args': [
              'cp',
              zip_name,
              '%s/packages/%s' % (bucket_path(no_track_origins), zip_name),
          ],
          'name':
              'gcr.io/cloud-builders/gsutil',
      },
  ]


def get_build(steps):
  """Get a build given steps."""
  return {
      'steps': steps,
      'timeout': str(BUILD_TIMEOUT) + 's',
      'options': {
          'machineType': 'N1_HIGHCPU_8',
      },
  }


def merge_steps(no_track_origins=False):
  """Get merge steps to merge individual packages into a single zip."""
  timestamp = datetime.datetime.utcnow().strftime('%Y%m%d%H%M')
  filename = 'latest-%s.zip' % timestamp

  return [
      {
          # Download all individual packages.
          'args': [
              '-m', 'cp', '-r',
              bucket_path(no_track_origins) + '/packages/', '.'
          ],
          'name':
              'gcr.io/cloud-builders/gsutil',
      },
      {
          # Extract.
          'args': [
              'bash',
              '-c',
              'mkdir all && cd all && unzip -o "../packages/*.zip"',
          ],
          'name':
              'gcr.io/oss-fuzz-base/base-msan-builder',
      },
      {
          # Zip.
          'args': [
              'bash', '-c',
              'find -L -name \'*.so*\' | zip -y %s -@' % filename
          ],
          'dir':
              'all',
          'name':
              'gcr.io/oss-fuzz-base/base-msan-builder',
      },
      {
          # Upload.
          'args': [
              'cp',
              filename,
              bucket_path(no_track_origins) + '/' + filename,
          ],
          'dir':
              'all',
          'name':
              'gcr.io/cloud-builders/gsutil',
      },
  ]


def start_build(cloudbuild, build_body):
  """Start a build."""
  build_info = cloudbuild.projects().builds().create(
      projectId='google.com:clusterfuzz', body=build_body).execute()
  return build_info['metadata']['build']['id']


def main():
  parser = argparse.ArgumentParser(
      'build_msan_libs.py', description='MSan builder.')
  parser.add_argument(
      '--no-track-origins',
      action='store_true',
      help='Build with -fsanitize-memory-track-origins=0.')
  parser.add_argument(
      'command',
      choices=['build_packages', 'merge'],
      help='The command to run.')
  args = parser.parse_args()

  cloudbuild = build('cloudbuild', 'v1', cache_discovery=False)

  if args.command == 'build_packages':
    for package in PACKAGES:
      build_body = get_build(build_steps(package, args.no_track_origins))
      print(start_build(cloudbuild, build_body))
  else:  # merge
    print(
        start_build(cloudbuild, get_build(merge_steps(args.no_track_origins))))


if __name__ == '__main__':
  main()
