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
"""Settings change related functions."""
import re

from clusterfuzz._internal.system import environment

from . import adb

BUILD_FINGERPRINT_REGEX = re.compile(
    r'(?P<vendor>.+)\/(?P<target>.+)'
    r'\/(?P<flavor>.+)\/(?P<name_name>.+)'
    r'\/(?P<build_id>.+):(?P<type>.+)\/(?P<keys>.+)')


def change_se_linux_to_permissive_mode():
  """Switch SELinux to permissive mode for working around local file access and
  other issues."""
  adb.run_shell_command(['setenforce', '0'])


def get_build_fingerprint():
  """Return build's fingerprint."""
  return adb.get_property('ro.build.fingerprint')


def get_build_flavor():
  """Return the build flavor."""
  return adb.get_property('ro.build.flavor')


def get_build_parameters():
  """Return build_id, target and type from the device's fingerprint"""
  build_fingerprint = environment.get_value('BUILD_FINGERPRINT',
                                            get_build_fingerprint())
  build_fingerprint_match = BUILD_FINGERPRINT_REGEX.match(build_fingerprint)
  if not build_fingerprint_match:
    return None

  build_id = build_fingerprint_match.group('build_id')
  target = build_fingerprint_match.group('target')
  build_type = build_fingerprint_match.group('type')
  return {'build_id': build_id, 'target': target, 'type': build_type}


def get_build_version():
  """Return the build version of the system as a character.
  K = Kitkat, L = Lollipop, M = Marshmellow, MASTER = Master.
  """
  build_version = adb.get_property('ro.build.id')
  if not build_version:
    return None

  if build_version == 'MASTER':
    return build_version

  match = re.match('^([A-Z])', build_version)
  if not match:
    return None

  return match.group(1)


def get_cpu_arch():
  """Return cpu architecture."""
  return adb.get_property('ro.product.cpu.abi')


def get_device_codename():
  """Return the device codename."""
  serial = environment.get_value('ANDROID_SERIAL')
  devices_output = adb.run_command(['devices', '-l'])

  serial_pattern = r'(^|\s){serial}\s'.format(serial=re.escape(serial))
  serial_regex = re.compile(serial_pattern)

  for line in devices_output.splitlines():
    values = line.strip().split()

    if not serial_regex.search(line):
      continue

    for value in values:
      if not value.startswith('device:'):
        continue
      device_codename = value.split(':')[-1]
      if device_codename:
        return device_codename

  # Unable to get code name.
  return ''


def get_platform_id():
  """Return a string as |android:{codename}_{sanitizer}:{build_version}|."""
  platform_id = 'android'

  # Add codename and sanitizer tool information.
  platform_id += ':%s' % get_device_codename()
  sanitizer_tool_name = get_sanitizer_tool_name()
  if sanitizer_tool_name:
    platform_id += '_%s' % sanitizer_tool_name

  # Add build version.
  build_version = get_build_version()
  if build_version:
    platform_id += ':%s' % build_version

  return platform_id


def get_product_brand():
  """Return product's brand."""
  return adb.get_property('ro.product.brand')


def get_product_name():
  """Return product's name."""
  return adb.get_property('ro.product.name')


def get_product_model():
  """Return product's model."""
  return adb.get_property('ro.product.model')


def get_build_product():
  """Return builds's product."""
  return adb.get_property('ro.build.product')


def get_sanitizer_tool_name():
  """Return sanitizer tool name e.g. ASAN if found on device."""
  build_flavor = get_build_flavor()
  if 'hwasan' in build_flavor:
    return 'hwasan'
  if 'kasan' in build_flavor:
    return 'kasan'
  if 'asan' in build_flavor:
    return 'asan'

  return None


def get_security_patch_level():
  """Return the security patch level reported by the device."""
  return adb.get_property('ro.build.version.security_patch')


def get_kernel_version_string():
  return adb.run_shell_command('cat /proc/version').strip()


def is_google_device():
  """Return true if this is a google branded device."""
  # If a build branch is already set, then this is a Google device. No need to
  # query device which can fail if the device is failing on recovery mode.
  build_branch = environment.get_value('BUILD_BRANCH')
  if build_branch:
    return True

  product_brand = environment.get_value('PRODUCT_BRAND', get_product_brand())
  if product_brand is None:
    return None

  return product_brand in ('google', 'generic')


def is_automotive():
  """Returns if we are running in Android Automotive OS, currently only for
  Osprey or Seahawk."""
  product_model = get_product_model()
  return product_model in ('Osprey', 'Seahawk')


def set_content_setting(table, key, value):
  """Set a device content setting. The input is not sanitized, so make sure to
  use with trusted input key and value pair only."""

  def _get_type_binding(value):
    """Return binding type for content setting."""
    if isinstance(value, bool):
      return 'b'
    if isinstance(value, float):
      return 'f'
    if isinstance(value, int):
      return 'i'

    # Default to string.
    return 's'

  content_setting_command = (
      'content insert --uri content://%s --bind name:s:%s --bind value:%s:%s' %
      (table, key, _get_type_binding(value), str(value)))

  adb.run_shell_command(content_setting_command)


def set_database_setting(database_path, table, key, value):
  """Update a key in a database. The input is not sanitized, so make sure to use
  with trusted input key and value pair only."""
  sql_command_string = ('"UPDATE %s SET value=\'%s\' WHERE name=\'%s\'"') % (
      table, str(value), key)
  adb.run_shell_command(['sqlite3', database_path, sql_command_string])
