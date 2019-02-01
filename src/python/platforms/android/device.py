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
"""Device information related functions."""

import copy
import datetime
import logger
import os
import random
import re
import socket
import time

try:
  from shlex import quote
except ImportError:
  from pipes import quote

from base import dates
from base import persistent_cache
from config import db_config
from datastore import locks
from metrics import logs
from platforms.android import adb
from platforms.android import fetch_artifact
from system import archive
from system import environment
from system import shell

ADD_TEST_ACCOUNT_APK_NAME = 'user_account_setup.apk'
ADD_TEST_ACCOUNT_CHECK_INTERVAL = 1 * 24 * 60 * 60
ADD_TEST_ACCOUNT_PKG_NAME = 'com.google.android.tests.utilities'
ADD_TEST_ACCOUNT_TIMEOUT = 20
ARCH32_ID = 'arm'
ARCH64_ID = 'aarch64'
ASAN_RT_LIB = 'libclang_rt.asan-{arch}-android.so'
ASAN_SCRIPT_TIMEOUT = 15 * 60
BUILD_FINGERPRINT_REGEX = re.compile(
    r'(?P<vendor>.+)\/(?P<target>.+)'
    r'\/(?P<flavor>.+)\/(?P<name_name>.+)'
    r'\/(?P<build_id>.+):(?P<type>.+)\/(?P<keys>.+)')
BUILD_PROP_PATH = '/system/build.prop'
BUILD_PROP_BACKUP_PATH = BUILD_PROP_PATH + '.bak'
BUILD_PROPERTIES = {
    # Disable boot animation.
    'debug.sf.nobootanimation': '1',
    # Disable privileged app permissions enforcement.
    'ro.control_privapp_permissions': 'disable',
    # Scan for wifi less often: saves battery.
    'wifi.supplicant_scan_interval': '500',
}
FLASH_IMAGE_REGEXES = [
    r'.*[.]img',
    r'.*-img-.*[.]zip',
]
FLASH_IMAGE_FILES = [
    # Order is important here.
    ('bootloader', 'bootloader*.img'),
    ('radio', 'radio*.img'),
    ('boot', 'boot.img'),
    ('system', 'system.img'),
    ('recovery', 'recovery.img'),
    ('vendor', 'vendor.img'),
    ('cache', 'cache.img'),
    ('userdata', 'userdata.img'),
]
FLASH_RETRIES = 3
FLASH_REBOOT_BOOTLOADER_WAIT = 15
FLASH_REBOOT_WAIT = 5 * 60
GMSCORE_APK_NAME = 'GmsCore'
GMSCORE_BRANCH = 'ub-gcore-v2-release'  # FIXME: Deprecate this old release.
GMSCORE_BRANCH_REGEX = r'gcore-([^-]+)'
GMSCORE_TARGET = 'GmsCore'
GMSCORE_UPDATE_INTERVAL = 1 * 24 * 60 * 60
KERNEL_LOG_FILES = [
    '/proc/last_kmsg',
    '/sys/fs/pstore/console-ramoops',
]
LOCAL_PROP_PATH = '/data/local.prop'
LOCAL_PROP_SETTINGS = [
    'ro.audio.silent=1',
    'ro.monkey=1',
    'ro.setupwizard.mode=DISABLED',
    'ro.test_harness=1',
    'ro.telephony.disable-call=true',
]
LOCKSCREEN_DB = '/data/system/locksettings.db'
LOCKSCREEN_TABLE_NAME = 'locksettings'
# The format of logcat when lowmemorykiller kills a process can be found in
# https://android.googlesource.com/platform/system/core/+/master/lmkd/lmkd.c#586
LOW_MEMORY_REGEX = re.compile(
    r'Low on memory:|'
    r'lowmemorykiller: Killing|'
    r'to\s+free.*because\s+cache.*is\s+below\s+limit.*for\s+oom_', re.DOTALL)
MEDIA_CODECS_CONFIG_BACKUP_PATH = '/etc/media_codecs.xml.orig'
MEDIA_CODECS_CONFIG_PATH = '/etc/media_codecs.xml'
MEMORY_CONSTRAINED_DEVICES = [
    '4560MMX_sprout',
    '4560MMX_b_sprout',
]
MEMORY_MONITOR_SCRIPT = 'memory_monitor.sh'
PS_REGEX = re.compile(
    r'\S+\s+([0-9]+)\s+[0-9]+\s+[0-9]+\s+[0-9]+\s+\S+\s+\S+\s+\S+\s+sh')
SANITIZER_TOOL_TO_FILE_MAPPINGS = {
    'ASAN': 'asan.options',
}
SCREEN_LOCK_SEARCH_STRING = 'mShowingLockscreen=true'
SCREEN_ON_SEARCH_STRING = 'Display Power: state=ON'
SYSTEM_WEBVIEW_APK_NAME = 'SystemWebViewGoogle.apk'
SYSTEM_WEBVIEW_DIRS = [
    '/system/app/webview',
    '/system/app/WebViewGoogle',
]
SYSTEM_WEBVIEW_PACKAGE = 'com.google.android.webview'
SYSTEM_WEBVIEW_VMSIZE_BYTES = 250 * 1000 * 1000
TARGET_MAPPER = {
    '4560MMX': 'sprout',
    '4560MMX_b': 'sprout_b',
}
WIFI_UTIL_PACKAGE_NAME = 'com.android.tradefed.utils.wifi'
WIFI_UTIL_CALL_PATH = '%s/.WifiUtil' % WIFI_UTIL_PACKAGE_NAME

BATTERY_CHARGE_INTERVAL = 30 * 60  # 0.5 hour.
BATTERY_CHECK_INTERVAL = 15 * 60  # 15 minutes.
EXPECTED_BATTERY_LEVEL = 80  # A percentage.
EXPECTED_BATTERY_TEMPERATURE = 35.0  # Degrees Celsius.
LOW_BATTERY_LEVEL_THRESHOLD = 40  # A percentage.
MAX_BATTERY_TEMPERATURE_THRESHOLD = 37.0  # Don't change this or battery swells.

BUILD_PROP_MD5_KEY = 'android_build_prop_md5'
LAST_BATTERY_CHECK_TIME_KEY = 'android_last_battery_check'
LAST_FLASH_BUILD_KEY = 'android_last_flash'
LAST_FLASH_TIME_KEY = 'android_last_flash_time'
LAST_GMSCORE_UPDATE_BUILD_KEY = 'android_last_gmscore_update'
LAST_GMSCORE_UPDATE_TIME_KEY = 'android_last_gmscore_update_time'
LAST_TEST_ACCOUNT_CHECK_KEY = 'android_last_test_account_check'
SCHEDULED_GCE_REIMAGE_TIME_KEY = 'android_gce_reimage_time'
SW_MEDIA_CODECS_FILE = 'sw_media_codecs.xml'


def add_test_accounts_if_needed():
  """Add test account to work with GmsCore, etc."""
  last_test_account_check_time = persistent_cache.get_value(
      LAST_TEST_ACCOUNT_CHECK_KEY,
      constructor=datetime.datetime.utcfromtimestamp)
  needs_test_account_update = (
      last_test_account_check_time is None or dates.time_has_expired(
          last_test_account_check_time,
          seconds=ADD_TEST_ACCOUNT_CHECK_INTERVAL))
  if not needs_test_account_update:
    return

  config = db_config.get()
  test_account_email = config.test_account_email
  test_account_password = config.test_account_password
  if not test_account_email or not test_account_password:
    return

  adb.run_as_root()
  configure_wifi_and_airplane_mode(wifi_enabled=True)

  if not adb.is_package_installed(ADD_TEST_ACCOUNT_PKG_NAME):
    logs.log('Installing helper apk for adding test account.')
    android_directory = environment.get_platform_resources_directory()
    add_test_account_apk_path = os.path.join(android_directory,
                                             ADD_TEST_ACCOUNT_APK_NAME)
    adb.install_package(add_test_account_apk_path)

  logs.log('Trying to add test account.')
  output = adb.run_adb_shell_command(
      'am instrument -e account %s -e password %s -w %s/.AddAccount' %
      (test_account_email, test_account_password, ADD_TEST_ACCOUNT_PKG_NAME),
      timeout=ADD_TEST_ACCOUNT_TIMEOUT)
  if not output or test_account_email not in output:
    logs.log('Failed to add test account, probably due to wifi issues.')
    return

  logs.log('Test account added successfully.')
  persistent_cache.set_value(LAST_TEST_ACCOUNT_CHECK_KEY, time.time())


def clear_testcase_directory():
  """Clears testcase directory."""
  # Cleanup downloads folder on /sdcard.
  adb.remove_directory(adb.DEVICE_DOWNLOAD_DIR, recreate=True)

  # Cleanup testcase directory.
  adb.remove_directory(adb.DEVICE_TESTCASES_DIR, recreate=True)


def configure_device_settings():
  """Configures device settings for test environment."""
  # FIXME: We shouldn't need repeat invocation of this. We need to do this
  # in case previous invocations of any of the below commands failed.
  # Write our test environment settings in content database.
  adb.run_as_root()
  set_content_settings('com.google.settings/partner',
                       'use_location_for_services', 0)
  set_content_settings('settings/global', 'assisted_gps_enabled', 0)
  set_content_settings('settings/global', 'development_settings_enabled', 0)
  set_content_settings('settings/global', 'stay_on_while_plugged_in', 3)
  set_content_settings('settings/global', 'send_action_app_error', 0)
  set_content_settings('settings/global', 'verifier_verify_adb_installs', 0)
  set_content_settings('settings/global', 'wifi_scan_always_enabled', 0)
  set_content_settings('settings/secure', 'anr_show_background', 0)
  set_content_settings('settings/secure', 'doze_enabled', 0)
  set_content_settings('settings/secure', 'location_providers_allowed', '')
  set_content_settings('settings/secure', 'lockscreen.disabled', 1)
  set_content_settings('settings/secure', 'screensaver_enabled', 0)
  set_content_settings('settings/system', 'accelerometer_rotation', 0)
  set_content_settings('settings/system', 'auto_time', 0)
  set_content_settings('settings/system', 'auto_timezone', 0)
  set_content_settings('settings/system', 'lockscreen.disabled', 1)
  set_content_settings('settings/system', 'notification_light_pulse', 0)
  set_content_settings('settings/system', 'screen_brightness_mode', 0)
  set_content_settings('settings/system', 'screen_brightness', 1)
  set_content_settings('settings/system', 'user_rotation', 0)

  # The following line filled with magic numbers will set media volume to 0
  # 3 is the 3rd function in the IAudioServiceList and the following
  # i32's specify 32 bit integer arguments to the function
  adb.run_adb_shell_command('service call audio 3 i32 3 i32 0 i32 1')

  # FIXME: We shouldn't need repeat invocation of this. We need to do this
  # in case previous invocations of any of the below commands failed.
  # On certain device/Android configurations we need to disable the lock screen
  # in a different database. Additionally, the password type must be set to 0.
  adb.update_key_in_sqlite_db(LOCKSCREEN_DB, LOCKSCREEN_TABLE_NAME,
                              'lockscreen.disabled', 1)
  adb.update_key_in_sqlite_db(LOCKSCREEN_DB, LOCKSCREEN_TABLE_NAME,
                              'lockscreen.password_type', 0)
  adb.update_key_in_sqlite_db(LOCKSCREEN_DB, LOCKSCREEN_TABLE_NAME,
                              'lockscreen.password_type_alternate', 0)

  adb.disable_packages_that_crash_with_gestures()

  # Create a list of property name and names to be used in local.prop file.
  local_properties_settings_list = copy.deepcopy(LOCAL_PROP_SETTINGS)

  # Add debugging flags to local settings list so that they persist across
  # reboots.
  local_properties_settings_list += get_debug_props_and_values()

  # Write the local properties file settings.
  local_properties_file_contents = '\n'.join(local_properties_settings_list)
  adb.write_data_to_file(local_properties_file_contents, LOCAL_PROP_PATH)


def wait_for_battery_charge_if_needed():
  """Check device battery and make sure it is charged beyond minimum level and
  temperature thresholds."""
  # Make sure device is online.
  adb.wait_for_device()

  # We don't care about battery levels on GCE.
  if environment.get_value('ANDROID_GCE'):
    return

  # Skip battery check if done recently.
  last_battery_check_time = persistent_cache.get_value(
      LAST_BATTERY_CHECK_TIME_KEY,
      constructor=datetime.datetime.utcfromtimestamp)
  if last_battery_check_time and not dates.time_has_expired(
      last_battery_check_time, seconds=BATTERY_CHECK_INTERVAL):
    return

  # Initialize variables.
  battery_level_threshold = environment.get_value('LOW_BATTERY_LEVEL_THRESHOLD',
                                                  LOW_BATTERY_LEVEL_THRESHOLD)
  battery_temperature_threshold = environment.get_value(
      'MAX_BATTERY_TEMPERATURE_THRESHOLD', MAX_BATTERY_TEMPERATURE_THRESHOLD)
  device_restarted = False

  while 1:
    battery_information = get_battery_information()
    if battery_information is None:
      logs.log_error('Failed to get battery information, skipping check.')
      return

    battery_level = battery_information['level']
    battery_temperature = battery_information['temperature']
    logs.log('Battery information: level (%d%%), temperature (%.1f celsius).' %
             (battery_level, battery_temperature))
    if (battery_level >= battery_level_threshold and
        battery_temperature <= battery_temperature_threshold):
      persistent_cache.set_value(LAST_BATTERY_CHECK_TIME_KEY, time.time())
      return

    logs.log('Battery in bad battery state, putting device in sleep mode.')

    if not device_restarted:
      reboot()
      adb.disable_wifi()
      device_restarted = True

    # Change thresholds to expected levels (only if they were below minimum
    # thresholds).
    if battery_level < battery_level_threshold:
      battery_level_threshold = EXPECTED_BATTERY_LEVEL
    if battery_temperature > battery_temperature_threshold:
      battery_temperature_threshold = EXPECTED_BATTERY_TEMPERATURE

    # Stopping shell should help with shutting off a lot of services that would
    # otherwise use up the battery. However, we need to turn it back on to get
    # battery status information. Also, turn off display explicitly (needed for
    # Nexus 9s).
    turn_off_display_if_needed()
    adb.stop_shell()
    time.sleep(BATTERY_CHARGE_INTERVAL)
    adb.start_shell()


def configure_wifi_and_airplane_mode(wifi_enabled=False):
  """Configure airplane mode and wifi on device."""
  # Airplane mode should be disabled in all cases. This can get inadvertently
  # turned on via gestures.
  adb.disable_airplane_mode()

  # GCE uses Ethernet, nothing to do here.
  if environment.get_value('ANDROID_GCE'):
    return

  # Need to disable wifi before changing configuration.
  adb.disable_wifi()

  # Check if wifi needs to be enabled. If not, then no need to modify the
  # supplicant file.
  wifi_enabled = wifi_enabled or environment.get_value('WIFI', True)
  if not wifi_enabled:
    # No more work to do, we already disabled it at start.
    return

  config = db_config.get()
  if not config.wifi_ssid:
    # No wifi config is set, skip.
    return

  adb.enable_wifi()

  # Wait 2 seconds to allow the wifi to be enabled.
  time.sleep(2)

  wifi_util_apk_path = os.path.join(
      environment.get_platform_resources_directory(), 'wifi_util.apk')
  if not adb.is_package_installed(WIFI_UTIL_PACKAGE_NAME):
    adb.install_package(wifi_util_apk_path)

  connect_wifi_command = (
      'am instrument -e method connectToNetwork -e ssid {ssid} ')
  if config.wifi_password:
    connect_wifi_command += '-e psk {password} '
  connect_wifi_command += '-w {call_path}'

  output = adb.run_adb_shell_command(
      connect_wifi_command.format(
          ssid=quote(config.wifi_ssid),
          password=quote(config.wifi_password),
          call_path=WIFI_UTIL_CALL_PATH))
  if 'result=true' not in output:
    logs.log_error('Failed to connect to wifi.', output=output)


def get_api_level():
  """Return device's API level."""
  try:
    return int(adb.get_property('ro.build.version.sdk'))
  except ValueError:
    logs.log_error('Failed to fetch API level.')
    return -1


def get_artifact_name(apk_name, branch, branch_regex):
  """Fetch the apk to download depending on build type and screen density."""
  # Initialize variables.
  apk = ''
  api_level = get_api_level()
  build_type = get_build_type()
  screen_density = get_screen_density()

  # If unknown build type, return default.
  if build_type not in ['eng', 'user', 'userdebug']:
    logs.log_error('Unknown device build type %s.' % str(build_type))
    return apk_name + '.apk'

  # Format - [signed/signed-]<apk_name>[-<density>][-<version>].apk.
  # Prepend signed for user and eng builds.
  if build_type in ['eng', 'user']:
    apk += 'signed/signed-'
  apk += apk_name

  # Add density.
  if screen_density == 'xxxhdpi':
    apk += '-xxhdpi'
  elif screen_density in ('mdpi', 'hdpi', 'xhdpi', 'xxhdpi'):
    apk += '-' + screen_density
  else:
    logs.log_error('Unknown screen density %s.' % str(screen_density))

  # For LMP and above, append release codename only for manchego and above.
  # FIXME: Add support for pano if needed in future.
  if api_level >= 21:
    match = re.search(branch_regex, branch)
    if match and match.group(1) >= 'manchego':
      if api_level >= 23:
        apk += '-mnc'
      else:
        apk += '-lmp'

  # Finish with apk extension.
  apk += '.apk'
  return apk


def get_battery_information():
  """Return device's battery level."""
  output = adb.run_adb_shell_command(['dumpsys', 'battery'])

  # Get battery level.
  m_battery_level = re.match(r'.*level: (\d+).*', output, re.DOTALL)
  if not m_battery_level:
    logs.log_error('Error occurred while getting battery status.')
    return None

  # Get battery temperature.
  m_battery_temperature = re.match(r'.*temperature: (\d+).*', output, re.DOTALL)
  if not m_battery_temperature:
    logs.log_error('Error occurred while getting battery temperature.')
    return None

  level = int(m_battery_level.group(1))
  temperature = float(m_battery_temperature.group(1)) / 10.0
  return {'level': level, 'temperature': temperature}


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
  target = TARGET_MAPPER.get(target, target)
  build_type = build_fingerprint_match.group('type')
  return {'build_id': build_id, 'target': target, 'type': build_type}


def get_build_type():
  """Return build type."""
  return adb.get_property('ro.build.type')


def get_build_version():
  """Return the build version of the system as a character.
  K = Kitkat, L = Lollipop, M = Marshmellow, A = Master.
  """
  build_version = adb.get_property('ro.build.id')
  if not build_version or not re.match('^[A-Z]', build_version):
    return None

  return build_version[0]


def get_codename():
  """Return the device codename."""
  device_serial = environment.get_value('ANDROID_SERIAL')
  devices_output = adb.run_adb_command(['devices', '-l'])

  for line in devices_output.splitlines():
    values = line.strip().split()
    serial = values[0]

    if serial != device_serial:
      continue

    for value in values:
      if not value.startswith('device:'):
        continue
      device_codename = value.split(':')[-1]
      if device_codename:
        return device_codename

  # Unable to get code name.
  return ''


def get_cpu_arch():
  """Return cpu architecture."""
  return adb.get_property('ro.product.cpu.abi')


def get_kernel_log_content():
  """Return content of kernel logs."""
  kernel_log_content = ''
  for kernel_log_file in KERNEL_LOG_FILES:
    kernel_log_content += adb.read_data_from_file(kernel_log_file) or ''

  return kernel_log_content


def get_platform_id():
  """Return a string as |android:{codename}_{sanitizer}:{build_version}|."""
  platform_id = 'android'

  # Add codename and sanitizer tool information.
  platform_id += ':%s' % get_codename()
  sanitizer_tool_name = get_sanitizer_tool_name()
  if sanitizer_tool_name:
    platform_id += '_%s' % sanitizer_tool_name

  # Add build version.
  build_version = get_build_version()
  if build_version:
    platform_id += ':%s' % build_version

  return platform_id


def get_pid_for_script(script_name):
  """Get the pid of a running shell script."""
  output = adb.run_adb_shell_command("ps | grep ' sh'")
  pids = PS_REGEX.findall(output)
  for pid in pids:
    cmdline = adb.run_adb_shell_command('cat /proc/%s/cmdline' % pid)
    if script_name in cmdline:
      return pid

  return None


def get_product_brand():
  """Return product's brand."""
  return adb.get_property('ro.product.brand')


def get_screen_density():
  """Return screen density."""
  output = adb.get_property('ro.sf.lcd_density')
  if not output or not output.isdigit():
    return None

  output = int(output)
  if output == 120:
    return 'ldpi'
  elif output == 160:
    return 'mdpi'
  elif output == 240:
    return 'hdpi'
  elif output == 320:
    return 'xhdpi'
  elif output == 480:
    return 'xxhdpi'
  elif output == 560:
    return 'xxhdpi'
  elif output == 640:
    return 'xxxhdpi'

  logs.log_error('Could not determine the density of the device.')
  return None


def get_screen_dimensions():
  """Return device's screen dimensions."""
  window_policy = adb.run_adb_shell_command(['dumpsys', 'window', 'policy'])
  window_policy = window_policy.split('\r\n')

  for line in window_policy[1:]:
    m = re.search(r'mContent=\((\d+),(\d+)\)-\((\d+),(\d+)\)', line)
    if m:
      return (int(m.group(1)), int(m.group(2)), int(m.group(3)), int(
          m.group(4)))

  # Fallback to default dimensions.
  return (0, 0, 1920, 1200)


def get_security_patch_level():
  """Return the security patch level reported by the device."""
  return adb.get_property('ro.build.version.security_patch')


def get_target(target):
  """Return full target name for a given CPU arch."""
  if not target:
    logs.log_error('Target is not set.')
    return None

  cpu_arch = get_cpu_arch()
  arch_suffix = None
  if cpu_arch == 'armeabi-v7a':
    arch_suffix = ''
  elif cpu_arch == 'arm64-v8a':
    arch_suffix = '_arm64'
  elif cpu_arch == 'armeabi':
    arch_suffix = '_armv5'
  elif cpu_arch == 'x86':
    arch_suffix = '_x86'
  elif cpu_arch == 'x86_64':
    arch_suffix = '_x86_64'
  elif cpu_arch == 'mips':
    arch_suffix = '_mips'
  else:
    logs.log_error('Could not find suitable target for cpu arch %s.' % cpu_arch)
    return None

  return target + arch_suffix


def get_type_binding(value):
  """Return binding type for content setting."""
  if isinstance(value, bool):
    return 'b'
  if isinstance(value, float):
    return 'f'
  if isinstance(value, int):
    return 'i'
  if isinstance(value, long):
    return 'l'
  if isinstance(value, str):
    return 's'
  raise ValueError('Unsupported type %s' % type(value))


def initialize_device():
  """Prepares android device for app install."""
  # Set up ADB.
  adb.setup_adb()

  # General device configuration settings.
  configure_build_properties_if_needed()
  configure_device_settings()
  setup_software_decoders_if_needed()
  upgrade_gms_core_if_needed()

  # FIXME: This functionality is disabled until a user account is whitelisted so
  # as to not trigger GAIA alerts.
  add_test_accounts_if_needed()

  # Setup AddressSanitizer if needed.
  setup_asan_if_needed()

  # Reboot device as above steps would need it and also it brings device in a
  # good state.
  reboot()

  # Make sure we are running as root after restart.
  adb.run_as_root()

  # Setup helper environment for quick access to values like codename, etc.
  # This must be done after the reboot so that we get values from device in
  # a good state.
  initialize_environment()

  # Other configuration tasks (only to done after reboot).
  configure_coverage_directories()
  configure_wifi_and_airplane_mode()
  setup_host_and_device_forwarder_if_needed()
  adb.clear_notifications()
  adb.change_se_linux_to_permissive_mode()
  adb.wait_until_package_optimization_complete()
  unlock_screen_if_locked()

  # FIXME: Should we should revert back to regular user permission ?


def force_software_decoders_if_needed():
  """Forces android device to use software decoders."""
  # Return if the backup file already exists.
  if adb.file_exists(MEDIA_CODECS_CONFIG_BACKUP_PATH):
    return

  # Copy the original file so we can revert to it later.
  adb.run_as_root()
  adb.remount()
  adb.run_adb_shell_command(
      ['cp', MEDIA_CODECS_CONFIG_PATH, MEDIA_CODECS_CONFIG_BACKUP_PATH])

  # Push the new media codecs config file
  local_codecs_config_path = os.path.join(
      environment.get_platform_resources_directory(), SW_MEDIA_CODECS_FILE)
  adb.run_adb_command(
      ['push', local_codecs_config_path, MEDIA_CODECS_CONFIG_PATH])


def revert_software_decoders_if_needed():
  """Cleans up a forced switch to software decoders from a previous run."""
  # If the media_codecs.xml.orig file does not exist, we don't need to do
  # anything.
  if not adb.file_exists(MEDIA_CODECS_CONFIG_BACKUP_PATH):
    return

  # Otherwise, rename the file back to media_codecs.xml.
  adb.run_as_root()
  adb.remount()
  adb.run_adb_shell_command(
      ['mv', MEDIA_CODECS_CONFIG_BACKUP_PATH, MEDIA_CODECS_CONFIG_PATH])


def setup_software_decoders_if_needed():
  """Sets up software decoders if needed."""
  if environment.get_value('USE_SOFTWARE_DECODERS'):
    force_software_decoders_if_needed()
    return

  revert_software_decoders_if_needed()


def google_device():
  """Return true if this is a google branded device."""
  # If a build branch is already set, then this is a Google device. No need to
  # query device which can fail if the device is failing on recovery mode.
  build_branch = environment.get_value('BUILD_BRANCH')
  if build_branch:
    return True

  product_brand = environment.get_value('PRODUCT_BRAND', get_product_brand())
  if product_brand is None:
    return None

  if product_brand == 'google':
    return True

  if product_brand == 'generic' or environment.get_value('ANDROID_GCE'):
    return True

  return False


def configure_coverage_directories():
  """Configure coverage directories on device."""
  adb.remove_directory(adb.DEVICE_COVERAGE_DIR, recreate=True)
  default_device_coverage_subdirectory = (
      os.path.join(adb.DEVICE_COVERAGE_DIR, '0'))
  adb.create_directory_if_needed(default_device_coverage_subdirectory)


def get_debug_props_and_values():
  """Return debug property names and values based on |ENABLE_DEBUG_CHECKS|
  flag."""
  debug_props_and_values_list = []
  enable_debug_checks = environment.get_value('ENABLE_DEBUG_CHECKS', False)

  logs.log('Debug flags set to %s.' % str(enable_debug_checks))

  # Keep system and applications level asserts disabled since these can lead to
  # potential battery depletion issues.
  debug_props_and_values_list += [
      'dalvik.vm.enableassertions=',
      'debug.assert=0',
  ]

  # JNI checks. See this link for more information.
  # http://android-developers.blogspot.com/2011/07/debugging-android-jni-with-checkjni.html.
  check_jni_flag = (
      enable_debug_checks or environment.get_value('ENABLE_CHECK_JNI', False))
  debug_props_and_values_list += [
      'dalvik.vm.checkjni=%s' % str(check_jni_flag).lower(),
      'debug.checkjni=%d' % int(check_jni_flag),
  ]

  # Enable debug malloc if
  # a. This is not a sanitizer build and
  # b. We are not running a memory constrained device (like Android One).
  #
  # The following values are interesting for security testing.
  # 5  - For filling allocated / freed memory with patterns defined by
  #      CHK_SENTINEL_VALUE, and CHK_FILL_FREE macros.
  # 10 - For adding pre-, post- allocation stubs in order to detect overruns.
  # FIXME: We cannot use =10 since it enables memory leaks and causes device to
  # die within minutes. See b/19145921.
  # FIXME: Can't enable on samsung devices, boot loop on startup. b/25156326.
  device_codename = environment.get_value('DEVICE_CODENAME', get_codename())
  product_brand = environment.get_value('PRODUCT_BRAND', get_product_brand())
  debug_malloc_enabled = (
      enable_debug_checks and not get_sanitizer_tool_name() and
      device_codename not in MEMORY_CONSTRAINED_DEVICES and
      product_brand != 'samsung')

  # https://android.googlesource.com/platform/bionic/+/master/libc/malloc_debug/README.md
  if debug_malloc_enabled:
    build_version = get_build_version()
    if is_build_at_least(build_version, 'N'):
      # FIXME: See b/30068677. 'backtrace' and 'free_track' options are
      # extremely expensive. Skip them for now until performance issues
      # are resolved.
      debug_malloc_string = 'fill guard'
      debug_props_and_values_list += [
          'libc.debug.malloc.options=%s' % debug_malloc_string
      ]
    else:
      debug_malloc_level = 5
      debug_props_and_values_list += [
          'libc.debug.malloc=%d' % debug_malloc_level
      ]

  return debug_props_and_values_list


def get_sanitizer_tool_name():
  """Return sanitizer tool name e.g. ASAN if found on device."""
  if 'asan' in get_build_flavor():
    return 'asan'

  return ''


def get_sanitizer_options_file_path(sanitizer_tool_name):
  """Return path for the sanitizer options file."""
  # If this a full sanitizer system build, then update the options file in
  # /system, else just put it in device temp directory.
  sanitizer_directory = ('/system'
                         if get_sanitizer_tool_name() else adb.DEVICE_TMP_DIR)

  sanitizer_filename = SANITIZER_TOOL_TO_FILE_MAPPINGS[sanitizer_tool_name]
  return os.path.join(sanitizer_directory, sanitizer_filename)


def initialize_environment():
  """Set common environment variables for easy access."""
  environment.set_value('BUILD_FINGERPRINT', get_build_fingerprint())
  environment.set_value('BUILD_VERSION', get_build_version())
  environment.set_value('DEVICE_CODENAME', get_codename())
  environment.set_value('DEVICE_PATH', adb.get_device_path())
  environment.set_value('PLATFORM_ID', get_platform_id())
  environment.set_value('PRODUCT_BRAND', get_product_brand())
  environment.set_value('SANITIZER_TOOL_NAME', get_sanitizer_tool_name())
  environment.set_value('SCREEN_DIMENSIONS', str(get_screen_dimensions()))


def update_system_web_view():
  """Updates the system webview on the device."""
  app_directory = environment.get_value('APP_DIR')
  system_webview_apk = os.path.join(app_directory, SYSTEM_WEBVIEW_APK_NAME)
  if not os.path.exists(system_webview_apk):
    logs.log_error('System Webview apk not found.')
    return
  adb.set_property('persist.sys.webview.vmsize', SYSTEM_WEBVIEW_VMSIZE_BYTES)

  adb.run_as_root()
  if any([adb.directory_exists(d) for d in SYSTEM_WEBVIEW_DIRS]):
    adb.remount()
    adb.stop_shell()
    adb.run_adb_shell_command(['rm', '-rf', ' '.join(SYSTEM_WEBVIEW_DIRS)])
    reboot()

  adb.uninstall_package(SYSTEM_WEBVIEW_PACKAGE)
  adb.install_package(system_webview_apk)

  if not adb.is_package_installed(SYSTEM_WEBVIEW_PACKAGE):
    logs.log_error(
        'Package %s was not installed successfully.' % SYSTEM_WEBVIEW_PACKAGE)


def install_application_if_needed(apk_path, force_update):
  """Install application package if it does not exist on device
  or if force_update is set."""
  # Make sure that apk exists and has non-zero size. Otherwise, it means we
  # are using a system package that we just want to fuzz, but not care about
  # installation.
  if (not apk_path or not os.path.exists(apk_path) or
      not os.path.getsize(apk_path)):
    return

  # If we don't have a package name, we can't uninstall the app. This is needed
  # for installation workflow.
  package_name = adb.get_package_name()
  if not package_name:
    return

  # Add |REINSTALL_APP_BEFORE_EACH_TASK| to force update decision.
  reinstall_app_before_each_task = environment.get_value(
      'REINSTALL_APP_BEFORE_EACH_TASK', False)
  force_update = force_update or reinstall_app_before_each_task

  # Install application if it is not found in the device's
  # package list or force_update flag has been set.
  if force_update or not adb.is_package_installed(package_name):
    # Update system webview when fuzzing webview shell apk.
    if package_name == 'org.chromium.webview_shell':
      update_system_web_view()

    adb.uninstall_package(package_name)
    adb.install_package(apk_path)

    if not adb.is_package_installed(package_name):
      logs.log_error(
          'Package %s was not installed successfully.' % package_name)
      return

    logs.log('Package %s is successfully installed using apk %s.' %
             (package_name, apk_path))

  adb.reset_application_state()


def push_testcases_to_device():
  """Pushes testcases from local fuzz directory onto device."""
  # Attempt to ensure that the local state is the same as the state on the
  # device by clearing existing files on device before pushing.
  clear_testcase_directory()

  local_testcases_directory = environment.get_value('FUZZ_INPUTS')
  if not os.listdir(local_testcases_directory):
    # Directory is empty, nothing to push.
    logs.log('No testcases to copy to device, skipping.')
    return

  logs.log('Started copying testcases to device.')
  adb.copy_local_directory_to_remote(local_testcases_directory,
                                     adb.DEVICE_TESTCASES_DIR)

  logs.log('Completed copying testcases to device.')


def reboot():
  """Reboots device and clear config state."""
  # Make sure to clear logcat before reboot occurs. In case of kernel crashes,
  # we use the log before reboot, so it is good to clear it when we are doing
  # the reboot explicitly.
  logger.clear_log()

  # Reboot.
  logs.log('Rebooting device.')
  adb.reboot()

  # Wait for boot to complete.
  adb.wait_until_fully_booted()

  # Start memory monitor script to prevent out-of-memory scenarios.
  setup_memory_monitor_script_if_needed()


def setup_asan_if_needed():
  """Sets the asan.options device property."""
  if not environment.get_value('ASAN_DEVICE_SETUP'):
    # Only do this step if explicitly enabled in the job type. This cannot be
    # determined from libraries in application directory since they can go
    # missing in a bad build, so we want to catch that.
    return

  if get_sanitizer_tool_name():
    # If this is a sanitizer build, no need to setup ASAN (incompatible).
    return

  app_directory = environment.get_value('APP_DIR')
  if not app_directory:
    # No app directory -> No ASAN runtime library. No work to do, bail out.
    return

  # Initialize variables.
  android_directory = environment.get_platform_resources_directory()
  asan_rt_arch32_lib = ASAN_RT_LIB.format(arch=ARCH32_ID)
  asan_rt_arch64_lib = ASAN_RT_LIB.format(arch=ARCH64_ID)
  cpu_arch = get_cpu_arch()
  device_id = environment.get_value('ANDROID_SERIAL')
  file_list = os.listdir(app_directory)

  # Hack for missing arm64 lib in older builds.
  if (cpu_arch.startswith('arm64') and asan_rt_arch32_lib in file_list and
      asan_rt_arch64_lib not in file_list):
    # Copy arm64 library from local copy.
    source_asan_rt_arch64_lib = os.path.join(android_directory,
                                             asan_rt_arch64_lib)
    dest_asan_rt_arch64_lib = os.path.join(app_directory, asan_rt_arch64_lib)
    shell.copy_file(source_asan_rt_arch64_lib, dest_asan_rt_arch64_lib)

  # Execute the script.
  logs.log('Executing ASan device setup script.')
  asan_device_setup_script_path = os.path.join(android_directory, 'third_party',
                                               'asan_device_setup.sh')
  asan_runtime_library_argument = '--lib %s' % app_directory
  device_argument = '--device %s' % device_id
  asan_options_file_path = get_sanitizer_options_file_path('ASAN')
  extra_asan_options = (
      '--extra-options include_if_exists=%s' % asan_options_file_path)
  command = '%s %s %s %s' % (asan_device_setup_script_path, device_argument,
                             asan_runtime_library_argument, extra_asan_options)
  adb.execute_command(command, timeout=ASAN_SCRIPT_TIMEOUT)


def set_content_settings(table, key, value):
  """Set a device content setting."""
  content_setting_command = (
      'content insert --uri content://%s --bind name:s:%s --bind value:%s:%s' %
      (table, key, get_type_binding(value), str(value)))

  adb.run_adb_shell_command(content_setting_command)


def set_sanitizer_options_if_needed(sanitizer_tool_name, sanitizer_options):
  """Sets up sanitizer options on the disk file."""
  sanitizer_options_file_path = get_sanitizer_options_file_path(
      sanitizer_tool_name)
  adb.write_data_to_file(sanitizer_options, sanitizer_options_file_path)


def setup_host_and_device_forwarder_if_needed():
  """Sets up http(s) forwarding between device and host."""
  # Android GCE devices connect directly to host ips, no need for forwarding.
  if environment.get_value('ANDROID_GCE'):
    return

  # Get list of ports to map.
  http_port_1 = environment.get_value('HTTP_PORT_1', 8000)
  http_port_2 = environment.get_value('HTTP_PORT_2', 8080)
  https_port_1 = environment.get_value('HTTPS_PORT_1', 8443)
  ports = [http_port_1, http_port_2, https_port_1]

  # Reverse map socket connections from device to host machine.
  for port in ports:
    port_string = 'tcp:%d' % port
    adb.run_adb_command(['reverse', port_string, port_string])


def setup_memory_monitor_script_if_needed():
  """Run check_process_mem.sh to monitor the memory usage"""
  # No need to run this script if it's an Android GCE device.
  if environment.get_value('ANDROID_GCE'):
    return

  # The script should only start if this is a low end device.
  device_codename = environment.get_value('DEVICE_CODENAME', get_codename())
  if device_codename not in MEMORY_CONSTRAINED_DEVICES:
    return

  adb.run_as_root()

  if get_pid_for_script(MEMORY_MONITOR_SCRIPT):
    # The script is already running, no work to do.
    return

  android_directory = environment.get_platform_resources_directory()
  script_host_path = os.path.join(android_directory, MEMORY_MONITOR_SCRIPT)
  script_device_path = os.path.join(adb.DEVICE_TMP_DIR, MEMORY_MONITOR_SCRIPT)

  # Push memory monitor script onto device and make it executable (if needed).
  if not adb.file_exists(script_device_path):
    adb.run_adb_command(['push', script_host_path, adb.DEVICE_TMP_DIR])
    adb.run_adb_shell_command(['chmod', '0755', script_device_path])

  # Run the memory monitor script.
  adb.run_adb_shell_command(
      'sh %s 2>/dev/null 1>/dev/null &' % script_device_path)

  # Wait one second to allow the script to run.
  time.sleep(1)

  # Change the priority of the process so that it will not be easily killed
  # by lowmemorykiller.
  pid = get_pid_for_script(MEMORY_MONITOR_SCRIPT)
  if not pid:
    logs.log_error('Memory monitor script failed to run.')
    return
  adb.run_adb_shell_command('echo -1000 \\> /proc/%s/oom_score_adj' % pid)
  adb.run_adb_shell_command('echo 0 \\> /proc/%s/oom_score' % pid)
  adb.run_adb_shell_command('echo -17 \\> /proc/%s/oom_adj' % pid)


def turn_off_display_if_needed():
  """Turn off the device screen if needed."""
  power_dump_output = adb.run_adb_shell_command(['dumpsys', 'power'])
  if SCREEN_ON_SEARCH_STRING not in power_dump_output:
    # Screen display is already off, no work to do.
    return

  adb.run_adb_shell_command(['input', 'keyevent', 'KEYCODE_POWER'])


def unlock_screen_if_locked():
  """Unlocks the screen if it is locked."""
  window_dump_output = adb.run_adb_shell_command(['dumpsys', 'window'])
  if SCREEN_LOCK_SEARCH_STRING not in window_dump_output:
    # Screen is not locked, no work to do.
    return

  # Quick power on and off makes this more reliable.
  adb.run_adb_shell_command(['input', 'keyevent', 'KEYCODE_POWER'])
  adb.run_adb_shell_command(['input', 'keyevent', 'KEYCODE_POWER'])

  # This key does the unlock.
  adb.run_adb_shell_command(['input', 'keyevent', 'KEYCODE_MENU'])

  # Artifical delay to let the unlock to complete.
  time.sleep(1)


def upgrade_gms_core_if_needed():
  """Upgrades GmsCore to latest stable build if needed."""
  # Local development script does not have access to build apiary credentials,
  # so we cannot fetch latest gmscore artifact.
  if environment.get_value('LOCAL_DEVELOPMENT'):
    return

  # FIXME: Add support for GMSCore update for N and higher. These builds are no
  # longer stored on build apiary.
  build_version = get_build_version()
  if is_build_at_least(build_version, 'N'):
    return

  # Check if an update is needed based on last recorded GmsCore update time.
  last_gmscore_update_time = persistent_cache.get_value(
      LAST_GMSCORE_UPDATE_TIME_KEY,
      constructor=datetime.datetime.utcfromtimestamp)
  needs_gmscore_update = (
      last_gmscore_update_time is None or dates.time_has_expired(
          last_gmscore_update_time, seconds=GMSCORE_UPDATE_INTERVAL))
  if not needs_gmscore_update:
    return

  # FIXME: Deprecate this and support properly for newer android releases.
  branch = GMSCORE_BRANCH
  target = get_target(GMSCORE_TARGET)  # Get full name with architecture.
  if not target:
    logs.log_error('Failed to get full target name for GmsCore upgrade.')
    return

  # Get full artifact name with codename, screen density, etc information.
  artifact_name = get_artifact_name(GMSCORE_APK_NAME, branch,
                                    GMSCORE_BRANCH_REGEX)

  # Download the latest build artifact for this branch and target.
  signed = 'signed' in artifact_name
  build_info = fetch_artifact.get_latest_artifact_info(
      branch, target, signed=signed)
  if not build_info:
    logs.log_error('Unable to fetch information on latest build artifact for '
                   'branch %s and target %s.' % (branch, target))
    return
  build_id = build_info['bid']
  target = build_info['target']

  # Check if we already tried once installing the same version of GmsCore.
  last_build_info = persistent_cache.get_value(LAST_GMSCORE_UPDATE_BUILD_KEY)
  if last_build_info and last_build_info['bid'] == build_id:
    logs.log('GmsCore version hasn\'t changed, nothing to upgrade.')
    return

  # Remove existing artifact first.
  builds_directory = environment.get_value('BUILDS_DIR')
  gmscore_apk_path = os.path.join(builds_directory, artifact_name)
  if os.path.exists(gmscore_apk_path):
    os.remove(gmscore_apk_path)

  # Fetch the GmsCore apk now.
  gmscore_apk_path = fetch_artifact.get(build_id, target, artifact_name,
                                        builds_directory)
  if not os.path.exists(gmscore_apk_path):
    logs.log_error(
        'Failed to download GmsCore artifact %s for '
        'branch %s and target %s.' % (gmscore_apk_path, branch, target))
    return

  logs.log('Installing GmsCore build %s for branch %s, target %s.' %
           (str(build_id), branch, target))
  adb.run_as_root()
  adb.install_package(gmscore_apk_path)

  persistent_cache.set_value(LAST_GMSCORE_UPDATE_BUILD_KEY, build_info)
  persistent_cache.set_value(LAST_GMSCORE_UPDATE_TIME_KEY, time.time())


def flash_to_latest_build_if_needed():
  """Wipes user data, resetting the device to original factory state."""
  run_timeout = environment.get_value('RUN_TIMEOUT')
  if run_timeout:
    # If we have a run timeout, then we are already scheduled to bail out and
    # will be probably get re-imaged. E.g. using frameworks like Tradefed.
    return

  # Check if a flash is needed based on last recorded flash time.
  last_flash_time = persistent_cache.get_value(
      LAST_FLASH_TIME_KEY, constructor=datetime.datetime.utcfromtimestamp)
  needs_flash = last_flash_time is None or dates.time_has_expired(
      last_flash_time, seconds=adb.FLASH_INTERVAL)
  if not needs_flash:
    return

  build_info = {}
  is_remote_device = environment.get_value('ANDROID_GCE')
  if is_remote_device:
    # To prevent thousands of devices all trying to reimage at the same time,
    # reimages are done at a random time in the future.
    scheduled_reimage_time = persistent_cache.get_value(
        SCHEDULED_GCE_REIMAGE_TIME_KEY,
        constructor=datetime.datetime.utcfromtimestamp)

    if scheduled_reimage_time is None:
      # No reimage scheduled yet, so we need to do so.
      delay = random.randint(0, 3600)
      reimage_time = int(time.time()) + delay
      logs.log('Scheduling a new reimage in %d seconds.' % delay)
      persistent_cache.set_value(SCHEDULED_GCE_REIMAGE_TIME_KEY, reimage_time)
      return

    current_time = datetime.datetime.utcnow()
    if current_time < scheduled_reimage_time:
      time_left = scheduled_reimage_time - current_time
      # Not yet time for the reimage.
      logs.log('Scheduled reimage in %d seconds.' % time_left.seconds)
      return

    # Recreating the virtual device will reimage this to the latest image
    # available (with retry logic).
    logs.log('Reimaging device to latest image.')
    if not adb.recreate_virtual_device():
      logs.log_error('Unable to recreate virtual device. Reimaging failed.')
      adb.bad_state_reached()

  else:
    is_google_device = google_device()
    if google_device() is None:
      logs.log_error('Unable to query device. Reimaging failed.')
      adb.bad_state_reached()

    if not is_google_device:
      # We can't reimage these, skip.
      logs.log('Non-Google device found, skipping reimage.')
      return

    else:
      # For Google devices.
      # Check if both |BUILD_BRANCH| and |BUILD_TARGET| environment variables
      # are set. If not, we don't have enough data for reimaging and hence
      # we bail out.
      branch = environment.get_value('BUILD_BRANCH')
      target = environment.get_value('BUILD_TARGET')
      if not target:
        # We default to userdebug configuration.
        build_params = get_build_parameters()
        if build_params:
          target = build_params.get('target') + '-userdebug'

          # Cache target in environment. This is also useful for cases when
          # device is bricked and we don't have this information available.
          environment.set_value('BUILD_TARGET', target)

      if not branch or not target:
        return

      # Download the latest build artifact for this branch and target.
      build_info = fetch_artifact.get_latest_artifact_info(branch, target)
      if not build_info:
        logs.log_error(
            'Unable to fetch information on latest build artifact for '
            'branch %s and target %s.' % (branch, target))
        return

      # Check if our local build matches the latest build. If not, we will
      # download it.
      build_id = build_info['bid']
      target = build_info['target']
      image_directory = environment.get_value('IMAGES_DIR')
      last_build_info = persistent_cache.get_value(LAST_FLASH_BUILD_KEY)
      if not last_build_info or last_build_info['bid'] != build_id:
        # Clean up the images directory first.
        shell.remove_directory(image_directory, recreate=True)

        # We have a new build, download the build artifacts for it.
        for image_regex in FLASH_IMAGE_REGEXES:
          image_file_path = fetch_artifact.get(build_id, target, image_regex,
                                               image_directory)
          if not image_file_path:
            logs.log_error(
                'Failed to download image artifact %s for '
                'branch %s and target %s.' % (image_file_path, branch, target))
            return
          if image_file_path.endswith('.zip'):
            archive.unpack(image_file_path, image_directory)

      # We do one device flash at a time on one host, otherwise we run into
      # failures and device being stuck in a bad state.
      flash_lock_key_name = 'flash:%s' % socket.gethostname()
      if not locks.acquire_lock(flash_lock_key_name, by_zone=True):
        logs.log_error('Failed to acquire lock for reimaging, exiting.')
        return

      logs.log('Reimaging started.')
      logs.log('Rebooting into bootloader mode.')
      for _ in xrange(FLASH_RETRIES):
        adb.run_as_root()
        adb.run_adb_command(['reboot-bootloader'])
        time.sleep(FLASH_REBOOT_BOOTLOADER_WAIT)
        adb.run_fastboot_command(['oem', 'off-mode-charge', '0'])
        adb.run_fastboot_command(['-w', 'reboot-bootloader'])

        for partition, partition_image_filename in FLASH_IMAGE_FILES:
          partition_image_file_path = os.path.join(image_directory,
                                                   partition_image_filename)
          adb.run_fastboot_command(
              ['flash', partition, partition_image_file_path])
          if partition in ['bootloader', 'radio']:
            adb.run_fastboot_command(['reboot-bootloader'])
        adb.run_fastboot_command('reboot')
        time.sleep(FLASH_REBOOT_WAIT)

        if adb.get_device_state() == 'device':
          break
        logs.log_error('Reimaging failed, retrying.')

      locks.release_lock(flash_lock_key_name, by_zone=True)

  if adb.get_device_state() != 'device':
    logs.log_error('Unable to find device. Reimaging failed.')
    adb.bad_state_reached()

  logs.log('Reimaging finished.')

  # Reset all of our persistent keys after wipe.
  persistent_cache.delete_value(BUILD_PROP_MD5_KEY)
  persistent_cache.delete_value(LAST_GMSCORE_UPDATE_BUILD_KEY)
  persistent_cache.delete_value(LAST_GMSCORE_UPDATE_TIME_KEY)
  persistent_cache.delete_value(LAST_TEST_ACCOUNT_CHECK_KEY)
  persistent_cache.set_value(LAST_FLASH_BUILD_KEY, build_info)
  persistent_cache.set_value(LAST_FLASH_TIME_KEY, time.time())

  if is_remote_device:
    persistent_cache.delete_value(SCHEDULED_GCE_REIMAGE_TIME_KEY)


def configure_build_properties_if_needed():
  """Edits /system/build.prop for better boot speed and power use."""
  # Check md5 checksum of build.prop to see if already updated,
  # in which case exit. If build.prop does not exist, something
  # is very wrong with the device, so bail.
  old_md5 = persistent_cache.get_value(BUILD_PROP_MD5_KEY)
  current_md5 = adb.get_file_checksum(BUILD_PROP_PATH)
  if current_md5 is None:
    logs.log_error('Unable to find %s on device.' % BUILD_PROP_PATH)
    return
  if old_md5 == current_md5:
    return

  # Pull to tmp file.
  bot_tmp_directory = environment.get_value('BOT_TMPDIR')
  old_build_prop_path = os.path.join(bot_tmp_directory, 'old.prop')
  adb.run_adb_command(['pull', BUILD_PROP_PATH, old_build_prop_path])
  if not os.path.exists(old_build_prop_path):
    logs.log_error('Unable to fetch %s from device.' % BUILD_PROP_PATH)
    return

  # Write new build.prop.
  new_build_prop_path = os.path.join(bot_tmp_directory, 'new.prop')
  old_build_prop_file_content = open(old_build_prop_path, 'r')
  new_build_prop_file_content = open(new_build_prop_path, 'w')
  new_content_notification = '### CHANGED OR ADDED PROPERTIES ###'
  for line in old_build_prop_file_content:
    property_name = line.split('=')[0].strip()
    if property_name in BUILD_PROPERTIES:
      continue
    if new_content_notification in line:
      continue
    new_build_prop_file_content.write(line)

  new_build_prop_file_content.write(new_content_notification + '\n')
  for flag, value in BUILD_PROPERTIES.iteritems():
    new_build_prop_file_content.write('%s=%s\n' % (flag, value))
  old_build_prop_file_content.close()
  new_build_prop_file_content.close()

  # Keep verified boot disabled for M and higher releases. This makes it easy
  # to modify system's app_process to load asan libraries.
  build_version = get_build_version()
  if is_build_at_least(build_version, 'M'):
    adb.run_as_root()
    adb.run_adb_command('disable-verity')
    reboot()

  # Make /system writable.
  adb.run_as_root()
  adb.remount()

  # Remove seccomp policies (on N and higher) as ASan requires extra syscalls.
  if is_build_at_least(build_version, 'N'):
    policy_files = adb.run_adb_shell_command(
        ['find', '/system/etc/seccomp_policy/', '-type', 'f'])
    for policy_file in policy_files.splitlines():
      adb.run_adb_shell_command(['rm', policy_file.strip()])

  # Remove Google Plus app from non-Google devices. Makes it easy to install
  # older Gallery app on these devices. Otherwise, we run into duplicate
  # permission errors.
  if not google_device():
    adb.run_adb_shell_command(['rm', '/system/app/PlusOne.apk'])
    adb.run_adb_shell_command(['rm', '/system/app/PlusOne/PlusOne.apk'])

  # Push new build.prop and backup to device.
  logs.log('Pushing new build properties file on device.')
  adb.run_adb_command(
      ['push', '-p', old_build_prop_path, BUILD_PROP_BACKUP_PATH])
  adb.run_adb_command(['push', '-p', new_build_prop_path, BUILD_PROP_PATH])
  adb.run_adb_shell_command(['chmod', '644', BUILD_PROP_PATH])

  # Set persistent cache key containing and md5sum.
  current_md5 = adb.get_file_checksum(BUILD_PROP_PATH)
  persistent_cache.set_value(BUILD_PROP_MD5_KEY, current_md5)


def is_build_at_least(current_version, other_version):
  """Returns whether or not |current_version| is at least as new as
  |other_version|."""
  if current_version is None:
    return False

  # Special-cases for master builds.
  if current_version == 'A':
    # If the current build is master, we consider it at least as new as any
    # other.
    return True

  if other_version == 'A':
    # Since this build is not master, it is not at least as new as master.
    return False

  return current_version >= other_version
