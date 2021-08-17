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
import os
import time

import six

from clusterfuzz._internal.base import dates
from clusterfuzz._internal.base import persistent_cache
from clusterfuzz._internal.config import db_config
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment

from . import adb
from . import app
from . import constants
from . import logger
from . import sanitizer
from . import settings
from . import ui
from . import wifi

# Variables related to adding test account on device.
ADD_TEST_ACCOUNT_APK_NAME = 'user_account_setup.apk'
ADD_TEST_ACCOUNT_CHECK_INTERVAL = 1 * 24 * 60 * 60
ADD_TEST_ACCOUNT_PKG_NAME = 'com.google.android.tests.utilities'
ADD_TEST_ACCOUNT_CALL_PATH = '%s/.AddAccount' % ADD_TEST_ACCOUNT_PKG_NAME
ADD_TEST_ACCOUNT_TIMEOUT = 20

# System build properties related vars.
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

# Local development settings related vars.
LOCAL_PROP_PATH = '/data/local.prop'
LOCAL_PROP_SETTINGS = [
    'ro.audio.silent=1',
    'ro.monkey=1',
    'ro.setupwizard.mode=DISABLED',
    'ro.test_harness=1',
    'ro.telephony.disable-call=true',
]

# Lockscreen database settings related vars.
LOCKSCREEN_DB = '/data/system/locksettings.db'
LOCKSCREEN_TABLE_NAME = 'locksettings'


def add_test_accounts_if_needed():
  """Add test account to work with GmsCore, etc."""
  last_test_account_check_time = persistent_cache.get_value(
      constants.LAST_TEST_ACCOUNT_CHECK_KEY,
      constructor=datetime.datetime.utcfromtimestamp)
  needs_test_account_update = (
      last_test_account_check_time is None or dates.time_has_expired(
          last_test_account_check_time,
          seconds=ADD_TEST_ACCOUNT_CHECK_INTERVAL))
  if not needs_test_account_update:
    return

  config = db_config.get()
  if not config:
    return

  test_account_email = config.test_account_email
  test_account_password = config.test_account_password
  if not test_account_email or not test_account_password:
    return

  adb.run_as_root()
  wifi.configure(force_enable=True)

  if not app.is_installed(ADD_TEST_ACCOUNT_PKG_NAME):
    logs.log('Installing helper apk for adding test account.')
    android_directory = environment.get_platform_resources_directory()
    add_test_account_apk_path = os.path.join(android_directory,
                                             ADD_TEST_ACCOUNT_APK_NAME)
    app.install(add_test_account_apk_path)

  logs.log('Trying to add test account.')
  output = adb.run_shell_command(
      'am instrument -e account %s -e password %s -w %s' %
      (test_account_email, test_account_password, ADD_TEST_ACCOUNT_CALL_PATH),
      timeout=ADD_TEST_ACCOUNT_TIMEOUT)
  if not output or test_account_email not in output:
    logs.log('Failed to add test account, probably due to wifi issues.')
    return

  logs.log('Test account added successfully.')
  persistent_cache.set_value(constants.LAST_TEST_ACCOUNT_CHECK_KEY, time.time())


def clear_temp_directories():
  """Clear temp directories."""
  adb.remove_directory(constants.DEVICE_DOWNLOAD_DIR, recreate=True)
  adb.remove_directory(constants.DEVICE_TMP_DIR, recreate=True)
  adb.remove_directory(constants.DEVICE_FUZZING_DIR, recreate=True)


def clear_testcase_directory():
  """Clears testcase directory."""
  adb.remove_directory(constants.DEVICE_TESTCASES_DIR, recreate=True)


def configure_device_settings():
  """Configures device settings for test environment."""
  adb.run_as_root()

  # The following line filled with magic numbers will set media volume to 0
  # 3 is the 3rd function in the IAudioServiceList and the following
  # i32's specify 32 bit integer arguments to the function
  adb.run_shell_command('service call audio 3 i32 3 i32 0 i32 1')

  # FIXME: We shouldn't need repeat invocation of this. We need to do this
  # in case previous invocations of any of the below commands failed.
  # Write our test environment settings in content database.
  settings.set_content_setting('com.google.settings/partner',
                               'use_location_for_services', 0)
  settings.set_content_setting('settings/global', 'assisted_gps_enabled', 0)
  settings.set_content_setting('settings/global',
                               'development_settings_enabled', 0)
  settings.set_content_setting('settings/global', 'stay_on_while_plugged_in', 3)
  settings.set_content_setting('settings/global', 'send_action_app_error', 0)
  settings.set_content_setting('settings/global',
                               'verifier_verify_adb_installs', 0)
  settings.set_content_setting('settings/global', 'wifi_scan_always_enabled', 0)
  settings.set_content_setting('settings/secure', 'anr_show_background', 0)
  settings.set_content_setting('settings/secure', 'doze_enabled', 0)
  settings.set_content_setting('settings/secure', 'location_providers_allowed',
                               '')
  settings.set_content_setting('settings/secure', 'lockscreen.disabled', 1)
  settings.set_content_setting('settings/secure', 'screensaver_enabled', 0)
  settings.set_content_setting('settings/system', 'accelerometer_rotation', 0)
  settings.set_content_setting('settings/system', 'auto_time', 0)
  settings.set_content_setting('settings/system', 'auto_timezone', 0)
  settings.set_content_setting('settings/system', 'lockscreen.disabled', 1)
  settings.set_content_setting('settings/system', 'notification_light_pulse', 0)
  settings.set_content_setting('settings/system', 'screen_brightness_mode', 0)
  settings.set_content_setting('settings/system', 'screen_brightness', 1)
  settings.set_content_setting('settings/system', 'user_rotation', 0)

  # On certain device/Android configurations we need to disable the lock screen
  # in a different database. Additionally, the password type must be set to 0.
  settings.set_database_setting(LOCKSCREEN_DB, LOCKSCREEN_TABLE_NAME,
                                'lockscreen.disabled', 1)
  settings.set_database_setting(LOCKSCREEN_DB, LOCKSCREEN_TABLE_NAME,
                                'lockscreen.password_type', 0)
  settings.set_database_setting(LOCKSCREEN_DB, LOCKSCREEN_TABLE_NAME,
                                'lockscreen.password_type_alternate', 0)

  app.disable_packages_that_crash_with_gestures()

  # Create a list of property name and names to be used in local.prop file.
  local_properties_settings_list = copy.deepcopy(LOCAL_PROP_SETTINGS)

  # Add debugging flags to local settings list so that they persist across
  # reboots.
  local_properties_settings_list += get_debug_props_and_values()

  # Write the local properties file settings.
  local_properties_file_contents = '\n'.join(local_properties_settings_list)
  adb.write_data_to_file(local_properties_file_contents, LOCAL_PROP_PATH)


def configure_system_build_properties():
  """Modifies system build properties in /system/build.prop for better boot
  speed and power use."""
  adb.run_as_root()

  # Check md5 checksum of build.prop to see if already updated,
  # in which case exit. If build.prop does not exist, something
  # is very wrong with the device, so bail.
  old_md5 = persistent_cache.get_value(constants.BUILD_PROP_MD5_KEY)
  current_md5 = adb.get_file_checksum(BUILD_PROP_PATH)
  if current_md5 is None:
    logs.log_error('Unable to find %s on device.' % BUILD_PROP_PATH)
    return
  if old_md5 == current_md5:
    return

  # Pull to tmp file.
  bot_tmp_directory = environment.get_value('BOT_TMPDIR')
  old_build_prop_path = os.path.join(bot_tmp_directory, 'old.prop')
  adb.run_command(['pull', BUILD_PROP_PATH, old_build_prop_path])
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
  for flag, value in six.iteritems(BUILD_PROPERTIES):
    new_build_prop_file_content.write('%s=%s\n' % (flag, value))
  old_build_prop_file_content.close()
  new_build_prop_file_content.close()

  # Keep verified boot disabled for M and higher releases. This makes it easy
  # to modify system's app_process to load asan libraries.
  build_version = settings.get_build_version()
  if is_build_at_least(build_version, 'M'):
    adb.run_as_root()
    adb.run_command('disable-verity')
    reboot()

  # Make /system writable.
  adb.run_as_root()
  adb.remount()

  # Remove seccomp policies (on N and higher) as ASan requires extra syscalls.
  if is_build_at_least(build_version, 'N'):
    policy_files = adb.run_shell_command(
        ['find', '/system/etc/seccomp_policy/', '-type', 'f'])
    for policy_file in policy_files.splitlines():
      adb.run_shell_command(['rm', policy_file.strip()])

  # Push new build.prop and backup to device.
  logs.log('Pushing new build properties file on device.')
  adb.run_command(['push', '-p', old_build_prop_path, BUILD_PROP_BACKUP_PATH])
  adb.run_command(['push', '-p', new_build_prop_path, BUILD_PROP_PATH])
  adb.run_shell_command(['chmod', '644', BUILD_PROP_PATH])

  # Set persistent cache key containing and md5sum.
  current_md5 = adb.get_file_checksum(BUILD_PROP_PATH)
  persistent_cache.set_value(constants.BUILD_PROP_MD5_KEY, current_md5)


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

  is_build_supported = is_build_at_least(settings.get_build_version(), 'N')
  debug_malloc_enabled = (
      enable_debug_checks and is_build_supported and
      not settings.get_sanitizer_tool_name())

  # https://android.googlesource.com/platform/bionic/+/master/libc/malloc_debug/README.md
  if debug_malloc_enabled:
    # FIXME: 'free_track' is very crashy. Skip for now.
    debug_malloc_string = 'fill guard'
    debug_props_and_values_list += [
        'libc.debug.malloc.options=%s' % debug_malloc_string
    ]

  return debug_props_and_values_list


def initialize_device():
  """Prepares android device for app install."""
  if environment.is_engine_fuzzer_job() or environment.is_kernel_fuzzer_job():
    # These steps are not applicable to libFuzzer and syzkaller jobs and can
    # brick a device on trying to configure device build settings.
    return

  adb.setup_adb()

  # General device configuration settings.
  configure_system_build_properties()
  configure_device_settings()
  add_test_accounts_if_needed()

  # Setup AddressSanitizer if needed.
  sanitizer.setup_asan_if_needed()

  # Reboot device as above steps would need it and also it brings device in a
  # good state.
  reboot()

  # Make sure we are running as root after restart.
  adb.run_as_root()

  # Other configuration tasks (only to done after reboot).
  wifi.configure()
  setup_host_and_device_forwarder_if_needed()
  settings.change_se_linux_to_permissive_mode()
  app.wait_until_optimization_complete()
  ui.clear_notifications()
  ui.unlock_screen()

  # FIXME: Should we should revert back to regular user permission ?


def initialize_environment():
  """Set common environment variables for easy access."""
  environment.set_value('BUILD_FINGERPRINT', settings.get_build_fingerprint())
  environment.set_value('BUILD_VERSION', settings.get_build_version())
  environment.set_value('DEVICE_CODENAME', settings.get_device_codename())
  environment.set_value('DEVICE_PATH', adb.get_device_path())
  environment.set_value('PLATFORM_ID', settings.get_platform_id())
  environment.set_value('PRODUCT_BRAND', settings.get_product_brand())
  environment.set_value('SANITIZER_TOOL_NAME',
                        settings.get_sanitizer_tool_name())
  environment.set_value('SECURITY_PATCH_LEVEL',
                        settings.get_security_patch_level())


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
  package_name = app.get_package_name()
  if not package_name:
    return

  # Add |REINSTALL_APP_BEFORE_EACH_TASK| to force update decision.
  reinstall_app_before_each_task = environment.get_value(
      'REINSTALL_APP_BEFORE_EACH_TASK', False)
  force_update = force_update or reinstall_app_before_each_task

  # Install application if it is not found in the device's
  # package list or force_update flag has been set.
  if force_update or not app.is_installed(package_name):
    app.uninstall(package_name)
    app.install(apk_path)

    if not app.is_installed(package_name):
      logs.log_error(
          'Package %s was not installed successfully.' % package_name)
      return

    logs.log('Package %s is successfully installed using apk %s.' %
             (package_name, apk_path))

  app.reset()


def is_build_at_least(current_version, other_version):
  """Returns whether or not |current_version| is at least as new as
  |other_version|."""
  if current_version is None:
    return False

  # Special-cases for master builds.
  if current_version == 'MASTER':
    # If the current build is master, we consider it at least as new as any
    # other.
    return True

  if other_version == 'MASTER':
    # Since this build is not master, it is not at least as new as master.
    return False

  return current_version >= other_version


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

  adb.copy_local_directory_to_remote(local_testcases_directory,
                                     constants.DEVICE_TESTCASES_DIR)


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


def setup_host_and_device_forwarder_if_needed():
  """Sets up http(s) forwarding between device and host."""
  # Get list of ports to map.
  http_port_1 = environment.get_value('HTTP_PORT_1', 8000)
  http_port_2 = environment.get_value('HTTP_PORT_2', 8080)
  ports = [http_port_1, http_port_2]

  # Reverse map socket connections from device to host machine.
  for port in ports:
    port_string = 'tcp:%d' % port
    adb.run_command(['reverse', port_string, port_string])


def update_build(apk_path, force_update=True, should_initialize_device=True):
  """Prepares the device and updates the build if necessary."""
  # Prepare device for app install.
  if should_initialize_device:
    initialize_device()

  # On Android, we may need to write a command line file. We do this in
  # advance so that we do not have to write this to the device multiple
  # times.
  # TODO(mbarbella): Platforms code should not depend on bot.
  from clusterfuzz._internal.bot import testcase_manager
  testcase_manager.get_command_line_for_application(
      write_command_line_file=True)

  # Install the app if it does not exist.
  install_application_if_needed(apk_path, force_update=force_update)
