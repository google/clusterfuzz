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

from __future__ import absolute_import
from builtins import range
import copy
import datetime
import os
import re
import six
import socket
import time

from . import adb
from . import app
from . import constants
from . import fetch_artifact
from . import logger
from . import settings
from . import wifi
from base import dates
from base import persistent_cache
from config import db_config
from datastore import locks
from metrics import logs
from system import archive
from system import environment
from system import shell

ADD_TEST_ACCOUNT_APK_NAME = 'user_account_setup.apk'
ADD_TEST_ACCOUNT_CHECK_INTERVAL = 1 * 24 * 60 * 60
ADD_TEST_ACCOUNT_PKG_NAME = 'com.google.android.tests.utilities'
ADD_TEST_ACCOUNT_CALL_PATH = '%s/.AddAccount' % ADD_TEST_ACCOUNT_PKG_NAME
ADD_TEST_ACCOUNT_TIMEOUT = 20
ASAN_SCRIPT_TIMEOUT = 15 * 60
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
    ('vbmeta', 'vbmeta.img'),
    ('dtbo', 'dtbo.img'),
    ('userdata', 'userdata.img'),
]
FLASH_RETRIES = 3
FLASH_REBOOT_BOOTLOADER_WAIT = 15
FLASH_REBOOT_WAIT = 5 * 60
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
PS_REGEX = re.compile(
    r'\S+\s+([0-9]+)\s+[0-9]+\s+[0-9]+\s+[0-9]+\s+\S+\s+\S+\s+\S+\s+sh')
SANITIZER_TOOL_TO_FILE_MAPPINGS = {
    'ASAN': 'asan.options',
}
SCREEN_LOCK_SEARCH_STRING = 'mShowingLockscreen=true'

BUILD_PROP_MD5_KEY = 'android_build_prop_md5'
LAST_FLASH_BUILD_KEY = 'android_last_flash'
LAST_FLASH_TIME_KEY = 'android_last_flash_time'
LAST_TEST_ACCOUNT_CHECK_KEY = 'android_last_test_account_check'


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
  persistent_cache.set_value(LAST_TEST_ACCOUNT_CHECK_KEY, time.time())


def clear_testcase_directory():
  """Clears testcase directory."""
  # Cleanup downloads folder on /sdcard.
  adb.remove_directory(adb.DEVICE_DOWNLOAD_DIR, recreate=True)

  # Cleanup testcase directory.
  adb.remove_directory(constants.DEVICE_TESTCASES_DIR, recreate=True)


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
  adb.run_shell_command('service call audio 3 i32 3 i32 0 i32 1')

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

  app.disable_packages_that_crash_with_gestures()

  # Create a list of property name and names to be used in local.prop file.
  local_properties_settings_list = copy.deepcopy(LOCAL_PROP_SETTINGS)

  # Add debugging flags to local settings list so that they persist across
  # reboots.
  local_properties_settings_list += get_debug_props_and_values()

  # Write the local properties file settings.
  local_properties_file_contents = '\n'.join(local_properties_settings_list)
  adb.write_data_to_file(local_properties_file_contents, LOCAL_PROP_PATH)


def get_kernel_log_content():
  """Return content of kernel logs."""
  kernel_log_content = ''
  for kernel_log_file in KERNEL_LOG_FILES:
    kernel_log_content += adb.read_data_from_file(kernel_log_file) or ''

  return kernel_log_content


def get_pid_for_script(script_name):
  """Get the pid of a running shell script."""
  output = adb.run_shell_command("ps | grep ' sh'")
  pids = PS_REGEX.findall(output)
  for pid in pids:
    cmdline = adb.run_shell_command('cat /proc/%s/cmdline' % pid)
    if script_name in cmdline:
      return pid

  return None


def get_type_binding(value):
  """Return binding type for content setting."""
  if isinstance(value, bool):
    return 'b'
  if isinstance(value, float):
    return 'f'
  if isinstance(value, int):
    return 'i'
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
  wifi.configure()
  setup_host_and_device_forwarder_if_needed()
  adb.clear_notifications()
  settings.change_se_linux_to_permissive_mode()
  app.wait_until_optimization_complete()
  unlock_screen_if_locked()

  # FIXME: Should we should revert back to regular user permission ?


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


def get_sanitizer_options_file_path(sanitizer_tool_name):
  """Return path for the sanitizer options file."""
  # If this a full sanitizer system build, then update the options file in
  # /system, else just put it in device temp directory.
  sanitizer_directory = ('/system' if settings.get_sanitizer_tool_name() else
                         adb.DEVICE_TMP_DIR)

  sanitizer_filename = SANITIZER_TOOL_TO_FILE_MAPPINGS[sanitizer_tool_name]
  return os.path.join(sanitizer_directory, sanitizer_filename)


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


def setup_asan_if_needed():
  """Sets the asan.options device property."""
  if not environment.get_value('ASAN_DEVICE_SETUP'):
    # Only do this step if explicitly enabled in the job type. This cannot be
    # determined from libraries in application directory since they can go
    # missing in a bad build, so we want to catch that.
    return

  if settings.get_sanitizer_tool_name():
    # If this is a sanitizer build, no need to setup ASAN (incompatible).
    return

  app_directory = environment.get_value('APP_DIR')
  if not app_directory:
    # No app directory -> No ASAN runtime library. No work to do, bail out.
    return

  # Initialize variables.
  android_directory = environment.get_platform_resources_directory()
  device_id = environment.get_value('ANDROID_SERIAL')

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

  # Wait until fully booted as otherwise shell restart followed by a quick
  # reboot can trigger data corruption in /data/data.
  adb.wait_until_fully_booted()


def set_content_settings(table, key, value):
  """Set a device content setting."""
  content_setting_command = (
      'content insert --uri content://%s --bind name:s:%s --bind value:%s:%s' %
      (table, key, get_type_binding(value), str(value)))

  adb.run_shell_command(content_setting_command)


def set_sanitizer_options_if_needed(sanitizer_tool_name, sanitizer_options):
  """Sets up sanitizer options on the disk file."""
  sanitizer_options_file_path = get_sanitizer_options_file_path(
      sanitizer_tool_name)
  adb.write_data_to_file(sanitizer_options, sanitizer_options_file_path)


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


def unlock_screen_if_locked():
  """Unlocks the screen if it is locked."""
  window_dump_output = adb.run_shell_command(['dumpsys', 'window'])
  if SCREEN_LOCK_SEARCH_STRING not in window_dump_output:
    # Screen is not locked, no work to do.
    return

  # Quick power on and off makes this more reliable.
  adb.run_shell_command(['input', 'keyevent', 'KEYCODE_POWER'])
  adb.run_shell_command(['input', 'keyevent', 'KEYCODE_POWER'])

  # This key does the unlock.
  adb.run_shell_command(['input', 'keyevent', 'KEYCODE_MENU'])

  # Artifical delay to let the unlock to complete.
  time.sleep(1)


def flash_to_latest_build_if_needed():
  """Wipes user data, resetting the device to original factory state."""
  if environment.get_value('LOCAL_DEVELOPMENT'):
    # Don't reimage local development devices.
    return

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
  if adb.is_gce():
    adb.recreate_gce_device()
  else:
    # Physical device.
    is_google_device = settings.is_google_device()
    if is_google_device is None:
      logs.log_error('Unable to query device. Reimaging failed.')
      adb.bad_state_reached()

    elif not is_google_device:
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
        build_params = settings.get_build_parameters()
        if build_params:
          target = build_params.get('target') + '-userdebug'

          # Cache target in environment. This is also useful for cases when
          # device is bricked and we don't have this information available.
          environment.set_value('BUILD_TARGET', target)

      if not branch or not target:
        logs.log_warn(
            'BUILD_BRANCH and BUILD_TARGET are not set, skipping reimage.')
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
      for _ in range(FLASH_RETRIES):
        adb.run_as_root()
        adb.run_command(['reboot-bootloader'])
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

        # Disable ramdump to avoid capturing ramdumps during kernel crashes.
        # This causes device lockup of several minutes during boot and we intend
        # to analyze them ourselves.
        adb.run_fastboot_command(['oem', 'ramdump', 'disable'])

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
  persistent_cache.delete_value(LAST_TEST_ACCOUNT_CHECK_KEY)
  persistent_cache.set_value(LAST_FLASH_BUILD_KEY, build_info)
  persistent_cache.set_value(LAST_FLASH_TIME_KEY, time.time())


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
  persistent_cache.set_value(BUILD_PROP_MD5_KEY, current_md5)


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
