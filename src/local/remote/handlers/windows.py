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
"""Handler for performing remote tasks on windows."""
import os
import time

from fabric import api
from fabric import exceptions

from local.butler import common as butler_common
from local.butler import package
from local.remote import utils

TEMPLATE_REMMINA_PATH = 'src/local/remote/windows.remmina'
GENERATED_REMMINA_PATH = 'src/local/remote/generated.remmina'
EXTRACT_ZIP_PS_LOCAL_PATH = 'src/local/remote/extract_zip.ps1'
EXTRACT_ZIP_PS_REMOTE_PATH = r'c:\extract_clusterfuzz_stage_source_zip.ps1'


class Handler(object):
  """Handler for windows."""

  def __init__(self, instance_name, project, zone):
    assert project, 'Need to specify a project via --project argument.'
    assert zone, 'Need to specify a zone via --zone argument.'

    # FIXME: Make these configurable.
    self.username = 'clusterfuzz'
    self.domain = 'GOOGLE'
    self.clusterfuzz_parent_path = r'c:'

    self.staging_source_filename = 'clusterfuzz-source-stage.zip'

    (hostname, _, _) = utils.get_host_user_and_ssh_key_path(
        instance_name, project, zone)

    api.env.password = utils.get_password()
    api.env.user = self.username
    api.env.hosts = [hostname]
    api.env.host_string = '{username}@{hostname}'.format(
        username=self.username, hostname=hostname)
    api.env.key_filename = None
    api.env.gss_auth = None
    api.env.gss_deleg_creds = None
    api.env.gss_kex = None
    api.env.no_keys = True
    api.env.key_filename = None
    api.env.no_agent = True
    api.env.use_shell = False

  def _powershell(self, command, powershell_option='command'):
    """Wrap a command with powershell."""
    # Setting TMP is necessary to solve the flakiness problem.
    # See @tanin47's comment on:
    # https://github.com/PowerShell/PowerShell/issues/1746
    api.run(r'cmd /c set TMP=%USERPROFILE%\appdata\local\temp'
            ' && powershell -{powershell_option} {command}'.format(
                powershell_option=powershell_option, command=command))

  def _abspath(self, path):
    """Get absolute path on host given a path inside the clusterfuzz folder."""
    return self.clusterfuzz_parent_path + '\\clusterfuzz\\' + path

  def _log_path(self, log_name):
    return r'{log_dir}\{log_name}.log'.format(
        log_dir=self._abspath(r'bot\logs'), log_name=log_name)

  def tail(self, log_name, line_count):
    """Print the last `size` lines of ./bot/logs/`log_name`.log."""
    self._powershell(r'Get-Content -Path {log_path} -Tail {line_count}'.format(
        log_path=self._log_path(log_name), line_count=line_count))

  def tailf(self, log_names):
    """Print ./bot/logs/`name`.log in real-time (equivalent to `tail -f`)."""
    if len(log_names) > 1:
      raise Exception('Sorry, on windows, we cannot tailf multiple logs')

    self._powershell(r'Get-Content -Path {log_path} -Wait -Tail 100'.format(
        log_path=self._log_path(log_names[0])))

  def reboot(self):
    """Reboot the machine and verify if succeeded."""
    api.run('cmd /c shutdown /r /f /t 0')
    print('Sleeping 45 seconds to allow reboot to finish.')
    time.sleep(45)

    try:
      api.run('cmd /c echo "Test rebooting"')
      raise Exception(
          'Failed to reboot because we can still connect to the machine.')
    except exceptions.NetworkError:
      print('Cannot connect to the machine. The machine has been rebooted '
            'successfully.')

  def restart(self):
    """Kill all run_bot.py processes. run.py will get the new source code and
       start run_bot.py."""
    api.run('wmic process where'
            ' (name="python.exe" AND commandline like "%run_bot%")'
            ' get commandline,processid')
    api.run('wmic process where'
            ' (name="python.exe" AND commandline like "%run_bot%")'
            ' delete')

  def stage(self, config_dir):
    """Stage a zip (built by `python butler.py package`)."""
    os.environ['CONFIG_DIR_OVERRIDE'] = config_dir

    self.restart()
    time.sleep(1)

    zip_path = package.package(
        revision=butler_common.compute_staging_revision(),
        platform_name='windows')
    remote_zip_path = (
        '{clusterfuzz_parent_path}\\{staging_source_filename}'.format(
            clusterfuzz_parent_path=self.clusterfuzz_parent_path,
            staging_source_filename=self.staging_source_filename))
    api.put(zip_path, remote_zip_path)

    api.put(EXTRACT_ZIP_PS_LOCAL_PATH, EXTRACT_ZIP_PS_REMOTE_PATH)
    self._powershell(EXTRACT_ZIP_PS_REMOTE_PATH, 'file')

    self.restart()

  def rdp(self, share_path=None):
    """Launch remmina with correct configuration for the target instance."""
    password = utils.get_password()
    template = utils.get_file_content(TEMPLATE_REMMINA_PATH)

    with open(GENERATED_REMMINA_PATH, 'w') as config:
      config.write(
          template.format(
              domain=self.domain,
              username=self.username,
              password=password,
              share_path=share_path or '',
              hostname=api.env.hosts[0]))

    api.local('remmina -c ' + os.path.abspath(GENERATED_REMMINA_PATH))
