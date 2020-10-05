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
"""Handler for performing remote tasks on linux."""
import os
import re
import time

from fabric import api
from fabric import exceptions
from paramiko import ssh_exception

from local.butler import common as butler_common
from local.butler import package


class Handler(object):
  """Handler for performing linux task."""

  def __init__(self, instance_name, platform, project, zone):
    self.instance_name = instance_name
    self.platform = platform
    self.project = project
    self.zone = zone

    self.staging_source_filename = 'clusterfuzz-source-stage.zip'

  def _abspath(self, path):
    """Get absolute path on host given a path inside the clusterfuzz folder."""
    return self.clusterfuzz_parent_path + '/clusterfuzz/' + path

  def _get_run_bot_pids(self):
    """Get the PIDs of run_bot.py."""
    with api.warn_only():
      output = self._run('ps aux | grep run_bot | grep -v grep')

    pids = []
    for line in output.splitlines():
      line = line.strip()
      if line and self._should_kill(line):
        pids.append(re.split(r'\s+', line)[1])

    return pids

  def _log_path(self, log_name):
    return '{log_dir}/{log_name}.log'.format(
        log_dir=self._abspath('bot/logs'), log_name=log_name)

  def _run(self, command):
    """Run the command."""
    print('Running: ' + command)
    return api.run(command)

  def _should_kill(self, run_bot_line):  # pylint: disable=unused-argument
    """Determine if this run_bot.py process should be killed."""
    return True

  def reboot(self):
    """Reboot the machine with `sudo reboot` and verify if succeeded."""
    try:
      api.sudo('reboot', timeout=1)
    except exceptions.CommandTimeout:
      # The timeout exception is expected if rebooting is successful.
      pass

    try:
      api.run('echo "Test rebooting"', timeout=3)
      raise Exception(
          'Failed to reboot because we can still connect to the machine.')
    except ssh_exception.ProxyCommandFailure:
      print('Cannot connect to the machine. The machine has been rebooted '
            'successfully.')

  def restart(self):
    """Restart clusterfuzz by killing existing run_bot.py processes and starting
    it back again."""
    pids = self._get_run_bot_pids()
    if not pids:
      raise Exception('No run_bot.py is running.')

    self._run('kill %s' % ' '.join(pids))
    time.sleep(3)

    for _ in range(30):
      new_pids = self._get_run_bot_pids()
      if new_pids:
        break

      time.sleep(1)

    if not new_pids:
      raise Exception('Failed to start run_bot.py after restarting.')

    print('run_bot.py has been restarted (PID=%s).' % ','.join(new_pids))

  def tail(self, log_name, line_count):
    """Print the last x lines of ./bot/logs/`log_name`.log."""
    self._run('tail -n {line_count} {log_path}'.format(
        line_count=line_count, log_path=self._log_path(log_name)))

  def tailf(self, log_names):
    """Print ./bot/logs/`name`.log in real-time (equivalent to `tail -f`)."""
    log_paths = ' '.join([self._log_path(i) for i in log_names])
    self._run('tail -f -n 100 %s' % log_paths)

  def _copy_staging_archive_from_local_to_remote(self, local_zip_path):
    """Copy staging archive from local to remote."""
    remote_zip_path = (
        '{clusterfuzz_parent_path}/{staging_source_filename}'.format(
            clusterfuzz_parent_path=self.clusterfuzz_parent_path,
            staging_source_filename=self.staging_source_filename))
    self._run('rm -f ' + remote_zip_path)
    api.put(local_zip_path, remote_zip_path)

  def stage(self, config_dir):
    """Stage a zip (built by `python butler.py package`)."""
    os.environ['CONFIG_DIR_OVERRIDE'] = config_dir

    # Restarting ensures that the target bot is updated to latest revision.
    # See crbug.com/674173 for more info.
    self.restart()

    local_zip_path = package.package(
        revision=butler_common.compute_staging_revision(),
        platform_name=self.platform)
    self._copy_staging_archive_from_local_to_remote(local_zip_path)

    self._run(('cd {clusterfuzz_parent_path} && '
               'unzip -o -d . {staging_source_filename}').format(
                   clusterfuzz_parent_path=self.clusterfuzz_parent_path,
                   staging_source_filename=self.staging_source_filename))
    self._run('chown -R {username} {clusterfuzz_parent_path}'.format(
        username=self.username,
        clusterfuzz_parent_path=self.clusterfuzz_parent_path))

    self.restart()
