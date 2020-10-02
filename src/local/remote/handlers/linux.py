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
from fabric import api

from local.remote import utils
from local.remote.handlers import posix


class Handler(posix.Handler):
  """Handler for performing linux task."""

  def __init__(self, instance_name, project=None, zone=None):
    assert project, 'Need to specify a project via --project argument.'
    assert zone, 'Need to specify a zone via --zone argument.'

    super(Handler, self).__init__(
        instance_name=instance_name,
        platform='linux',
        project=project,
        zone=zone)

    # FIXME: Make these configurable.
    self.username = 'clusterfuzz'
    self.clusterfuzz_parent_path = '/mnt/scratch0'
    self.clusterfuzz_parent_path_outside = '/var/scratch0'

    (hostname, username,
     ssh_key_file_path) = utils.get_host_user_and_ssh_key_path(
         self.instance_name, self.project, self.zone)
    api.env.host_string = '{username}@{hostname}'.format(
        username=username, hostname=hostname)
    api.env.key_filename = ssh_key_file_path
    api.env.use_shell = True

  def _path_outside_docker(self, path):
    """Return the path outside docker."""
    return path.replace(self.clusterfuzz_parent_path,
                        self.clusterfuzz_parent_path_outside)

  def _run(self, command):
    """Custom _run that ensures that command is run inside docker container."""
    print('Running: ' + command)
    return api.sudo('docker exec {user} bash -c "{command}"'.format(
        user=self.username, command=command.replace('"', '\\"')))

  def _copy_staging_archive_from_local_to_remote(self, local_zip_path):
    """Copy staging archive from local to remote."""
    remote_zip_path = (
        '{clusterfuzz_parent_path}/{staging_source_filename}'.format(
            clusterfuzz_parent_path=self.clusterfuzz_parent_path,
            staging_source_filename=self.staging_source_filename))
    self._run('rm -f ' + remote_zip_path)

    api.sudo('chmod a+w ' + self.clusterfuzz_parent_path_outside)
    api.put(local_zip_path, self._path_outside_docker(remote_zip_path))
