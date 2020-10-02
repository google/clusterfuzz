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
"""Handler for managing an android in the chrome lab."""
import os

from fabric import api

from local.remote import utils
from local.remote.handlers import posix


class Handler(posix.Handler):
  """Handler for managing an android host in the chrome lab."""

  def __init__(self, instance_name, *_):
    super(Handler, self).__init__(
        instance_name=instance_name, platform='linux', project=None, zone=None)

    # FIXME: Make these configurable.
    tokens = self.instance_name.split('-')
    api.env.host_string = '%s-%s.labs' % (tokens[1], tokens[2])
    self.bot_name = tokens[3]
    self.username = 'chrome-bot'
    self.clusterfuzz_parent_path = ('/home/{user}/bots/{bot_name}'.format(
        user=self.username, bot_name=self.bot_name))

    api.env.user = self.username
    api.env.gateway = None
    api.env.use_ssh_config = True
    api.env.ssh_config_path = '~/.ssh/config'
    api.env.key_filename = None
    api.env.use_shell = True
    api.env.password = api.env.sudo_password = utils.get_password()

    # Disable passwordless authentication, so we don't have to touch
    # a security key multiple times because it tries to access keys that
    # we don't need.
    os.environ['SSH_AUTH_SOCK'] = ''

    print()
    print('SSHing into chrome lab only works if you performs the below in'
          ' order:')
    print('(1) Your `~/.ssh/config` is up-to-date. You can get it from'
          ' go/chrome-lab-ssh-config')
    print('(2) You are a member of clusterfuzz-build-access (see'
          ' go/clusterfuzz-build-access)')
    print('(3) ControlMaster is enabled. Put the below'
          ' lines in your `~/.ssh/config`:')
    print()
    print('Match host *')
    print('  ControlMaster auto')
    print('  ControlPath ~/.ssh/ctrl-%C')
    print('  ControlPersist 6h')
    print()
    print('(4) You ran `prodaccess --chromegolo_ssh` recently.')
    print("(5) You sshed into *one* of the chrome lab's machines in the last"
          ' 6 hours.')
    print()
    print('Now you can enjoy sshing into any android bot in the chrome lab.')
    print()

  def _should_kill(self, run_bot_line):
    """Determine if this run_bot.py process should be killed."""
    return self.bot_name in run_bot_line
