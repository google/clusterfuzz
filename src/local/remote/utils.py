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
"""Methods that are used in multiple places."""
import os
import re

from fabric import api


def get_file_content(file_path):
  """Return content of a file."""
  return open(file_path).read().strip()


def get_host_user_and_ssh_key_path(instance_name, project, zone):
  """Return a tuple of (hostname, username and ssh_key_path)."""
  output = api.local(
      'gcloud compute ssh --project "%s" --zone "%s" %s --dry-run' %
      (project, zone, instance_name),
      capture=True)
  print(output)

  m = re.match('/usr/bin/ssh .*-i ([^ ]+)(?: -o [^ ]+)* ([^ ]+)@([^ ]+)',
               output)
  return (m.group(3), m.group(2), m.group(1))


def get_password():
  """Return password from |PASSWORD_FILE_PATH| environment variable."""
  password_file_path = os.getenv('PASSWORD_FILE_PATH')
  if not password_file_path:
    raise Exception('Please set PASSWORD_FILE_PATH in environment.')

  return get_file_content(password_file_path)
