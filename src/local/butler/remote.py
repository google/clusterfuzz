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
"""Helps with remote command-line tasks (e.g. read logs, stage zip)."""

import inspect
import paramiko
import six

from fabric import api

from local.remote.handlers import android_chrome_lab
from local.remote.handlers import linux
from local.remote.handlers import mac
from local.remote.handlers import windows

paramiko.util.log_to_file('paramiko.log')
api.env.connection_attempts = 3
api.env.timeout = 3


def _get_handler_ctor(args):
  """Get a Handler class given arguments."""
  if 'linux' in args.instance_name:
    return linux.Handler
  if 'windows' in args.instance_name:
    return windows.Handler
  if 'golo' in args.instance_name:
    return mac.Handler
  if 'android-build' in args.instance_name:
    return android_chrome_lab.Handler
  raise NotImplementedError('Unsupported platform.')


def _args_to_dict(args, method):
  """Convert args to dict that is compatible with the method's argument."""
  arg_names = inspect.getfullargspec(method).args[1:]
  args_dict = {
      k: v
      for k, v in six.iteritems(vars(args))
      if k in arg_names and v is not None
  }
  return args_dict


def execute(args):
  """Run command-line tasks on a remote bot."""
  handler_ctor = _get_handler_ctor(args)
  handler = handler_ctor(**_args_to_dict(args, handler_ctor.__init__))

  method = getattr(handler, args.remote)
  method(**_args_to_dict(args, method))
