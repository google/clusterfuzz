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
"""Process runner."""

import subprocess


class Process(object):
  """Represent an child process.

       This class is intentionally similar to subprocess, except that it allows
       various fields to be set before executing the process. Additionally, it
       allows tests to overload process creation and execution in one place;
       see MockProcess.
    """

  def __init__(self, args, **kwargs):
    self.args = args
    self.cwd = kwargs.get('cwd', None)
    self.stdin = kwargs.get('stdin', None)
    self.stdout = kwargs.get('stdout', None)
    self.stderr = kwargs.get('stderr', None)

  def popen(self):
    """Analogous to subprocess.Popen."""
    p = subprocess.Popen(
        self.args, stdin=self.stdin, stdout=self.stdout, stderr=self.stderr)
    self.__init__([])
    return p

  def call(self):
    """Analogous to subprocess.call."""
    p = self.popen()
    return p.wait()

  def check_call(self):
    """Analogous to subprocess.check_call."""
    cmd = self.args
    rc = self.call()
    if rc != 0:
      raise subprocess.CalledProcessError(rc, cmd)
    return rc

  def check_output(self):
    """Analogous to subprocess.check_output."""
    cmd = self.args
    self.stdout = subprocess.PIPE
    p = self.popen()
    out, _ = p.communicate()
    rc = p.returncode
    if rc != 0:
      raise subprocess.CalledProcessError(rc, cmd)
    return out
