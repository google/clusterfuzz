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
"""Fuchsia utilities for handling logging."""

from builtins import object
import os
import re
import subprocess


class Log(object):
  """Provides a context-managed interface to the fuzzing logs."""

  def __init__(self, fuzzer):
    self.fuzzer = fuzzer
    self.device = fuzzer.device
    self.host = fuzzer.host

  def __enter__(self):
    """Resets the fuzzing logs.

      This will clear stale logs from the device for the given fuzzer and
      restart loglistener.
    """
    self.device.ssh(['rm', self.fuzzer.data_path('fuzz-*.log')])
    self.host.killall('loglistener')
    with open(self.fuzzer.results('zircon.log'), 'w') as log:
      self.host.zircon_tool(['loglistener'], logfile=log)

  def __exit__(self, e_type, e_value, traceback):
    """Gathers and processes the fuzzing logs.

      This will stop loglistener and symbolize its output.  It will also
      retrieve fuzzing logs from
      the device for each libFuzzer worker, and download any test unit artifacts
      they reference.
    """
    self.host.killall('loglistener')
    with open(self.fuzzer.results('zircon.log'), 'r') as log_in:
      with open(self.fuzzer.results('symbolized.log'), 'w') as log_out:
        self.host.symbolize(log_in, log_out)
    try:
      self.device.fetch(
          self.fuzzer.data_path('fuzz-*.log'), self.fuzzer.results())
    except subprocess.CalledProcessError:
      pass
    units = []
    pattern = re.compile(r'Test unit written to (\S*)$')
    for log in os.listdir(self.fuzzer.results()):
      if log.startswith('fuzz-') and log.endswith('.log'):
        with open(self.fuzzer.results(log), 'r') as f:
          matches = [pattern.match(line) for line in f.readlines()]
          units.extend([m.group(1) for m in matches if m])
    for unit in units:
      self.device.fetch(unit, self.fuzzer.results())
