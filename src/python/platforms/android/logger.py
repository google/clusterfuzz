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
"""System log manager related functions."""

import adb
import re

LOG_RETRIES = 2


def clear_log():
  """Clear log."""
  retries = LOG_RETRIES
  while retries:
    # Try clearing the log.
    adb.run_adb_command('logcat -c')

    # Check if the log is cleared. If yes, we can return. Otherwise, we retry
    # by continuing the loop.
    if not log_output():
      return

    retries -= 1


def is_line_valid(line):
  """Returns true if we consider this line in logs."""
  contain_url = 'NotifyBeforeURLRequest' in line
  # Discard noisy debug/verbose output.
  # http://developer.android.com/tools/debugging/debugging-log.html.
  at_least_info_level = not (line.startswith('D/') or line.startswith('V/'))

  return contain_url or at_least_info_level


def filter_log_output(output):
  """Filters log output. Removes debug info, etc and normalize output."""
  if not output:
    return ''

  filtered_output = ''
  last_process_id = 0
  for line in output.splitlines():
    line = line.strip()
    if not is_line_valid(line):
      continue

    m_line = re.match('[^D]/([^:]+)[:] (.*)', line)
    if not m_line:
      continue

    filtered_line = m_line.group(2)

    # Process Android crash stack frames and convert into sanitizer format.
    m_crash_state = re.match(r'\s*#([0-9]+)\s+pc\s+([xX0-9a-fA-F]+)\s+(.+)',
                             filtered_line)
    if m_crash_state:
      frame_no = int(m_crash_state.group(1))
      frame_address = m_crash_state.group(2)
      frame_binary = m_crash_state.group(3).strip()

      # Ignore invalid frames, helps to prevent errors
      # while symbolizing.
      if '<unknown>' in frame_binary:
        continue

      # Normalize frame address.
      if not frame_address.startswith('0x'):
        frame_address = '0x%s' % frame_address

      # Seperate out the function argument.
      frame_binary = (frame_binary.split(' '))[0]

      # Normalize line into the same sanitizer tool format.
      filtered_line = ('    #%d %s (%s+%s)' % (frame_no, frame_address,
                                               frame_binary, frame_address))

    # Process Chrome crash stack frames and convert into sanitizer format.
    # Stack frames don't have paranthesis around frame binary and address, so
    # add it explicitly to allow symbolizer to catch it.
    m_crash_state = re.match(
        r'\s*#([0-9]+)\s+([xX0-9a-fA-F]+)\s+([^(]+\+[xX0-9a-fA-F]+)$',
        filtered_line)
    if m_crash_state:
      frame_no = int(m_crash_state.group(1))
      frame_address = m_crash_state.group(2)
      frame_binary_and_address = m_crash_state.group(3).strip()
      filtered_line = ('    #%d %s (%s)' % (frame_no, frame_address,
                                            frame_binary_and_address))

    # Add process number if changed.
    m_process_num = re.match(r'(.*)[(]\s*(\d+)[)]', m_line.group(1))
    if m_process_num:
      process_id = int(m_process_num.group(2))
      if process_id != last_process_id:
        process_name = (m_process_num.group(1)).strip()
        filtered_output += '--------- %s (%d):\n' % (process_name, process_id)
        last_process_id = process_id

    filtered_output += filtered_line + '\n'

  return filtered_output


def log_output(additional_flags=''):
  """Return log data without noise and some normalization."""
  output = adb.run_adb_command('logcat -d -v brief %s *:V' % additional_flags)
  return filter_log_output(output)


def log_output_before_last_reboot():
  """Return log data from last reboot without noise and some normalization."""
  return log_output(additional_flags='-L')
