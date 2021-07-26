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
"""Gestures related functions."""

import random
import time

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import shell

MAX_CHARS_TO_TYPE = 20
RELOAD_GESTURE = 'key,F5'

COORDINATE_DELTA_MIN = -100
COORDINATE_DELTA_MAX = 200
SCREEN_WIDTH = 1280
SCREEN_HEIGHT = 1024


def _xdotool_path():
  """Return full path to xdotool."""
  return shell.which('xdotool')


def find_windows_for_process(process_id):
  """Return visible windows belonging to a process."""
  pids = utils.get_process_ids(process_id)
  if not pids:
    return []

  xdotool_path = _xdotool_path()
  if not xdotool_path:
    logs.log_error('Xdotool not installed, cannot locate process windows.')
    return []

  visible_windows = []
  for pid in pids:
    windows = (
        shell.execute_command(
            '%s search --all --pid %d --onlyvisible' % (xdotool_path, pid)))

    for line in windows.splitlines():
      if not line.isdigit():
        continue

      visible_windows.append(int(line))

  return visible_windows


def get_random_gestures(gesture_count):
  """Return list of random gesture command strings."""
  gesture_types = [
      'click --repeat TIMES,mbutton',
      'drag',
      'key,ctrl+minus',
      'key,ctrl+plus',
      'key,Function',
      'key,Letter',
      'key,Letters',
      'key,Modifier+Letter',
      'keydown,Letter',
      'keyup,Letter',
      'type,Chars',
      'type,Chars',
      'mousedown,mbutton',
      'mousemove --sync,x y',
      'mousemove_relative --sync,nx ny',
      'mouseup,mbutton',
  ]

  if not random.randint(0, 3):
    gesture_types.append('windowsize,P P')

  gestures = []
  for _ in range(gesture_count):
    random_gesture = utils.random_element_from_list(gesture_types)
    if random_gesture == 'drag':
      gestures.append('mousemove,%d %d' % (random.randint(0, SCREEN_WIDTH),
                                           random.randint(0, SCREEN_HEIGHT)))
      gestures.append('mousedown,1')
      gestures.append('mousemove_relative,0 1')
      gestures.append('mousemove_relative,0 -')
      gestures.append('mousemove,%d %d' % (random.randint(0, SCREEN_WIDTH),
                                           random.randint(0, SCREEN_HEIGHT)))
      gestures.append('mouseup,1')
      continue

    if 'Function' in random_gesture:
      random_gesture = (
          random_gesture.replace('Function', 'F%d' % random.randint(1, 12)))

    elif 'mbutton' in random_gesture:
      random_gesture = random_gesture.replace('TIMES', str(
          random.randint(1, 3)))

      picked_button = 1 if random.randint(0, 4) else random.randint(2, 5)
      random_gesture = random_gesture.replace('mbutton', str(picked_button))

    elif ',x y' in random_gesture:
      random_gesture = random_gesture.replace(
          ',x y', ',%d %d' % (random.randint(0, SCREEN_WIDTH),
                              random.randint(0, SCREEN_HEIGHT)))

    elif ',nx ny' in random_gesture:
      random_gesture = random_gesture.replace(
          ',nx ny', ',%d %d' %
          (random.randint(COORDINATE_DELTA_MIN, COORDINATE_DELTA_MAX),
           random.randint(COORDINATE_DELTA_MIN, COORDINATE_DELTA_MAX)))

    elif ',P P' in random_gesture:
      random_gesture = random_gesture.replace(
          ',P P',
          ',%d%% %d%%' % (random.randint(10, 100), random.randint(10, 100)))

    elif 'Chars' in random_gesture:
      random_gesture = random_gesture.replace('Chars',
                                              "'%s'" % get_text_to_type())

    else:
      if 'Modifier' in random_gesture:
        random_gesture = random_gesture.replace(
            'Modifier',
            utils.random_element_from_list([
                'alt', 'ctrl', 'control', 'meta', 'super', 'shift', 'ctrl+shift'
            ]))

      if 'Letters' in random_gesture:
        num_letters = random.randint(1, 10)
        letters = []
        for _ in range(num_letters):
          letters.append(
              utils.random_element_from_list([
                  'Escape', 'BackSpace', 'Delete', 'Tab', 'space', 'Down',
                  'Return', 'Up', 'Down', 'Left', 'Right',
                  chr(random.randint(48, 57)),
                  chr(random.randint(65, 90)),
                  chr(random.randint(97, 122))
              ]))
        random_gesture = random_gesture.replace('Letters', ' '.join(letters))

      elif 'Letter' in random_gesture:
        random_gesture = random_gesture.replace(
            'Letter',
            utils.random_element_from_list([
                'space',
                chr(random.randint(48, 57)),
                chr(random.randint(65, 90)),
                chr(random.randint(97, 122))
            ]))

        if 'ctrl+c' in random_gesture.lower():
          continue

    gestures.append(random_gesture)

  return gestures


def get_text_to_type():
  """Return text to type."""
  chars = []
  chars_to_type_count = random.randint(1, MAX_CHARS_TO_TYPE)
  meta_chars = [
      '|', '&', ';', '(', ')', '<', '>', ' ', '\t', ',', '\'', '"', '`', '[',
      ']', '{', '}'
  ]

  for _ in range(chars_to_type_count):
    char_code = random.randint(32, 126)
    char = chr(char_code)
    if char in meta_chars:
      continue

    chars.append(char)

  return ''.join(chars)


def run_gestures(gestures, process_id, process_status, start_time, timeout,
                 windows):
  """Run the provided interaction gestures."""
  xdotool_path = _xdotool_path()
  if not xdotool_path:
    logs.log_error('Xdotool not installed, cannot emulate gestures.')
    return

  if not windows:
    windows += find_windows_for_process(process_id)

  for window in windows:
    # Activate the window so that it can receive gestures.
    shell.execute_command(
        '%s windowactivate --sync %d' % (xdotool_path, window))

    for gesture in gestures:
      # If process had exited or our timeout interval has exceeded,
      # just bail out.
      if process_status.finished or time.time() - start_time >= timeout:
        return

      gesture_type, gesture_cmd = gesture.split(',')
      if gesture_type == 'windowsize':
        shell.execute_command(
            '%s %s %d %s' % (xdotool_path, gesture_type, window, gesture_cmd))
      else:
        shell.execute_command(
            '%s %s -- %s' % (xdotool_path, gesture_type, gesture_cmd))
