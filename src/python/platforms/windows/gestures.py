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

import ast
import random
import time

from base import utils
from metrics import logs

try:
  from pywinauto import application
except ImportError:
  # This can be imported from appengine, so make sure we don't exception out.
  pass

RELOAD_GESTURE = 'key,{F5}'


def find_windows_for_process(process_id):
  """Return visible windows belonging to a process."""
  pids = utils.get_process_ids(process_id)
  if not pids:
    return []

  visible_windows = []
  for pid in pids:
    app = application.Application()
    try:
      app.connect(process=pid)
    except:
      logs.log_warn('Unable to connect to process.')
      continue

    try:
      windows = app.windows()
    except:
      logs.log_warn('Unable to get application windows.')
      continue

    for window in windows:
      try:
        window.type_keys('')
      except:
        continue

      visible_windows.append(window)

  return visible_windows


def get_random_gestures(gesture_count):
  """Return list of random gesture command strings."""
  gestures_types = [
      'key,Letters', 'key,Letters', 'key,Letters', 'key,Letters', 'mouse,MA',
      'mousedrag,MB', 'mousemove,MC'
  ]

  gestures = []
  for _ in range(gesture_count):
    random_gesture = utils.random_element_from_list(gestures_types)
    if 'Letters' in random_gesture:
      num_letters = random.randint(1, 10)
      letters = []
      for _ in range(num_letters):
        if not random.randint(0, 7):
          letters.append(
              utils.random_element_from_list([
                  '{BACK}', '{BACKSPACE}', '{BKSP}', '{CAP}', '{DEL}',
                  '{DELETE}', '{DOWN}', '{DOWN}', '{END}', '{ENTER}', '{ENTER}',
                  '{ENTER}', 'A{ESC}', '{F1}', '{F2}', '{F3}', 'A{F4}', '{F5}',
                  '{F6}', '{F7}', '{F8}', '{F9}', '{F10}', '{F11}', '{F12}',
                  '{HOME}', '{INSERT}', '{LEFT}', '{PGDN}', '{PGUP}', '{RIGHT}',
                  '{SPACE}', '{TAB}', '{TAB}', '{TAB}', '{TAB}', '{UP}', '{UP}',
                  '+', '^'
              ]))
        else:
          letters.append(
              utils.random_element_from_list(
                  ['{TAB}', '^=', '^-',
                   '{%s}' % chr(random.randint(32, 126))]))
      random_gesture = random_gesture.replace('Letters', ''.join(letters))
      if ('^c' in random_gesture.lower() or '^d' in random_gesture.lower() or
          '^z' in random_gesture.lower()):
        continue

    if ',MA' in random_gesture:
      button = utils.random_element_from_list(['left', 'right', 'middle'])
      coords = '(%d,%d)' % (random.randint(0, 1000), random.randint(0, 1000))
      double = utils.random_element_from_list(['True', 'False'])
      random_gesture = random_gesture.replace(
          'MA', '%s;%s;%s' % (button, coords, double))

    if ',MB' in random_gesture:
      button = utils.random_element_from_list(['left', 'right', 'middle'])
      coords1 = '(%d,%d)' % (random.randint(0, 1000), random.randint(0, 1000))
      coords2 = '(%d,%d)' % (random.randint(0, 1000), random.randint(0, 1000))
      random_gesture = random_gesture.replace(
          'MB', '%s;%s;%s' % (button, coords1, coords2))

    if ',MC' in random_gesture:
      button = utils.random_element_from_list(['left', 'right', 'middle'])
      coords = '(%d,%d)' % (random.randint(0, 1000), random.randint(0, 1000))
      random_gesture = random_gesture.replace('MC', '%s;%s' % (button, coords))

    gestures.append(random_gesture)

  return gestures


def run_gestures(gestures, process_id, process_status, start_time, timeout,
                 windows):
  """Run the provided interaction gestures."""
  if not windows:
    windows += find_windows_for_process(process_id)

  for window in windows:
    for gesture in gestures:
      # If process had exited or our timeout interval has exceeded,
      # just bail out.
      if process_status.finished or time.time() - start_time >= timeout:
        return

      try:
        tokens = gesture.split(',')
        command = tokens.pop(0)
        value = ','.join(tokens)

        if command == 'key':
          window.type_keys(value)

        elif command == 'mouse':
          button, coords, double = value.split(';')
          window.click_input(
              button=button,
              coords=ast.literal_eval(coords),
              double=ast.literal_eval(double))

        elif command == 'mousedrag':
          button, coords1, coords2 = value.split(';')
          window.drag_mouse(
              button=button,
              press_coords=ast.literal_eval(coords1),
              release_coords=ast.literal_eval(coords2))

        elif command == 'mousemove':
          button, coords = value.split(';')
          window.move_mouse(pressed=button, coords=ast.literal_eval(coords))

      except Exception:
        # Several types of errors can happen. Just ignore them until a better
        # solution is available. E.g. controls not visible, gestures cannot be
        # run, invalid window handle, window failed to respond to gesture, etc.
        pass
