# Copyright 2024 Google LLC
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
"""Handles knobs that can be randomly chosen for fuzz_task."""
import collections

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import ndb_utils
from clusterfuzz._internal.fuzzing import gesture_handler
from clusterfuzz._internal.system import environment

DEFAULT_CHOOSE_PROBABILITY = 9  # 10%
MAX_GESTURES = 30

Redzone = collections.namedtuple('Redzone', ['size', 'weight'])
SelectionMethod = collections.namedtuple('SelectionMethod',
                                         'method_name probability')
SELECTION_METHOD_DISTRIBUTION = [
    SelectionMethod('default', .7),
    SelectionMethod('multi_armed_bandit', .3)
]


def do_multiarmed_bandit_strategy_selection(uworker_env):
  """Set multi-armed bandit strategy selection during preprocessing. Set
  multi-armed bandit strategy selection distribution as an environment variable
  so we can access it in launcher."""
  # TODO: Remove environment variable once fuzzing engine refactor is
  # complete.
  if not environment.get_value(
      'USE_BANDIT_STRATEGY_SELECTION', env=uworker_env):
    return
  selection_method = utils.random_weighted_choice(SELECTION_METHOD_DISTRIBUTION,
                                                  'probability')
  environment.set_value('STRATEGY_SELECTION_METHOD',
                        selection_method.method_name, uworker_env)
  distribution = get_strategy_distribution_from_ndb()
  if not distribution:
    return
  environment.set_value('STRATEGY_SELECTION_DISTRIBUTION', distribution,
                        uworker_env)


def pick_gestures(test_timeout):
  """Return a list of random gestures."""
  if not environment.get_value('ENABLE_GESTURES', True):
    # Gestures disabled.
    return []

  # Probability of choosing gestures.
  if utils.random_number(0, DEFAULT_CHOOSE_PROBABILITY):
    return []

  gesture_count = utils.random_number(1, MAX_GESTURES)
  gestures = gesture_handler.get_gestures(gesture_count)
  if not gestures:
    return []

  # Pick a random trigger time to run the gesture at.
  min_gesture_time = int(
      utils.random_element_from_list([0.25, 0.50, 0.50, 0.50]) * test_timeout)
  max_gesture_time = test_timeout - 1
  gesture_time = utils.random_number(min_gesture_time, max_gesture_time)

  gestures.append('Trigger:%d' % gesture_time)
  return gestures


def pick_redzone():
  """Return a random size for redzone."""
  thread_multiplier = environment.get_value('THREAD_MULTIPLIER', 1)

  if thread_multiplier == 1:
    redzone_list = [
        Redzone(16, 1.0),
        Redzone(32, 1.0),
        Redzone(64, 0.5),
        Redzone(128, 0.5),
        Redzone(256, 0.25),
        Redzone(512, 0.25),
    ]
  else:
    # For beefier boxes, prioritize using bigger redzones.
    redzone_list = [
        Redzone(16, 0.25),
        Redzone(32, 0.25),
        Redzone(64, 0.50),
        Redzone(128, 0.50),
        Redzone(256, 1.0),
        Redzone(512, 1.0),
    ]

  return utils.random_weighted_choice(redzone_list).size


def pick_ubsan_disabled(job_type):
  """Choose whether to disable UBSan in an ASan+UBSan build."""
  # This is only applicable in an ASan build.
  memory_tool_name = environment.get_memory_tool_name(job_type)
  if memory_tool_name not in ['ASAN', 'HWASAN']:
    return False

  # Check if UBSan is enabled in this ASan build. If not, can't disable it.
  if not environment.get_value('UBSAN'):
    return False

  return not utils.random_number(0, DEFAULT_CHOOSE_PROBABILITY)


def pick_timeout_multiplier():
  """Return a random testcase timeout multiplier and adjust timeout."""
  fuzz_test_timeout = environment.get_value('FUZZ_TEST_TIMEOUT')
  custom_timeout_multipliers = environment.get_value(
      'CUSTOM_TIMEOUT_MULTIPLIERS')
  timeout_multiplier = 1.0

  use_multiplier = not utils.random_number(0, DEFAULT_CHOOSE_PROBABILITY)
  if (use_multiplier and not fuzz_test_timeout and
      not custom_timeout_multipliers):
    timeout_multiplier = utils.random_element_from_list([0.5, 1.5, 2.0, 3.0])
  elif use_multiplier and custom_timeout_multipliers:
    # Since they are explicitly set in the job definition, it is fine to use
    # custom timeout multipliers even in the case where FUZZ_TEST_TIMEOUT is
    # set.
    timeout_multiplier = utils.random_element_from_list(
        custom_timeout_multipliers)

  return timeout_multiplier


def pick_window_argument():
  """Return a window argument with random size and x,y position."""
  default_window_argument = environment.get_value('WINDOW_ARG', '')
  window_argument_change_chance = not utils.random_number(
      0, DEFAULT_CHOOSE_PROBABILITY)

  window_argument = ''
  if window_argument_change_chance:
    window_argument = default_window_argument
    if window_argument:
      width = utils.random_number(
          100, utils.random_element_from_list([256, 1280, 2048]))
      height = utils.random_number(
          100, utils.random_element_from_list([256, 1024, 1536]))
      left = utils.random_number(0, width)
      top = utils.random_number(0, height)

      window_argument = window_argument.replace('$WIDTH', str(width))
      window_argument = window_argument.replace('$HEIGHT', str(height))
      window_argument = window_argument.replace('$LEFT', str(left))
      window_argument = window_argument.replace('$TOP', str(top))

  # FIXME: Random seed is currently passed along to the next job
  # via WINDOW_ARG. Rename it without breaking existing tests.
  random_seed_argument = environment.get_value('RANDOM_SEED')
  if random_seed_argument:
    if window_argument:
      window_argument += ' '
    seed = utils.random_number(-2147483648, 2147483647)
    window_argument += '%s=%d' % (random_seed_argument.strip(), seed)

  environment.set_value('WINDOW_ARG', window_argument)
  return window_argument


def get_strategy_distribution_from_ndb():
  """Queries and returns the distribution stored in the ndb table."""
  query = data_types.FuzzStrategyProbability.query()
  distribution = []
  for strategy_entry in list(ndb_utils.get_all_from_query(query)):
    distribution.append({
        'strategy_name': strategy_entry.strategy_name,
        'probability': strategy_entry.probability,
        'engine': strategy_entry.engine
    })
  return distribution
