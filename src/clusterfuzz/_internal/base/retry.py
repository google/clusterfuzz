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
"""Retry decorator. We separate this part out into its
  own file because we want to avoid importing too many modules; now it can be
  used in more places."""

import functools
import inspect
import sys
import time
from typing import Any
from typing import Callable
from typing import cast
from typing import Optional
from typing import ParamSpec
from typing import Sequence
from typing import TypeVar

from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment

_P = ParamSpec('_P')
_R = TypeVar('_R')


def sleep(seconds: float | int) -> None:
  """Invoke time.sleep. This is to avoid the flakiness of time.sleep. See:
  crbug.com/770375"""
  time.sleep(seconds)


def _should_ignore_delay_for_testing() -> bool:
  return cast(
      bool,
      environment.get_value('PY_UNITTESTS') or
      environment.get_value('INTEGRATION') or
      environment.get_value('UNTRUSTED_RUNNER_TESTS') or
      environment.get_value('LOCAL_DEVELOPMENT') or
      environment.get_value('UTASK_TESTS'))


def get_delay(num_try: int, delay: float | int,
              backoff: float | int) -> float | int:
  """Compute backoff delay."""
  delay = delay * (backoff**(num_try - 1))
  if _should_ignore_delay_for_testing():
    # Don't sleep for long during tests. Flake is better.
    return min(delay, 3)

  return delay


def wrap(retries: int,
         delay: float | int,
         function: str,
         backoff: float | int = 2,
         exception_types: Optional[Sequence[type[BaseException]]] = None,
         retry_on_false: bool = False) -> Callable[[Any], Any]:
  """Retry decorator for a function."""

  assert delay > 0
  assert backoff >= 1
  assert retries >= 0

  if exception_types is None:
    exception_types = [Exception]

  def is_exception_type(exception: BaseException) -> bool:
    return any(
        isinstance(exception, exception_type)
        for exception_type in exception_types)

  def decorator(func: Any) -> Any:
    """Decorator for the given function."""
    tries = retries + 1
    is_generator = inspect.isgeneratorfunction(func)
    function_with_type = function
    if is_generator:
      function_with_type += ' (generator)'

    def handle_retry(num_try: int,
                     exception: Optional[BaseException] = None) -> bool:
      """Handle retry."""
      from clusterfuzz._internal.metrics import monitoring_metrics

      if (exception is None or
          is_exception_type(exception)) and num_try < tries:
        logs.info(
            'Retrying on %s failed with %s. Retrying again.' %
            (function_with_type, sys.exc_info()[1]),
            num=num_try,
            total=tries)
        sleep(get_delay(num_try, delay, backoff))
        return True

      monitoring_metrics.TRY_COUNT.increment({
          'function': function,
          'is_succeeded': False
      })
      logs.error(
          'Retrying on %s failed with %s. Raise.' % (function_with_type,
                                                     sys.exc_info()[1]),
          total=tries)
      return False

    @functools.wraps(func)
    def _wrapper(*args: Any, **kwargs: Any) -> Any:
      """Regular function wrapper."""
      from clusterfuzz._internal.metrics import monitoring_metrics

      for num_try in range(1, tries + 1):
        try:
          result = func(*args, **kwargs)
          if retry_on_false and not result:
            if not handle_retry(num_try):
              return result

            continue

          monitoring_metrics.TRY_COUNT.increment({
              'function': function,
              'is_succeeded': True
          })
          return result
        except Exception as e:
          if not handle_retry(num_try, exception=e):
            raise

      return None

    @functools.wraps(func)
    def _generator_wrapper(*args: Any, **kwargs: Any) -> Any:
      """Generator function wrapper."""
      # This argument is not applicable for generator functions.
      assert not retry_on_false

      from clusterfuzz._internal.metrics import monitoring_metrics

      already_yielded_element_count = 0
      for num_try in range(1, tries + 1):
        try:
          for index, result in enumerate(func(*args, **kwargs)):
            if index >= already_yielded_element_count:
              yield result
              already_yielded_element_count += 1

          monitoring_metrics.TRY_COUNT.increment({
              'function': function,
              'is_succeeded': True
          })
          break
        except Exception as e:
          if not handle_retry(num_try, exception=e):
            raise

    if is_generator:
      return _generator_wrapper
    return _wrapper

  return decorator
