# Copyright 2023 Google LLC
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
"""Module for handling errors in utasks."""

from typing import Callable
from typing import Dict

from clusterfuzz._internal.protos import uworker_msg_pb2

# A handler takes an output object with its `error_type` set, and does whatever
# it wants with it.
ErrorHandler = Callable[[uworker_msg_pb2.Output], None]  # pylint: disable=no-member

# Must use string type because of protobuf enum shenanigans.
HandlerDict = Dict['uworker_msg_pb2.ErrorType', ErrorHandler]


class CompositeErrorHandler:
  """A handler for several different types of uworker errors."""

  def __init__(self, handlers: HandlerDict):
    """Initializes a handler that delegates to the values in `handlers`.

    For example:

      CompositeErrorHandler({FOO: handle_foo, BAR: handle_bar})

    Will delegate handling `FOO` errors to `handle_foo`, and `BAR` errors
    to `handle_bar`.
    """
    self._handlers = handlers

  # Must use string types because `CompositeErrorHandler` is not defined yet.
  def compose_with(self,
                   *args: 'CompositeErrorHandler') -> 'CompositeErrorHandler':
    """Adds all handlers from the given composite handlers to this instance.
    Returns `self` for chaining.

    Eachn handler (including `self`) must handle a disjoint set of error types.

    Raises:
      ValueError: if any two handlers (including `self`) handle the same error
        type.
    """
    for other in args:
      for error_type, handler in other._handlers.items():  # pylint: disable=protected-access
        if error_type in self._handlers:
          raise ValueError(f'Duplicate handlers for error type {error_type}')

        self._handlers[error_type] = handler

    return self

  def is_handled(self, error_type: uworker_msg_pb2.ErrorType) -> bool:  # pylint: disable=no-member
    """Returns whether the given error type is handled by this instance."""
    return error_type in self._handlers

  def handle(self, output: uworker_msg_pb2.Output):  # pylint: disable=no-member
    """Handles the given `output`, delegating to underlying handlers.

    Raises:
      RuntimeError: if `output.error_type` is not handled by this instance.
    """
    handler = self._handlers.get(output.error_type)
    if handler is None:
      raise RuntimeError(f'Cannot handle error type {output.error_type}')

    handler(output)


def noop_handler(*args, **kwargs):
  del args
  del kwargs


# A composite error handler for `UNHANDLED` errors, that ignores such errors.
UNHANDLED_ERROR_HANDLER = CompositeErrorHandler({
    uworker_msg_pb2.ErrorType.UNHANDLED: noop_handler,  # pylint: disable=no-member
})
