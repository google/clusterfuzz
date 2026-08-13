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
"""Stack parser module."""

import inspect
import re
from typing import Any

from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.protos import process_state_pb2


def unsigned_to_signed(address: int) -> int:
  """Convert unsigned address to signed int64 (as defined in the proto)."""
  return (address - 2**64) if address >= 2**63 else address


def format_address_to_dec(address: object, base: int = 16) -> int | None:
  """Addresses may be formatted as decimal, hex string with 0x or 0X prefix,
     or without any prefix. Convert to decimal int."""
  if address is None:
    return None

  address_str = str(address).replace('`', '').strip()
  if not address_str:
    return None

  # This is required for Chrome Win and Mac stacks, which mix decimal and hex.
  try_bases = [base, 16] if base != 16 else [base]
  for base_try in try_bases:
    try:
      return int(address_str, base_try)
    except Exception:
      continue

  logs.warning('Error formatting address %s to decimal int64 in bases %s.' %
               (str(address_str), str(try_bases)))
  return None


class StackFrameStructure:
  """IR for fields a stackframe may conptain/expect."""

  def __init__(
      self,
      address: Any = None,
      function_name: Any = None,
      function_base: Any = None,
      function_offset: Any = None,
      filename: Any = None,
      fileline: Any = None,
      module_name: Any = None,
      module_base: Any = None,
      module_offset: Any = None,
  ) -> None:
    self._address: Any = address
    self._function_name: Any = function_name
    self._function_base: Any = function_base
    self._function_offset: Any = function_offset
    self._filename: Any = filename
    self._fileline: Any = fileline
    self._module_name: Any = module_name
    self._module_base: Any = module_base
    self._module_offset: Any = module_offset

  @property
  def address(self) -> Any:
    return self._address

  @address.setter
  def address(self, address: Any) -> None:
    self._address = address

  @property
  def function_name(self) -> Any:
    return self._function_name

  @function_name.setter
  def function_name(self, function_name: Any) -> None:
    self._function_name = function_name

  @property
  def function_base(self) -> Any:
    return self._function_base

  @function_base.setter
  def function_base(self, function_base: Any) -> None:
    self._function_base = function_base

  @property
  def function_offset(self) -> Any:
    return self._function_offset

  @function_offset.setter
  def function_offset(self, function_offset: Any) -> None:
    self._function_offset = function_offset

  @property
  def filename(self) -> Any:
    return self._filename

  @filename.setter
  def filename(self, filename: Any) -> None:
    self._filename = filename

  @property
  def fileline(self) -> Any:
    return self._fileline

  @fileline.setter
  def fileline(self, fileline: Any) -> None:
    self._fileline = fileline

  @property
  def module_name(self) -> Any:
    return self._module_name

  @module_name.setter
  def module_name(self, module_name: Any) -> None:
    self._module_name = module_name

  @property
  def module_base(self) -> Any:
    return self._module_base

  @module_base.setter
  def module_base(self, module_base: Any) -> None:
    self._module_base = module_base

  @property
  def module_offset(self) -> Any:
    return self._module_offset

  @module_offset.setter
  def module_offset(self, module_offset: Any) -> None:
    self._module_offset = module_offset

  def to_proto(self) -> process_state_pb2.StackFrame:  # pylint: disable=no-member
    """Convert StackFrame to process_state.proto format for upload to crash/."""
    frame_proto = process_state_pb2.StackFrame()  # pylint: disable=no-member
    if self.address is not None:
      frame_proto.instruction = unsigned_to_signed(int(self.address))
    if self.module_base is not None:
      frame_proto.module.base_address = unsigned_to_signed(  # pylint: disable=no-member
          int(self.module_base))
    if self.module_name is not None:
      frame_proto.module.code_file = str(self.module_name)  # pylint: disable=no-member
    if self.function_name is not None:
      frame_proto.function_name = str(self.function_name)
    if self.function_base is not None:
      frame_proto.function_base = unsigned_to_signed(int(self.function_base))
    if self.filename is not None:
      frame_proto.source_file_name = str(self.filename)
    if self.fileline is not None:
      frame_proto.source_line = int(self.fileline)

    return frame_proto


class StackFrame(StackFrameStructure):
  """IR for canonicalizing stackframe strings."""

  base: int

  def __init__(
      self,
      address: object = None,
      function_name: object = None,
      function_base: object = None,
      function_offset: object = None,
      filename: object = None,
      fileline: object = None,
      module_name: object = None,
      module_base: object = None,
      module_offset: object = None,
      base: int = 16,
  ) -> None:
    super().__init__(
        address=format_address_to_dec(address),
        function_name=function_name,
        function_base=format_address_to_dec(function_base),
        function_offset=format_address_to_dec(function_offset),
        filename=filename,
        fileline=fileline,
        module_name=module_name,
        module_base=format_address_to_dec(module_base),
        module_offset=format_address_to_dec(module_offset))

    # Base for converting addresses set in frame. Most will be in hex.
    self._base: int = base

  def __setattr__(self, field_name: str, field_value: Any) -> None:
    """Set attributes, performing conversions as needed for address fields."""
    if field_name == 'base':
      self._base = field_value
      return

    address_fields = [
        'address',
        'function_base',
        'function_offset',
        'module_base',
        'module_offset',
    ]
    if field_name in address_fields:
      address = format_address_to_dec(field_value, self._base)
      super().__setattr__(field_name, address)
      return

    super().__setattr__(field_name, field_value)

  def __str__(self) -> str:
    s: list[str] = []
    for name, member in inspect.getmembers(StackFrame):
      if not isinstance(member, property):
        continue
      s += ['%s: %s' % (name, str(getattr(self, name)))]
    return ', '.join(s)


class StackFrameSpec(StackFrameStructure):
  """Representation paralleling that of StackFrames for pulling out the correct
     groups in a *_STACK_FRAME_REGEX match."""

  def __init__(
      self,
      address: Any = None,
      function_name: Any = None,
      function_base: Any = None,
      function_offset: Any = None,
      filename: Any = None,
      fileline: Any = None,
      module_name: Any = None,
      module_base: Any = None,
      module_offset: Any = None,
      base: int = 16,
  ) -> None:
    """Specify a stackframe format. Each field should be an index into a match.
       See comments inline *_STACK_FRAME_REGEX for appropriate indices."""
    address_val = address if address is not None else []
    function_name_val = function_name if function_name is not None else []
    function_base_val = function_base if function_base is not None else []
    function_offset_val = function_offset if function_offset is not None else []
    filename_val = filename if filename is not None else []
    fileline_val = fileline if fileline is not None else []
    module_name_val = module_name if module_name is not None else []
    module_base_val = module_base if module_base is not None else []
    module_offset_val = module_offset if module_offset is not None else []
    super().__init__(
        address=address_val,
        function_name=function_name_val,
        function_base=function_base_val,
        function_offset=function_offset_val,
        filename=filename_val,
        fileline=fileline_val,
        module_name=module_name_val,
        module_base=module_base_val,
        module_offset=module_offset_val)

    # Base for converting addresses processed by this spec. Most will be in hex.
    self._base: int = base

  @property
  def base(self) -> int:
    return self._base

  @base.setter
  def base(self, base: int) -> None:
    self._base = base

  def parse_stack_frame(
      self,
      frame_match: re.Match[str] | None,
  ) -> StackFrame | None:
    """Given a match and stackframe specification, populate a stackframe with
       information from the match."""
    if frame_match is None:
      return None

    frame = StackFrame()

    # Set base to use for address translation.
    frame.base = self.base  # pylint: disable=attribute-defined-outside-init
    for name, member in inspect.getmembers(StackFrameSpec):
      # Pull out only the property fields; we don't care about methods etc.
      if not isinstance(member, property):
        continue

      # We've already set the base (which we need to do first); skip.
      if name == 'base':
        continue

      # Populate the stackframe field. Try all provided lookup groups.
      indices = getattr(self, name)
      if not isinstance(indices, list):
        indices = [indices]
        setattr(self, name, indices)
      for ind in indices:
        frame_field = frame_match.group(ind)
        if frame_field is not None and frame_field:
          setattr(frame, name, frame_field.strip())
          break

    return frame
