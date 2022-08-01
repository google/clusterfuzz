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
"""Tests for the stack frame module."""

import re
import unittest

from clusterfuzz._internal.crash_analysis.stack_parsing import stack_parser


class StackFrameTestcase(unittest.TestCase):
  """Stack analyzer tests."""

  def test_parse_stack_frame(self):
    """Check that stackframes are correctly parsed."""
    spec = stack_parser.StackFrameSpec(
        address=1,
        filename=[4, 8],
        fileline=[5, 9],
    )
    stack_frame_regex = re.compile(
        r'([xXa-fA-F0-9]*) '
        # optional parts: filename:line:char or filename:line
        r'(((\w+):(\d+):(\d+))|((\w+):(\d+)))')
    stack_frame_lines = [
        '0xa1c0 a_file:1234:56',
        '0xa1c0 a_file:1234',
    ]
    stack_frames = []
    for stack_frame_line in stack_frame_lines:
      m = stack_frame_regex.match(stack_frame_line)
      stack_frames.append(spec.parse_stack_frame(m))

    for stack_frame in stack_frames:
      self.assertEqual(stack_frame.address, 41408)
      self.assertEqual(stack_frame.filename, 'a_file')
      self.assertEqual(stack_frame.fileline, '1234')

  def test_to_proto(self):
    """Test converting to protobuf."""
    stack_frame = stack_parser.StackFrame(
        address='0x1',
        function_name='fun',
        function_base='0x10',
        function_offset='0x03',
        filename='a_file.cc',
        fileline=42,
        module_name='modname',
        module_base='0x2',
        module_offset='0xbeef',
    )
    stack_frame_proto = stack_frame.to_proto()

    self.assertEqual(stack_frame_proto.instruction, 1)
    self.assertEqual(stack_frame_proto.module.base_address, 2)
    self.assertEqual(stack_frame_proto.module.code_file, 'modname')
    self.assertEqual(stack_frame_proto.function_name, 'fun')
    self.assertEqual(stack_frame_proto.function_base, 16)
    self.assertEqual(stack_frame_proto.source_file_name, 'a_file.cc')
    self.assertEqual(stack_frame_proto.source_line, 42)

  def test_to_proto_big_addresses(self):
    stack_frame = stack_parser.StackFrame(
        address='0xfffffffffffffff2',
        function_base='0xfffffffffffffff3',
        module_base='0x8000000000000000')
    stack_frame_proto = stack_frame.to_proto()

    self.assertEqual(stack_frame_proto.instruction, -14)
    self.assertEqual(stack_frame_proto.function_base, -13)
    self.assertEqual(stack_frame_proto.module.base_address,
                     -9223372036854775808)
