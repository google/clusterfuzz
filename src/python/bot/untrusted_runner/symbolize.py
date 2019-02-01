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
"""Stacktrace symbolization."""

from crash_analysis.stack_parsing import stack_symbolizer
from protos import untrusted_runner_pb2


def symbolize_stacktrace(request):
  """Symbolize stacktrace."""
  symbolized_stacktrace = stack_symbolizer.symbolize_stacktrace(
      request.unsymbolized_crash_stacktrace, request.enable_inline_frames)

  return untrusted_runner_pb2.SymbolizeStacktraceResponse(
      symbolized_stacktrace=symbolized_stacktrace)
