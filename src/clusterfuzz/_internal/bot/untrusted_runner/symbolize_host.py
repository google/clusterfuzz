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
"""Stacktrace symbolization (host side)."""

from clusterfuzz._internal.protos import untrusted_runner_pb2

from . import host
from . import protobuf_utils


def symbolize_stacktrace(unsymbolized_crash_stacktrace,
                         enable_inline_frames=True):
  """Symbolize stacktrace."""
  request = untrusted_runner_pb2.SymbolizeStacktraceRequest(
      unsymbolized_crash_stacktrace=protobuf_utils.encode_utf8_if_unicode(
          unsymbolized_crash_stacktrace),
      enable_inline_frames=enable_inline_frames)

  response = host.stub().SymbolizeStacktrace(request)
  return response.symbolized_stacktrace
