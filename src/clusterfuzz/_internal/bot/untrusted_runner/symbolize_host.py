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

from typing import cast

from clusterfuzz._internal.protos import untrusted_runner_pb2
from clusterfuzz._internal.protos import untrusted_runner_pb2_grpc

from . import host
from . import protobuf_utils


def symbolize_stacktrace(unsymbolized_crash_stacktrace: str,
                         enable_inline_frames: bool = True) -> str:
  """Symbolize stacktrace."""
  request = untrusted_runner_pb2.SymbolizeStacktraceRequest(  # pylint: disable=no-member
      unsymbolized_crash_stacktrace=protobuf_utils.encode_utf8_if_unicode(
          unsymbolized_crash_stacktrace),  # type: ignore
      enable_inline_frames=enable_inline_frames)

  stub = cast(untrusted_runner_pb2_grpc.UntrustedRunnerStub, host.stub())
  response = stub.SymbolizeStacktrace(request)
  return response.symbolized_stacktrace
