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
"""Tasks RPC implementations."""
from __future__ import absolute_import

from google.protobuf import wrappers_pb2
from google.protobuf.any_pb2 import Any
import six

from . import protobuf_utils

from bot import testcase_manager
from bot.fuzzers import engine
from bot.tasks import corpus_pruning_task
from bot.tasks import fuzz_task
from bot.tasks import minimize_task
from datastore import data_types
from protos import untrusted_runner_pb2


def _proto_to_fuzz_target(proto):
  """Convert protobuf to FuzzTarget."""
  return data_types.FuzzTarget(
      engine=proto.engine, project=proto.project, binary=proto.binary)


def _proto_to_cross_pollinate_fuzzer(proto):
  """Convert protobuf to CrossPollinateFuzzer."""
  return corpus_pruning_task.CrossPollinateFuzzer(
      fuzz_target=_proto_to_fuzz_target(proto.fuzz_target),
      backup_bucket_name=proto.backup_bucket_name,
      corpus_engine_name=proto.corpus_engine_name)


def prune_corpus(request, _):
  """Prune corpus."""
  context = corpus_pruning_task.Context(
      _proto_to_fuzz_target(request.fuzz_target), [
          _proto_to_cross_pollinate_fuzzer(proto)
          for proto in request.cross_pollinate_fuzzers
      ])

  result = corpus_pruning_task.do_corpus_pruning(
      context, request.last_execution_failed, request.revision)

  # Intentionally skip edge and function coverage values as those would come
  # from fuzzer coverage cron task (see src/go/server/cron/coverage.go).
  coverage_info = untrusted_runner_pb2.CoverageInfo(
      corpus_size_units=result.coverage_info.corpus_size_units,
      corpus_size_bytes=result.coverage_info.corpus_size_bytes,
      corpus_location=result.coverage_info.corpus_location,
      corpus_backup_location=result.coverage_info.corpus_backup_location,
      quarantine_size_units=result.coverage_info.quarantine_size_units,
      quarantine_size_bytes=result.coverage_info.quarantine_size_bytes,
      quarantine_location=result.coverage_info.quarantine_location)

  crashes = [
      untrusted_runner_pb2.CorpusCrash(
          crash_state=crash.crash_state,
          crash_type=crash.crash_type,
          crash_address=crash.crash_address,
          crash_stacktrace=protobuf_utils.encode_utf8_if_unicode(
              crash.crash_stacktrace),
          unit_path=crash.unit_path,
          security_flag=crash.security_flag,
      ) for crash in result.crashes
  ]

  return untrusted_runner_pb2.PruneCorpusResponse(
      coverage_info=coverage_info,
      crashes=crashes,
      fuzzer_binary_name=result.fuzzer_binary_name,
      revision=result.revision)


def process_testcase(request, _):
  """Process testcase."""
  tool_name_map = {
      untrusted_runner_pb2.ProcessTestcaseRequest.MINIMIZE: 'minimize',
      untrusted_runner_pb2.ProcessTestcaseRequest.CLEANSE: 'cleanse',
  }

  # TODO(ochang): Support other engines.
  assert request.engine == 'libFuzzer'
  assert request.operation in tool_name_map

  result = minimize_task.run_libfuzzer_engine(
      tool_name_map[request.operation], request.target_name, request.arguments,
      request.testcase_path, request.output_path, request.timeout)

  return untrusted_runner_pb2.EngineReproduceResult(
      return_code=result.return_code,
      time_executed=result.time_executed,
      output=result.output)


def engine_fuzz(request, _):
  """Run engine fuzzer."""
  engine_impl = engine.get(request.engine)
  result, fuzzer_metadata = fuzz_task.run_engine_fuzzer(
      engine_impl, request.target_name, request.sync_corpus_directory,
      request.testcase_directory)

  crashes = [
      untrusted_runner_pb2.EngineCrash(
          input_path=crash.input_path,
          stacktrace=protobuf_utils.encode_utf8_if_unicode(crash.stacktrace),
          reproduce_args=crash.reproduce_args,
          crash_time=crash.crash_time) for crash in result.crashes
  ]

  packed_stats = {}
  for key, value in six.iteritems(result.stats):
    packed_value = Any()
    if isinstance(value, float):
      packed_value.Pack(wrappers_pb2.DoubleValue(value=value))
    elif isinstance(value, int):
      packed_value.Pack(wrappers_pb2.Int32Value(value=value))
    elif isinstance(value, six.string_types):
      packed_value.Pack(wrappers_pb2.StringValue(value=value))
    else:
      raise ValueError('Unknown stat type for ' + key)

    packed_stats[key] = packed_value

  return untrusted_runner_pb2.EngineFuzzResponse(
      logs=protobuf_utils.encode_utf8_if_unicode(result.logs),
      command=result.command,
      crashes=crashes,
      stats=packed_stats,
      time_executed=result.time_executed,
      fuzzer_metadata=fuzzer_metadata)


def engine_reproduce(request, _):
  """Run engine reproduce."""
  engine_impl = engine.get(request.engine)
  result = testcase_manager.engine_reproduce(engine_impl, request.target_name,
                                             request.testcase_path,
                                             request.arguments, request.timeout)
  return untrusted_runner_pb2.EngineReproduceResult(
      command=result.command,
      return_code=result.return_code,
      time_executed=result.time_executed,
      output=result.output)
