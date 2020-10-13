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
"""Tasks host."""

import datetime

from google.protobuf import wrappers_pb2
import grpc
import six

from . import host

from bot import testcase_manager
from bot.tasks import corpus_pruning_task
from bot.untrusted_runner import file_host
from datastore import data_types
from lib.clusterfuzz.fuzz import engine
from protos import untrusted_runner_pb2


def _fuzz_target_to_proto(fuzz_target):
  """Convert fuzz_target to protobuf."""
  return untrusted_runner_pb2.FuzzTarget(
      engine=fuzz_target.engine,
      project=fuzz_target.project,
      binary=fuzz_target.binary,
  )


def do_corpus_pruning(context, last_execution_failed, revision):
  """Do corpus pruning on untrusted worker."""
  cross_pollinate_fuzzers = [
      untrusted_runner_pb2.CrossPollinateFuzzer(
          fuzz_target=_fuzz_target_to_proto(cpf.fuzz_target),
          backup_bucket_name=cpf.backup_bucket_name,
          corpus_engine_name=cpf.corpus_engine_name,
      ) for cpf in context.cross_pollinate_fuzzers
  ]

  request = untrusted_runner_pb2.PruneCorpusRequest(
      fuzz_target=_fuzz_target_to_proto(context.fuzz_target),
      cross_pollinate_fuzzers=cross_pollinate_fuzzers,
      last_execution_failed=last_execution_failed,
      revision=revision)

  response = host.stub().PruneCorpus(request)

  project_qualified_name = context.fuzz_target.project_qualified_name()
  today_date = datetime.datetime.utcnow().date()
  coverage_info = data_types.CoverageInformation(
      fuzzer=project_qualified_name, date=today_date)

  # Intentionally skip edge and function coverage values as those would come
  # from fuzzer coverage cron task (see src/go/server/cron/coverage.go).
  coverage_info.corpus_size_units = response.coverage_info.corpus_size_units
  coverage_info.corpus_size_bytes = response.coverage_info.corpus_size_bytes
  coverage_info.corpus_location = response.coverage_info.corpus_location
  coverage_info.corpus_backup_location = (
      response.coverage_info.corpus_backup_location)
  coverage_info.quarantine_size_units = (
      response.coverage_info.quarantine_size_units)
  coverage_info.quarantine_size_bytes = (
      response.coverage_info.quarantine_size_bytes)
  coverage_info.quarantine_location = response.coverage_info.quarantine_location

  crashes = [
      corpus_pruning_task.CorpusCrash(
          crash_state=crash.crash_state,
          crash_type=crash.crash_type,
          crash_address=crash.crash_address,
          crash_stacktrace=crash.crash_stacktrace,
          unit_path=crash.unit_path,
          security_flag=crash.security_flag,
      ) for crash in response.crashes
  ]

  result_stats = response.cross_pollination_stats
  pollination_stats = corpus_pruning_task.CrossPollinationStats(
      project_qualified_name=result_stats.project_qualified_name,
      method=result_stats.method,
      sources=result_stats.sources,
      tags=result_stats.tags,
      initial_corpus_size=result_stats.initial_corpus_size,
      corpus_size=result_stats.corpus_size,
      initial_edge_coverage=result_stats.initial_edge_coverage,
      edge_coverage=result_stats.edge_coverage,
      initial_feature_coverage=result_stats.initial_feature_coverage,
      feature_coverage=result_stats.feature_coverage)

  return corpus_pruning_task.CorpusPruningResult(
      coverage_info=coverage_info,
      crashes=crashes,
      fuzzer_binary_name=response.fuzzer_binary_name,
      revision=response.revision,
      cross_pollination_stats=pollination_stats)


def process_testcase(engine_name, tool_name, target_name, arguments,
                     testcase_path, output_path, timeout):
  """Process testcase on untrusted worker."""
  if tool_name == 'minimize':
    operation = untrusted_runner_pb2.ProcessTestcaseRequest.MINIMIZE
  else:
    operation = untrusted_runner_pb2.ProcessTestcaseRequest.CLEANSE

  rebased_testcase_path = file_host.rebase_to_worker_root(testcase_path)
  file_host.copy_file_to_worker(testcase_path, rebased_testcase_path)

  request = untrusted_runner_pb2.ProcessTestcaseRequest(
      engine=engine_name,
      operation=operation,
      target_name=target_name,
      arguments=arguments,
      testcase_path=file_host.rebase_to_worker_root(testcase_path),
      output_path=file_host.rebase_to_worker_root(output_path),
      timeout=timeout)

  response = host.stub().ProcessTestcase(request)

  rebased_output_path = file_host.rebase_to_worker_root(output_path)
  file_host.copy_file_from_worker(rebased_output_path, output_path)

  return engine.ReproduceResult(
      list(response.command), response.return_code, response.time_executed,
      response.output)


def _unpack_values(values):
  """Unpack protobuf values."""
  unpacked = {}
  for key, packed_value in six.iteritems(values):
    if packed_value.Is(wrappers_pb2.DoubleValue.DESCRIPTOR):
      value = wrappers_pb2.DoubleValue()
    elif packed_value.Is(wrappers_pb2.Int64Value.DESCRIPTOR):
      value = wrappers_pb2.Int64Value()
    elif packed_value.Is(wrappers_pb2.StringValue.DESCRIPTOR):
      value = wrappers_pb2.StringValue()
    else:
      raise ValueError('Unknown stat type for ' + key)

    packed_value.Unpack(value)
    unpacked[key] = value.value

  return unpacked


def engine_fuzz(engine_impl, target_name, sync_corpus_directory,
                testcase_directory):
  """Run engine fuzzer on untrusted worker."""
  request = untrusted_runner_pb2.EngineFuzzRequest(
      engine=engine_impl.name,
      target_name=target_name,
      sync_corpus_directory=file_host.rebase_to_worker_root(
          sync_corpus_directory),
      testcase_directory=file_host.rebase_to_worker_root(testcase_directory))

  response = host.stub().EngineFuzz(request)
  crashes = [
      engine.Crash(
          input_path=file_host.rebase_to_host_root(crash.input_path),
          stacktrace=crash.stacktrace,
          reproduce_args=crash.reproduce_args,
          crash_time=crash.crash_time) for crash in response.crashes
  ]

  unpacked_stats = _unpack_values(response.stats)
  unpacked_strategies = _unpack_values(response.strategies)

  result = engine.FuzzResult(
      logs=response.logs,
      command=list(response.command),
      crashes=crashes,
      stats=unpacked_stats,
      time_executed=response.time_executed)

  file_host.pull_testcases_from_worker()
  return result, dict(response.fuzzer_metadata), unpacked_strategies


def engine_reproduce(engine_impl, target_name, testcase_path, arguments,
                     timeout):
  """Run engine reproduce on untrusted worker."""
  rebased_testcase_path = file_host.rebase_to_worker_root(testcase_path)
  file_host.copy_file_to_worker(testcase_path, rebased_testcase_path)

  request = untrusted_runner_pb2.EngineReproduceRequest(
      engine=engine_impl.name,
      target_name=target_name,
      testcase_path=rebased_testcase_path,
      arguments=arguments,
      timeout=timeout)

  try:
    response = host.stub().EngineReproduce(request)
  except grpc.RpcError as e:
    if 'TargetNotFoundError' in repr(e):
      # Resurface the right exception.
      raise testcase_manager.TargetNotFoundError('Failed to find target ' +
                                                 target_name)
    raise

  return engine.ReproduceResult(
      list(response.command), response.return_code, response.time_executed,
      response.output)
