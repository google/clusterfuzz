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

import host

from base import utils
from bot.tasks import corpus_pruning_task
from datastore import data_types
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
          crash_stacktrace=utils.decode_to_unicode(crash.crash_stacktrace),
          unit_path=crash.unit_path,
          security_flag=crash.security_flag,
      ) for crash in response.crashes
  ]

  return corpus_pruning_task.CorpusPruningResult(
      coverage_info=coverage_info,
      crashes=crashes,
      fuzzer_binary_name=response.fuzzer_binary_name,
      revision=response.revision)
