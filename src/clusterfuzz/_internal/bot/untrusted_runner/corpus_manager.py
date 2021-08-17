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
"""Remote corpus manager."""

from clusterfuzz._internal.fuzzing import corpus_manager
from clusterfuzz._internal.google_cloud_utils import gsutil

from . import remote_process_host


class RemoteGSUtilRunner(gsutil.GSUtilRunner):
  """Remote GSUtil runner."""

  def __init__(self):
    super(
        RemoteGSUtilRunner,
        self).__init__(_process_runner=remote_process_host.RemoteProcessRunner)


class RemoteFuzzTargetCorpus(corpus_manager.FuzzTargetCorpus):
  """libFuzzer corpus sync that runs on untrusted bot."""

  def __init__(self, fuzzer_name, fuzzer_executable_name, quarantine=False):
    super(RemoteFuzzTargetCorpus, self).__init__(
        fuzzer_name,
        fuzzer_executable_name,
        quarantine,
        # Never log results for remote corpora since the state is on the worker.
        log_results=False,
        _gsutil_runner=RemoteGSUtilRunner)
