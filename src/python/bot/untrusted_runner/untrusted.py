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
"""Untrusted instance."""
from __future__ import absolute_import

from builtins import object
import functools
import grpc
import os
import threading
import time
import traceback

from concurrent import futures

from . import build_setup
from . import config
from . import file_impl
from . import remote_process
from . import symbolize
from . import tasks_impl

from base import utils
from google_cloud_utils import compute_metadata
from metrics import logs
from protos import heartbeat_pb2
from protos import heartbeat_pb2_grpc
from protos import untrusted_runner_pb2
from protos import untrusted_runner_pb2_grpc
from system import environment
from system import process_handler
from system import shell

SHUTDOWN_GRACE_SECONDS = 5


class WorkerState(object):
  """Worker's state."""

  def __init__(self):
    self.server = None
    self.shutting_down = threading.Event()
    self.start_time = None


_worker_state = WorkerState()

# Used to detect overlapping RPCs.
_rpc_count_lock = threading.Lock()
_rpc_count = 0


def wrap_servicer(func):
  """Wrap a servicer to add additional functionality."""

  @functools.wraps(func)
  def wrapper(self, request, context):  # pylint: disable=unused-argument
    """Wrapper function."""
    global _rpc_count

    # Check if there is a in-progress RPC.
    with _rpc_count_lock:
      if _rpc_count > 0:
        logs.log_error('Hung RPC detected, shutting down.')
        _worker_state.shutting_down.set()
        return None

      _rpc_count += 1

    try:
      result = func(self, request, context)
    except Exception:
      # Include full exception details.
      context.set_code(grpc.StatusCode.UNKNOWN)
      context.set_details(traceback.format_exc())
      raise
    finally:
      with _rpc_count_lock:
        assert _rpc_count_lock > 0
        _rpc_count -= 1

    return result

  return wrapper


class UntrustedRunnerServicer(
    untrusted_runner_pb2_grpc.UntrustedRunnerServicer):
  """Untrusted runner implementation."""

  @wrap_servicer
  def GetStatus(self, request, context):  # pylint: disable=unused-argument
    return untrusted_runner_pb2.GetStatusResponse(
        revision=utils.current_source_version(),
        start_time=_worker_state.start_time,
        bot_name=environment.get_value('BOT_NAME'))

  @wrap_servicer
  def SetupRegularBuild(self, request, _):
    return build_setup.setup_regular_build(request)

  @wrap_servicer
  def SetupSymbolizedBuild(self, request, _):
    return build_setup.setup_symbolized_build(request)

  @wrap_servicer
  def SetupProductionBuild(self, request, _):
    return build_setup.setup_production_build(request)

  @wrap_servicer
  def RunAndWait(self, request, context):
    return remote_process.run_and_wait(request, context)

  @wrap_servicer
  def RunProcess(self, request, context):
    return remote_process.run_process(request, context)

  @wrap_servicer
  def CreateDirectory(self, request, context):
    return file_impl.create_directory(request, context)

  @wrap_servicer
  def RemoveDirectory(self, request, context):
    return file_impl.remove_directory(request, context)

  @wrap_servicer
  def ListFiles(self, request, context):
    return file_impl.list_files(request, context)

  @wrap_servicer
  def CopyFileTo(self, request_iterator, context):
    return file_impl.copy_file_to_worker(request_iterator, context)

  @wrap_servicer
  def CopyFileFrom(self, request, context):
    return file_impl.copy_file_from_worker(request, context)

  @wrap_servicer
  def Stat(self, request, context):
    return file_impl.stat(request, context)

  @wrap_servicer
  def UpdateEnvironment(self, request, _):
    os.environ.update(request.env)
    return untrusted_runner_pb2.UpdateEnvironmentResponse()

  @wrap_servicer
  def ResetEnvironment(self, _, context):  # pylint: disable=unused-argument
    environment.reset_environment()
    return untrusted_runner_pb2.ResetEnvironmentResponse()

  @wrap_servicer
  def UpdateSource(self, request, context):  # pylint: disable=unused-argument
    # Exit and let run.py update source.
    _worker_state.shutting_down.set()
    return untrusted_runner_pb2.UpdateSourceResponse()

  @wrap_servicer
  def SymbolizeStacktrace(self, request, _):
    return symbolize.symbolize_stacktrace(request)

  @wrap_servicer
  def TerminateStaleApplicationInstances(self, request, context):  # pylint: disable=unused-argument
    process_handler.terminate_stale_application_instances()
    return untrusted_runner_pb2.TerminateStaleApplicationInstancesResponse()

  @wrap_servicer
  def GetFuzzTargets(self, request, context):
    return file_impl.get_fuzz_targets(request, context)

  @wrap_servicer
  def ProcessTestcase(self, request, context):
    return tasks_impl.process_testcase(request, context)

  @wrap_servicer
  def PruneCorpus(self, request, context):
    return tasks_impl.prune_corpus(request, context)


class HeartbeatServicer(heartbeat_pb2_grpc.HeartbeatServicer):
  """Heartbeat service (for keeping connections alive)."""

  def Beat(self, _, context):  # pylint: disable=unused-argument
    return heartbeat_pb2.HeartbeatResponse()


def _get_tls_cert_and_key():
  """Get the TLS cert from instance metadata."""
  # TODO(ochang): Implement a fake metadata server for testing.
  local_cert_location = environment.get_value('UNTRUSTED_TLS_CERT_FOR_TESTING')
  local_key_location = environment.get_value('UNTRUSTED_TLS_KEY_FOR_TESTING')

  if local_cert_location and local_key_location:
    with open(local_cert_location) as f:
      cert_contents = f.read()

    with open(local_key_location) as f:
      key_contents = f.read()

    return cert_contents, key_contents

  return (str(compute_metadata.get('instance/attributes/tls-cert')),
          str(compute_metadata.get('instance/attributes/tls-key')))


def start_server():
  """Start the server."""
  # Check overall free disk space. If we are running too low, clear all
  # data directories like builds, fuzzers, data bundles, etc.
  shell.clear_data_directories_on_low_disk_space()

  cert_contents, key_contents = _get_tls_cert_and_key()
  assert cert_contents and key_contents
  server_credentials = grpc.ssl_server_credentials([(key_contents,
                                                     cert_contents)])
  _worker_state.server = grpc.server(
      futures.ThreadPoolExecutor(max_workers=config.NUM_WORKER_THREADS),
      options=config.GRPC_OPTIONS)

  untrusted_runner_pb2_grpc.add_UntrustedRunnerServicer_to_server(
      UntrustedRunnerServicer(), _worker_state.server)
  heartbeat_pb2_grpc.add_HeartbeatServicer_to_server(HeartbeatServicer(),
                                                     _worker_state.server)

  _worker_state.server.add_secure_port('[::]:%d' % config.PORT,
                                       server_credentials)

  _worker_state.start_time = int(time.time())
  _worker_state.server.start()

  logs.log('Server started.')

  # Run forever until shutdown.
  _worker_state.shutting_down.wait()

  logs.log('Server shutting down.')
  stopped = _worker_state.server.stop(SHUTDOWN_GRACE_SECONDS)
  stopped.wait()

  # Prevent python GIL deadlocks on shutdown. See https://crbug.com/744680.
  # pylint: disable=protected-access
  os._exit(0)


def server():
  """Return the grpc.Server."""
  return _worker_state.server
