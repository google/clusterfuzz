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
"""Trusted host."""
from __future__ import absolute_import

from builtins import object
from builtins import range
import sys
import threading
import time

import grpc

from base import untrusted
from base import utils
from datastore import data_types
from datastore import ndb
from metrics import logs
from metrics import monitoring_metrics
from protos import heartbeat_pb2
from protos import heartbeat_pb2_grpc
from protos import untrusted_runner_pb2
from protos import untrusted_runner_pb2_grpc
from system import environment

from . import config

WAIT_TLS_CERT_SECONDS = 60
RPC_FAIL_WAIT_TIME = 10


class ChannelState(object):
  """The host's view of the channel state."""
  # Channel isn't ready for sending RPCs.
  NOT_READY = 0

  # Channel is ready for RPCS.
  READY = 1

  # The host found that the worker is in an inconsistent state. That is, we
  # detected that either the worker has a different source version, or if it
  # restarted without us knowing.
  INCONSISTENT = 2


class HostState(object):
  """The state of the host."""

  def __init__(self):
    self.channel = None
    self.stub = None
    self.heartbeat_thread = None
    self.expect_shutdown = False

    self.worker_start_time = None
    self.worker_bot_name = None

    # Protects access to |channel_state| and notifies when the state becomes
    # READY or INCONSISTENT.
    self.channel_condition = threading.Condition()
    self.channel_state = ChannelState.NOT_READY


_host_state = HostState()


class UntrustedRunnerStub(untrusted_runner_pb2_grpc.UntrustedRunnerStub):
  """Stub for making RPC calls.

  We override the generated stub because we need to wrap these RPC calls to add
  error handling/retry logic."""

  def __init__(self, channel):
    super(UntrustedRunnerStub, self).__init__(channel)

    # Don't wrap GetStatus() because it's used during connection state changes.
    # Don't wrap UpdateSource() because it can be expected to fail.

    # pylint: disable=invalid-name
    self.SetupRegularBuild = _wrap_call(self.SetupRegularBuild)
    self.SetupSymbolizedBuild = _wrap_call(self.SetupSymbolizedBuild)
    self.SetupProductionBuild = _wrap_call(self.SetupProductionBuild)
    self.RunProcess = _wrap_call(self.RunProcess)
    self.RunAndWait = _wrap_call(self.RunAndWait)
    self.CreateDirectory = _wrap_call(self.CreateDirectory)
    self.RemoveDirectory = _wrap_call(self.RemoveDirectory)
    self.ListFiles = _wrap_call(self.ListFiles)
    self.CopyFileTo = _wrap_call(self.CopyFileTo)
    self.CopyFileFrom = _wrap_call(self.CopyFileFrom)
    self.Stat = _wrap_call(self.Stat)
    self.UpdateEnvironment = _wrap_call(self.UpdateEnvironment)
    self.SymbolizeStacktrace = _wrap_call(self.SymbolizeStacktrace)
    self.GetFuzzTargets = _wrap_call(self.GetFuzzTargets)
    self.TerminateStaleApplicationInstances = _wrap_call(
        self.TerminateStaleApplicationInstances)
    self.ProcessTestcase = _wrap_call(self.ProcessTestcase)

    # The following are RPCs that execute larger tasks. Don't retry these.
    self.PruneCorpus = _wrap_call(self.PruneCorpus, num_retries=0)
    # pylint: enable=invalid-name


def _check_channel_state(wait_time):
  """Check the channel's state."""
  with _host_state.channel_condition:
    if (_host_state.channel_state == ChannelState.READY or
        _host_state.channel_state == ChannelState.INCONSISTENT):
      # Nothing to do in these states.
      return _host_state.channel_state

    # The channel is not ready, so we wait for a (re)connect.
    _host_state.channel_condition.wait(wait_time)
    return _host_state.channel_state


def _wrap_call(func, num_retries=config.RPC_RETRY_ATTEMPTS):
  """Wrapper for stub calls to add error handling and retry logic."""

  def wrapped(*args, **kwargs):
    """Wrapper for adding retry logic."""
    for retry_attempt in range(num_retries + 1):
      # Wait for channel to (re)connect if necessary.
      state = _check_channel_state(config.RECONNECT_TIMEOUT_SECONDS)

      if state == ChannelState.INCONSISTENT:
        # No point retrying if the worker is inconsistent.
        monitoring_metrics.HOST_INCONSISTENT_COUNT.increment()
        logs.log_warn('Worker got into an inconsistent state.')
        host_exit_no_return(return_code=0)

      if state == ChannelState.NOT_READY:
        # Channel still isn't ready.
        logs.log_warn(
            'Channel failed to become ready within reconnect timeout.')
        if retry_attempt == num_retries:
          # Last attempt.
          host_exit_no_return()

        continue

      try:
        return func(*args, **kwargs)
      except grpc.RpcError as e:
        logs.log_warn('Failed RPC: ' + str(e))
        if retry_attempt == num_retries:
          # Last attempt.
          host_exit_no_return()

        time.sleep(RPC_FAIL_WAIT_TIME)

  return wrapped


def _do_heartbeat():
  """Heartbeat thread."""
  # grpc stubs and channels should be thread-safe.
  heartbeat_stub = heartbeat_pb2_grpc.HeartbeatStub(_host_state.channel)
  while True:
    try:
      heartbeat_stub.Beat(
          heartbeat_pb2.HeartbeatRequest(),
          timeout=config.HEARTBEAT_TIMEOUT_SECONDS)
    except grpc.RpcError as e:
      logs.log_warn('worker heartbeat failed: ' + str(e))

    time.sleep(config.HEARTBEAT_INTERVAL_SECONDS)


def _get_host_worker_assignment():
  """Get the host worker assignment for the current host."""
  # This only needs to be called once before the host connects to the worker.
  # This is because the host->worker assignment algorithm should ensure that a
  # worker is reassigned only if it is also reimaged.
  #
  # If a worker is reimaged, then the host's connection state will be lost and
  # it will restart its run_bot.py instance to figure out which worker to
  # connect to again. We should never get into a case where worker re-assignment
  # happens without them being reimaged.
  key = ndb.Key(data_types.HostWorkerAssignment,
                environment.get_value('BOT_NAME'))
  return key.get()


def _get_root_cert(project_name):
  """Get the root TLS cert for connecting to the worker."""
  key = ndb.Key(data_types.WorkerTlsCert, project_name)
  tls_cert = key.get()
  if not tls_cert:
    return None

  assert tls_cert.cert_contents, 'Cert contents should not be empty.'
  return tls_cert.cert_contents


def _connect():
  """Initial connect to the worker."""
  worker_assignment = _get_host_worker_assignment()
  assert worker_assignment is not None
  assert worker_assignment.worker_name is not None
  assert worker_assignment.project_name is not None

  root_cert = _get_root_cert(worker_assignment.project_name)
  if not root_cert:
    logs.log_warn('TLS certs not yet generated.')
    time.sleep(WAIT_TLS_CERT_SECONDS)
    sys.exit(0)

  environment.set_value(
      'QUEUE_OVERRIDE',
      untrusted.platform_name(worker_assignment.project_name, 'linux'))

  server_name = worker_assignment.worker_name
  if not environment.get_value('LOCAL_DEVELOPMENT'):
    server_name += untrusted.internal_network_domain()

  _host_state.worker_bot_name = worker_assignment.worker_name

  credentials = grpc.ssl_channel_credentials(root_cert)
  _host_state.channel = grpc.secure_channel(
      '%s:%d' % (server_name, config.PORT),
      credentials=credentials,
      options=config.GRPC_OPTIONS)
  _host_state.stub = UntrustedRunnerStub(_host_state.channel)

  logs.log('Connecting to worker %s...' % server_name)
  _host_state.channel.subscribe(
      _channel_connectivity_changed, try_to_connect=True)

  channel_state = _check_channel_state(config.INITIAL_CONNECT_TIMEOUT_SECONDS)
  if channel_state == ChannelState.INCONSISTENT:
    logs.log_warn('Worker inconsistent on initial connect.')
    monitoring_metrics.HOST_INCONSISTENT_COUNT.increment()
    host_exit_no_return(return_code=0)

  if channel_state != ChannelState.READY:
    raise untrusted.HostException('Failed to connect to worker.')

  environment.set_value('WORKER_BOT_NAME', worker_assignment.worker_name)

  _host_state.heartbeat_thread = threading.Thread(target=_do_heartbeat)
  _host_state.heartbeat_thread.daemon = True
  _host_state.heartbeat_thread.start()


def _channel_connectivity_changed(connectivity):
  """Callback for channel connectivity changes."""
  try:
    with _host_state.channel_condition:
      if connectivity == grpc.ChannelConnectivity.READY:
        if _check_state():
          logs.log('Connected to worker.')
          _host_state.channel_state = ChannelState.READY
        else:
          _host_state.channel_state = ChannelState.INCONSISTENT

        _host_state.channel_condition.notify_all()
        return

      _host_state.channel_state = ChannelState.NOT_READY

    if connectivity == grpc.ChannelConnectivity.SHUTDOWN:
      if _host_state.expect_shutdown:
        # We requested a shutdown to update the source.
        logs.log('Worker shutting down.')
        return

      raise untrusted.HostException('Unrecoverable error.')
  except AttributeError:
    # Python sets all globals to None on shutdown. Ignore.
    logs.log('Shutting down.')
    return

  if connectivity == grpc.ChannelConnectivity.TRANSIENT_FAILURE:
    logs.log_warn('Transient failure detected on worker channel.')

  if connectivity == grpc.ChannelConnectivity.CONNECTING:
    logs.log('Reconnecting to worker.')


def _check_state():
  """Check that the worker's state is consistent with the host's knowledge."""
  try:
    status = stub().GetStatus(
        untrusted_runner_pb2.GetStatusRequest(),
        timeout=config.GET_STATUS_TIMEOUT_SECONDS)
  except grpc.RpcError:
    logs.log_error('GetStatus failed.')
    return False

  if status.revision != utils.current_source_version():
    logs.log_warn('Mismatching source revision: %s (host) vs %s (worker).' %
                  (utils.current_source_version(), status.revision))
    return False

  if _host_state.worker_bot_name != status.bot_name:
    logs.log_warn('Worker bot name invalid (IP changed?).')
    return False

  if _host_state.worker_start_time:
    if _host_state.worker_start_time == status.start_time:
      return True

    logs.log_warn('Worker start time changed.')
    return False

  _host_state.worker_start_time = status.start_time
  return True


def init():
  """Initialize channel to untrusted instance."""
  _connect()


def stub():
  """Return the UntrustedRunnerStub."""
  return _host_state.stub


def update_worker():
  """Update untrusted worker."""
  _host_state.expect_shutdown = True
  try:
    stub().UpdateSource(
        untrusted_runner_pb2.UpdateSourceRequest(),
        timeout=config.UPDATE_SOURCE_TIMEOUT_SECONDS)
  except grpc.RpcError:
    # Assume server got the shutdown request.
    pass


def host_exit_no_return(return_code=1):
  """Called when there is a host error."""
  if return_code:
    monitoring_metrics.HOST_ERROR_COUNT.increment({'return_code': return_code})

  # Always try to get the worker to exit too.
  update_worker()

  # Prevent exceptions during shutdown.
  _host_state.channel.unsubscribe(_channel_connectivity_changed)

  # This should bypass most exception handlers and avoid callers from catching
  # this incorrectly.
  logs.log('Shutting down host.', return_code=return_code)
  raise untrusted.HostException(return_code)


def is_initialized():
  """Return whether or not the host is initialized."""
  return _host_state.stub is not None
