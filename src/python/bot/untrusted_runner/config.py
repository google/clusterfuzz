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
"""Trusted host/untrusted instance configuration."""

PORT = 9001

INITIAL_CONNECT_TIMEOUT_SECONDS = 5 * 60
RECONNECT_TIMEOUT_SECONDS = 30

FILE_TRANSFER_CHUNK_SIZE = 4096

HEARTBEAT_INTERVAL_SECONDS = 60
HEARTBEAT_TIMEOUT_SECONDS = 15

GET_STATUS_TIMEOUT_SECONDS = 15
UPDATE_SOURCE_TIMEOUT_SECONDS = 15

RPC_RETRY_ATTEMPTS = 1

GRPC_OPTIONS = (
    ('grpc.max_send_message_length', -1),
    ('grpc.max_receive_message_length', -1),
    ('grpc.max_metadata_size', 32 * 1024 * 1024),
)

NUM_WORKER_THREADS = 4
