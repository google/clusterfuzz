# Copyright 2025 Google LLC
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
"""gRPC authentication interceptor for API key validation."""

import os
import grpc
from typing import Callable, Any, Set

def _get_valid_api_keys() -> Set[str]:
  """
  Retrieves valid API keys from the 'VALID_API_KEYS' environment variable.
  Keys should be a comma-separated string.
  """
  keys_str = os.environ.get('VALID_API_KEYS', '')
  if not keys_str:
    # For local development and testing, provide a default key.
    # In production, the environment variable should always be set.
    print("WARNING: VALID_API_KEYS environment variable not set. Using default developer key.")
    return {"test-key-1"}
  return set(key.strip() for key in keys_str.split(','))

class ApiKeyInterceptor(grpc.ServerInterceptor):
  """An interceptor to validate an API key from request metadata."""

  def __init__(self):
    self._valid_keys = _get_valid_api_keys()

  def intercept_service(self, continuation: Callable,
                        handler_call_details: grpc.HandlerCallDetails) -> Any:
    """
    Intercepts a service call to perform authentication.
    """
    metadata = dict(handler_call_details.invocation_metadata)
    api_key = metadata.get('x-api-key')

    if self._is_valid_key(api_key):
      return continuation(handler_call_details)
    else:
      context = grpc.ServicerContext()
      context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid or missing API key")

  def _is_valid_key(self, api_key: str) -> bool:
    """Checks if the provided API key is valid."""
    if not api_key:
      print("Authentication failed: API key is missing.")
      return False

    if api_key not in self._valid_keys:
      print(f"Authentication failed: Invalid API key.")
      return False

    return True
