# Copyright 2026 Google LLC
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
"""A fake GCE metadata server for integration tests.

Spins up a WireMock container serving fake service account tokens and project
metadata from JSON configs (in test_suites/seed/gce_metadata_server/).

Tests can resolve credentials via google.auth, oauth2client, and
compute_metadata without a real GCE VM or cloud credentials.

Setup:
The test runner must call bootstrap() before importing Google auth or
application modules, so that the auth libraries pickup the fake server host
address instead of the real one.

  from test_suites.fixtures import gce_metadata_server
    gce_metadata_server.bootstrap()

Usage:
Wrap test code in a context manager to choose which credentials and metadata
are returned:

  with gce_metadata_server.trusted_as_default() as tworker:
    ...

  with gce_metadata_server.untrusted_as_default() as uworker:
    ...

To test interactions between trusted and untrusted environments, use
trusted_untrusted_pair(). In-process code uses tworker, while subprocesses
define the emulator instance by exporting the environment:

  with gce_metadata_server.trusted_untrusted_pair() as (tworker, uworker):
    subprocess.run(argv, env={uworker.env,...})

At runtime, use the client to update the values served by the metadata
server.

    with gce_metadata_server.trusted_as_default() as client:
      client.set_instance_attribute('key', 'value')
      client.set_service_account('account@domain.com', 'token')
"""

import contextlib
import json
import os
import tempfile

import requests
from wiremock.client import HttpMethods
from wiremock.client import Mapping
from wiremock.client import MappingRequest
from wiremock.client import MappingResponse
from wiremock.client import Mappings
from wiremock.constants import Config
from wiremock.testing.testcontainer import wiremock_container

_REQUEST_TIMEOUT = 5
_DEFAULT_EXPIRES_IN_SECONDS = 3600

_METADATA_HEADERS = {'Metadata-Flavor': 'Google'}
_TEXT_HEADERS = {
    'Metadata-Flavor': 'Google',
    'Content-Type': 'text/plain; charset=utf-8',
}
_JSON_HEADERS = {
    'Metadata-Flavor': 'Google',
    'Content-Type': 'application/json',
}
_REQUIRED_HEADER_MATCHER = {'Metadata-Flavor': {'equalTo': 'Google'}}

_DEFAULT_ADDRESS = '127.0.0.1:9010'
_SECONDARY_ADDRESS = '127.0.0.1:9012'


def config_path(name: str) -> str:
  """Returns the path to a named config fixture, e.g. 'tworker'."""
  test_suites_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
  return os.path.join(test_suites_dir, 'seed', 'gce_metadata_server',
                      f'{name}.json')


def load_config(name: str) -> dict:
  """Loads a named metadata fixture configuration."""
  path = config_path(name)
  if not os.path.exists(path):
    raise FileNotFoundError(f'No emulator config at {path}')

  with open(path, encoding='utf-8') as handle:
    return json.load(handle)


def _auth_env(hostport: str) -> dict[str, str]:
  """Returns the env vars that point the Google auth libraries at hostport."""
  return {
      # google-auth, and clusterfuzz's own compute_metadata.
      'GCE_METADATA_HOST': hostport,
      # Our vendored oauth2client.
      'GCE_METADATA_ROOT': hostport,
      # The reachability ping both libraries use to detect GCE.
      'GCE_METADATA_IP': hostport,
  }


def _flatten_entries(data: dict, prefix: str = '') -> dict[str, str]:
  """Flattens nested metadata dicts (excluding 'attributes') into relative paths."""
  items = {}
  for key, value in data.items():
    if key == 'attributes' or value is None:
      continue
    full_key = f'{prefix}/{key}' if prefix else key
    if isinstance(value, dict):
      items.update(_flatten_entries(value, prefix=full_key))
    else:
      items[full_key] = str(value)
  return items


def _forbidden_mapping() -> Mapping:
  """Returns a Mapping rejecting requests missing 'Metadata-Flavor: Google'."""
  return Mapping(
      persistent=True,
      request=MappingRequest(
          method=HttpMethods.ANY,
          url_pattern='.*',
          headers={'Metadata-Flavor': {
              'absent': True
          }},
      ),
      response=MappingResponse(
          status=403,
          body='',
          headers=_TEXT_HEADERS,
      ),
  )


def _root_mapping() -> Mapping:
  """Returns a Mapping for reachability pings at '/' and '/computeMetadata/v1/'."""
  return Mapping(
      persistent=True,
      request=MappingRequest(
          method=HttpMethods.GET,
          url_path_pattern=r'^/(computeMetadata/v1/)?$',
          headers=_REQUIRED_HEADER_MATCHER,
      ),
      response=MappingResponse(
          status=200,
          body='',
          headers=_TEXT_HEADERS,
      ),
  )


def _text_value_mapping(path: str,
                        value: str,
                        persistent: bool = False,
                        query_parameters: dict | None = None) -> Mapping:
  """Returns a Mapping serving a plain-text metadata value at path."""
  request_kwargs = {
      'method': HttpMethods.GET,
      'url_path': f'/computeMetadata/v1/{path}',
      'headers': _REQUIRED_HEADER_MATCHER,
  }
  if query_parameters is not None:
    request_kwargs['query_parameters'] = query_parameters

  return Mapping(
      persistent=persistent,
      request=MappingRequest(**request_kwargs),
      response=MappingResponse(
          status=200,
          body=str(value),
          headers=_TEXT_HEADERS,
      ),
  )


def _json_value_mapping(path: str,
                        payload: dict,
                        persistent: bool = False,
                        query_parameters: dict | None = None) -> Mapping:
  """Returns a Mapping serving a JSON metadata value at path."""
  request_kwargs = {
      'method': HttpMethods.GET,
      'url_path': f'/computeMetadata/v1/{path}',
      'headers': _REQUIRED_HEADER_MATCHER,
  }
  if query_parameters is not None:
    request_kwargs['query_parameters'] = query_parameters

  return Mapping(
      persistent=persistent,
      request=MappingRequest(**request_kwargs),
      response=MappingResponse(
          status=200,
          json_body=payload,
          headers=_JSON_HEADERS,
      ),
  )


class MetadataEmulatorClient:
  """Talks to a running WireMock metadata emulator."""

  def __init__(self, hostport: str, config: dict):
    self.hostport = hostport
    self.admin_url = f'http://{hostport}/__admin'
    self._baseline_instance_attributes = set()

    # Loopback traffic must not be handed to an ambient http_proxy, which
    # would answer with its own error instead of reaching the emulator.
    self._session = requests.Session()
    self._session.trust_env = False

    self.overwrite_config(config)

  @property
  def url(self) -> str:
    """Returns the base URL of the emulator."""
    return f'http://{self.hostport}'

  @property
  def session(self) -> requests.Session:
    """Returns a requests.Session that bypasses ambient proxies."""
    return self._session

  @property
  def env(self) -> dict[str, str]:
    """Env vars pointing the Google auth libraries at this emulator.

    Merge these into a child process's environment. They cannot retarget the
    current process: see the module docstring on start order.
    """
    return _auth_env(self.hostport)

  def _use_admin(self) -> None:
    """Points the wiremock SDK singleton at this emulator's admin endpoint."""
    Config.base_url = self.admin_url

  def close(self) -> None:
    """Releases the connections this client holds open to the emulator."""
    self._session.close()

  def overwrite_config(self, cfg: dict) -> None:
    """Replaces the emulator's baseline metadata with a fixture config."""
    self._use_admin()
    Mappings.create_mapping(_forbidden_mapping())
    Mappings.create_mapping(_root_mapping())

    metadata = cfg.get('metadata', {})
    project = metadata.get('project', {})
    instance = metadata.get('instance', {})

    for key, value in _flatten_entries(project).items():
      self.set_project_metadata(key, value, persistent=True)

    for key, value in _flatten_entries(instance).items():
      self.set_instance_metadata(key, value, persistent=True)

    for key, value in instance.get('attributes', {}).items():
      self.set_instance_attribute(key, value, persistent=True)

    for key, value in project.get('attributes', {}).items():
      self.set_project_attribute(key, value, persistent=True)

    creds = cfg.get('credentials', {})
    self.set_service_account(
        email=creds.get('email', 'default'),
        access_token=creds.get('access_token', 'fake-access-token'),
        scopes=creds.get('scopes', []),
        expires_in_seconds=int(
            creds.get('expires_in_seconds') or _DEFAULT_EXPIRES_IN_SECONDS),
        persistent=True,
    )

  def set_project_metadata(self, key: str, value: str,
                           persistent: bool = False) -> None:
    """Sets a project metadata value under 'project/<key>'."""
    self._use_admin()
    Mappings.create_mapping(
        _text_value_mapping(f'project/{key}', value, persistent=persistent))

  def set_project_attribute(self,
                            key: str,
                            value: str,
                            persistent: bool = False) -> None:
    """Sets 'project/attributes/<key>' and falls back for 'instance/attributes/<key>'."""
    self._use_admin()
    Mappings.create_mapping(
        _text_value_mapping(
            f'project/attributes/{key}', value, persistent=persistent))

    if key not in self._baseline_instance_attributes:
      Mappings.create_mapping(
          _text_value_mapping(
              f'instance/attributes/{key}', value, persistent=persistent))

  def set_instance_metadata(self,
                            key: str,
                            value: str,
                            persistent: bool = False) -> None:
    """Sets an instance metadata value under 'instance/<key>'."""
    self._use_admin()
    Mappings.create_mapping(
        _text_value_mapping(f'instance/{key}', value, persistent=persistent))

  def set_instance_attribute(self,
                             key: str,
                             value: str,
                             persistent: bool = False) -> None:
    """Sets 'instance/attributes/<key>', shadowing any project attribute."""
    self._use_admin()
    if persistent:
      self._baseline_instance_attributes.add(key)
    Mappings.create_mapping(
        _text_value_mapping(
            f'instance/attributes/{key}', value, persistent=persistent))

  def set_service_account(self,
                          email: str,
                          access_token: str,
                          scopes: list[str] | None = None,
                          expires_in_seconds: int = _DEFAULT_EXPIRES_IN_SECONDS,
                          persistent: bool = False) -> None:
    """Sets the service account identity and token served by the emulator."""
    self._use_admin()
    scopes = list(scopes or [])
    Mappings.create_mapping(
        _text_value_mapping(
            'instance/service-accounts/',
            f'{email}/\ndefault/\n',
            persistent=persistent))

    for account in dict.fromkeys(['default', email]):
      base_path = f'instance/service-accounts/{account}'
      Mappings.create_mapping(
          _text_value_mapping(
              f'{base_path}/',
              'aliases\nemail\nidentity\nscopes\ntoken\n',
              persistent=persistent,
              query_parameters={'recursive': {
                  'absent': True
              }}))
      Mappings.create_mapping(
          _json_value_mapping(
              f'{base_path}/', {
                  'aliases': ['default'],
                  'email': email,
                  'scopes': scopes,
              },
              persistent=persistent,
              query_parameters={'recursive': {
                  'matches': '.*'
              }}))
      Mappings.create_mapping(
          _text_value_mapping(f'{base_path}/email', email, persistent))
      Mappings.create_mapping(
          _text_value_mapping(f'{base_path}/aliases', 'default', persistent))
      Mappings.create_mapping(
          _text_value_mapping(f'{base_path}/scopes', '\n'.join(scopes) + '\n',
                              persistent))
      Mappings.create_mapping(
          _json_value_mapping(
              f'{base_path}/token', {
                  'access_token': access_token,
                  'expires_in': int(expires_in_seconds),
                  'token_type': 'Bearer',
              },
              persistent=persistent))

  def get(self, path: str) -> str:
    """Reads a metadata value straight from the emulator."""
    response = self._session.get(
        f'{self.url}/computeMetadata/v1/{path}',
        headers=_METADATA_HEADERS,
        timeout=_REQUEST_TIMEOUT)
    response.raise_for_status()
    return response.text


def bootstrap() -> None:
  """Points this process at the address the default emulator will bind.

  No server is started here. This publishes the default address, and has to
  run before anything imports the Google auth libraries, which resolve the
  metadata address once, at import time, and keep it. That is what lets a test
  start and stop emulators later and still have already-imported code reach
  them.
  """
  os.environ.update(_auth_env(_DEFAULT_ADDRESS))

  # google.auth.default() only reaches the metadata server after it has ruled
  # out GOOGLE_APPLICATION_CREDENTIALS and a gcloud login, so a developer who
  # ran `gcloud auth application-default login` would otherwise resolve to
  # their own identity instead of the emulator's.
  os.environ.pop('GOOGLE_APPLICATION_CREDENTIALS', None)
  os.environ['CLOUDSDK_CONFIG'] = tempfile.mkdtemp(prefix='metadata-cloudsdk-')
  print(
      f'Overriding GCE_METADATA_HOST to: {os.environ.get("GCE_METADATA_HOST")}')


@contextlib.contextmanager
def _metadata_emulator(name: str, hostport: str):
  """Yields a running WireMock emulator for the named fixture, and stops it after.

  hostport is _DEFAULT_ADDRESS or _SECONDARY_ADDRESS. Callers pick it through
  the public context managers below rather than naming an address themselves.
  """
  cfg = load_config(name)

  # The auth libraries read the address once, at import time, so if bootstrap()
  # did not publish it first nothing already imported can reach the emulator.
  if os.environ.get('GCE_METADATA_HOST') != _DEFAULT_ADDRESS:
    raise RuntimeError(
        'gce_metadata_server.bootstrap() has to run before the Google auth '
        'libraries are imported. See the gce_metadata_server docstring.')

  _, _, port = hostport.partition(':')

  with wiremock_container(
      secure=False, verify_ssl_certs=False, start=False) as wm:
    wm.with_bind_ports(wm.http_server_port, int(port))
    with wm:
      client = MetadataEmulatorClient(hostport, cfg)
      try:
        yield client
      finally:
        client.close()


# TODO(b/555371204): Make this into real pytest fixtures
@contextlib.contextmanager
def trusted_as_default():
  """Yields a tworker emulator on the default address, making it the in-process identity.
  
  Anything that already cached a credential keeps it, so tests wanting a fresh
  one have to say so: credentials.get_default(__memoize_force__=True).
  """
  with _metadata_emulator('tworker', _DEFAULT_ADDRESS) as emulator:
    yield emulator


@contextlib.contextmanager
def untrusted_as_default():
  """Yields a uworker emulator on the default address, making it the in-process identity.

  Anything that already cached a credential keeps it, so tests wanting a fresh
  one have to say so: credentials.get_default(__memoize_force__=True).
  """
  with _metadata_emulator('uworker', _DEFAULT_ADDRESS) as emulator:
    yield emulator


@contextlib.contextmanager
def trusted_untrusted_pair():
  """Yields a pair of emulators: tworker on the default address, uworker on the
  secondary address.
  
  tworker is the in-process identity here. uworker is reachable through the
  client returned, or by handing its env to a subprocess.
  """
  with trusted_as_default() as tworker, \
      _metadata_emulator('uworker', _SECONDARY_ADDRESS) as uworker:
    yield tworker, uworker
