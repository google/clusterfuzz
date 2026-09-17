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
"""Developer environment checks for the testcontainers dependency.

These verify that a developer environment can actually launch containers
through testcontainers. They are skipped automatically when no usable Docker
daemon is reachable (e.g. on bots without Docker).

Run with:
  pipenv run python -m pytest \
      src/clusterfuzz/tests/test_dev_env_testcontainers.py

or, from inside an activated virtualenv (`pipenv shell`):
  python -m pytest src/clusterfuzz/tests/test_dev_env_testcontainers.py

This is deliberately not part of CI: `butler.py py_unittest` only discovers
tests under src/clusterfuzz/_internal/tests/{core,appengine}, so this file is
never collected by the `core` or `appengine` targets that CI runs. The
`test_` prefix (rather than a `_test.py` suffix) is also intentional: it keeps
pytest collection working while opting out of butler's lint rule requiring an
__init__.py next to every *_test.py file, which exists to protect unittest
discovery that this file does not rely on.
"""

import pytest
from testcontainers.core.container import DockerContainer
from testcontainers.core.wait_strategies import LogMessageWaitStrategy

IMAGE = 'alpine:3.20'
MESSAGE = 'hello from testcontainers'


def _docker_available():
  """Return True if a Docker daemon is reachable."""
  try:
    # Imported lazily so that a missing docker SDK results in a skip, not an
    # import error.
    import docker  # pylint: disable=import-outside-toplevel
    docker.from_env().ping()
    return True
  except Exception:  # pylint: disable=broad-except
    return False


requires_docker = pytest.mark.skipif(
    not _docker_available(), reason='No reachable Docker daemon.')


@requires_docker
def test_hello_world():
  """Verify testcontainers starts a container, waits for logs, and cleans up."""
  container = (
      DockerContainer(IMAGE).with_command(f'echo "{MESSAGE}"').waiting_for(
          LogMessageWaitStrategy(MESSAGE).with_startup_timeout(60)))
  with container:
    stdout, _ = container.get_logs()

  assert MESSAGE in stdout.decode()


@requires_docker
def test_exec_in_running_container():
  """Verify exec on a live container returns its exit code and output."""
  with DockerContainer(IMAGE).with_command('sleep 30') as container:
    assert container.get_wrapped_container().id

    exit_code, output = container.exec(['echo', MESSAGE])
    assert exit_code == 0
    assert MESSAGE in output.decode()
