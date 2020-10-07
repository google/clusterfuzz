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
"""common.py contains common methods and variables that are used by multiple
   commands."""

import datetime
import io
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile

from distutils import dir_util

from local.butler import constants

try:
  from shlex import quote
except ImportError:
  from pipes import quote

INVALID_FILENAMES = ['src/third_party/setuptools/script (dev).tmpl']


class GcloudError(Exception):
  """Gcloud error."""


class GsutilError(Exception):
  """Gsutil error."""


class Gcloud(object):
  """Project specific gcloud."""

  def __init__(self, project_id):
    self.project_id = project_id

  def run(self, *args):
    arguments = ['gcloud', '--project=' + self.project_id]
    arguments.extend(args)
    return _run_and_handle_exception(arguments, GcloudError)


class Gsutil(object):
  """gsutil runner."""

  def run(self, *args):
    arguments = ['gsutil']
    arguments.extend(args)
    return _run_and_handle_exception(arguments, GsutilError)


def _run_and_handle_exception(arguments, exception_class):
  """Run a command and handle its error output."""
  print('Running:', ' '.join(quote(arg) for arg in arguments))
  try:
    return subprocess.check_output(arguments)
  except subprocess.CalledProcessError as e:
    raise exception_class(e.output)


def _utcnow():
  """We need this method for mocking."""
  return datetime.datetime.utcnow()


def compute_staging_revision():
  """Staging revision adds 2 days to timestamp and append 'staging'."""
  return _compute_revision(_utcnow() + datetime.timedelta(days=2), 'staging')


def compute_prod_revision():
  """Get prod revision."""
  return _compute_revision(_utcnow())


def _compute_revision(timestamp, *extras):
  """Return a revision that contains a timestamp, git-sha, user, and
    is_staging. The ordinality of revision is crucial for updating source code.
    Later revision *must* be greater than earlier revision. See:
    crbug.com/674173."""
  timestamp = timestamp.strftime('%Y%m%d%H%M%S-utc')
  _, git_sha = execute('git rev-parse --short HEAD')
  git_sha = git_sha.strip().decode('utf-8')

  components = [timestamp, git_sha, os.environ['USER']] + list(extras)
  return '-'.join(components)


def process_proc_output(proc, print_output=True):
  """Print output of process line by line. Returns the whole output."""

  def _print(s):
    if print_output:
      print(s)

  lines = []
  for line in iter(proc.stdout.readline, b''):
    _print('| %s' % line.rstrip().decode('utf-8'))
    lines.append(line)

  return b''.join(lines)


def execute_async(command, extra_environments=None, cwd=None):
  """Execute a bash command asynchronously. Returns a subprocess.Popen."""
  environments = os.environ.copy()
  if extra_environments is not None:
    environments.update(extra_environments)

  return subprocess.Popen(
      command,
      shell=True,
      stdout=subprocess.PIPE,
      stderr=subprocess.STDOUT,
      env=environments,
      cwd=cwd)


def execute(command,
            print_output=True,
            exit_on_error=True,
            extra_environments=None,
            cwd=None):
  """Execute a bash command."""

  def _print(s):
    if print_output:
      print(s)

  print_string = 'Running: %s' % command
  if cwd:
    print_string += " (cwd='%s')" % cwd
  _print(print_string)

  proc = execute_async(command, extra_environments, cwd=cwd)
  output = process_proc_output(proc, print_output)

  proc.wait()
  if proc.returncode != 0:
    _print('| Return code is non-zero (%d).' % proc.returncode)
    if exit_on_error:
      _print('| Exit.')
      sys.exit(proc.returncode)

  return (proc.returncode, output)


def kill_process(name):
  """Kill the process by its name."""
  plt = get_platform()
  if plt == 'windows':
    execute(
        'wmic process where (commandline like "%%%s%%") delete' % name,
        exit_on_error=False)
  elif plt in ['linux', 'macos']:
    execute('pkill -KILL -f "%s"' % name, exit_on_error=False)


def is_git_dirty():
  """Check if git is dirty."""
  _, output = execute('git status --porcelain')
  return output


def get_chromedriver_path():
  """Return path to chromedriver binary."""
  if get_platform() == 'windows':
    chromedriver_binary = 'chromedriver.exe'
    binary_directory = 'Scripts'
  else:
    chromedriver_binary = 'chromedriver'
    binary_directory = 'bin'

  return os.path.join(os.environ['ROOT_DIR'], 'ENV', binary_directory,
                      chromedriver_binary)


def _install_chromedriver():
  """Install the latest chromedriver binary in the virtualenv."""
  # Download a file containing the version number of the latest release.
  version_request = urllib.request.urlopen(constants.CHROMEDRIVER_VERSION_URL)
  version = version_request.read().decode()

  plt = get_platform()
  if plt == 'linux':
    archive_name = 'chromedriver_linux64.zip'
  elif plt == 'macos':
    archive_name = 'chromedriver_mac64.zip'
  elif plt == 'windows':
    archive_name = 'chromedriver_win32.zip'

  archive_request = urllib.request.urlopen(
      constants.CHROMEDRIVER_DOWNLOAD_PATTERN.format(
          version=version, archive_name=archive_name))
  archive_io = io.BytesIO(archive_request.read())
  chromedriver_archive = zipfile.ZipFile(archive_io)

  chromedriver_path = get_chromedriver_path()
  output_directory = os.path.dirname(chromedriver_path)
  chromedriver_binary = os.path.basename(chromedriver_path)

  chromedriver_archive.extract(chromedriver_binary, output_directory)
  os.chmod(chromedriver_path, 0o750)
  print('Installed chromedriver at: %s' % chromedriver_path)


def _pip():
  """Get the pip binary name."""
  return 'pip3'


def _install_pip(requirements_path, target_path):
  """Perform pip install using requirements_path onto target_path."""
  if os.path.exists(target_path):
    shutil.rmtree(target_path)

  execute(
      '{pip} install -r {requirements_path} --upgrade --target {target_path}'.
      format(
          pip=_pip(),
          requirements_path=requirements_path,
          target_path=target_path))


def _install_platform_pip(requirements_path, target_path, platform_name):
  """Install platform specific pip packages."""
  pip_platform = constants.PLATFORMS.get(platform_name)
  if not pip_platform:
    raise Exception('Unknown platform: %s.' % platform_name)

  # Some platforms can specify multiple pip platforms (e.g. macOS has multiple
  # SDK versions).
  if isinstance(pip_platform, str):
    pip_platforms = (pip_platform,)
  else:
    assert isinstance(pip_platform, tuple)
    pip_platforms = pip_platform

  pip_abi = constants.ABIS[platform_name]

  for pip_platform in pip_platforms:
    temp_dir = tempfile.mkdtemp()
    return_code, _ = execute(
        '{pip} download --no-deps --only-binary=:all: --platform={platform} '
        '--abi={abi} -r {requirements_path} -d {output_dir}'.format(
            pip=_pip(),
            platform=pip_platform,
            abi=pip_abi,
            requirements_path=requirements_path,
            output_dir=temp_dir),
        exit_on_error=False)

    if return_code != 0:
      print('Did not find package for platform: ' + pip_platform)
      continue

    execute('unzip -o -d %s \'%s/*.whl\'' % (target_path, temp_dir))
    shutil.rmtree(temp_dir, ignore_errors=True)
    break

  if return_code != 0:
    raise Exception('Failed to find package in supported platforms: %s' +
                    str(pip_platforms))


def _remove_invalid_files():
  """Remove invalid file whose filename is invalid to appengine."""
  for name in INVALID_FILENAMES:
    if os.path.exists(name):
      os.remove(name)


def install_dependencies(platform_name=None, is_reproduce_tool_setup=False):
  """Install dependencies for bots."""
  _install_pip('src/requirements.txt', 'src/third_party')
  if platform_name:
    _install_platform_pip(
        'src/platform_requirements.txt',
        'src/third_party',
        platform_name=platform_name)

  with tempfile.NamedTemporaryFile() as f:
    f.write(open('src/requirements.txt', 'rb').read())
    f.write(open('src/appengine/requirements.txt', 'rb').read())
    f.flush()

    _install_pip(f.name, 'src/appengine/third_party')

  # Only the previous dependencies are needed for reproduce tool installation.
  if is_reproduce_tool_setup:
    return

  _remove_invalid_files()
  execute('bower install --allow-root')

  _install_chromedriver()


def remove_symlink(target):
  """Removes a symlink."""
  if not os.path.exists(target):
    return

  if os.path.isdir(target) and get_platform() == 'windows':
    os.rmdir(target)
  else:
    os.remove(target)


def symlink(src, target):
  """Create the target to link to the src."""
  src = os.path.abspath(src)
  target = os.path.abspath(target)

  remove_symlink(target)

  if get_platform() == 'windows':
    execute(r'cmd /c mklink /j %s %s' % (target, src))
  else:
    os.symlink(src, target)

  assert os.path.exists(target), (
      'Failed to create {target} symlink for {src}.'.format(
          target=target, src=src))

  print('Created symlink: source: {src}, target {target}.'.format(
      src=src, target=target))


def copy_dir(src, target):
  """Copy directory."""
  if os.path.exists(target):
    shutil.rmtree(target, ignore_errors=True)

  shutil.copytree(src, target)


def has_file_in_path(filename):
  """Check to see if filename exists in the user's PATH."""
  path = os.getenv('PATH')
  for path_component in path.split(':'):
    if os.path.isfile(os.path.join(path_component, filename)):
      return True

  return False


def test_bucket(env_var):
  """Get the integration test bucket."""
  bucket = os.getenv(env_var)
  if not bucket:
    raise RuntimeError(
        'You need to specify {var} for integration testing'.format(var=env_var))

  return bucket


def kill_leftover_emulators():
  """Kill leftover instances of cloud emulators and dev_appserver."""
  kill_process('dev_appserver.py')
  kill_process('CloudDatastore.jar')
  kill_process('pubsub-emulator')
  kill_process('run_bot')


def get_platform():
  """Get the platform."""
  if platform.system() == 'Linux':
    return 'linux'
  if platform.system() == 'Darwin':
    return 'macos'
  if platform.system() == 'Windows':
    return 'windows'

  raise Exception('Unknown platform: %s.' % platform.system())


def update_dir(src_dir, dst_dir):
  """Recursively copy from src_dir to dst_dir, replacing files but only if
  they're newer or don't exist."""
  dir_util.copy_tree(src_dir, dst_dir, update=True)
