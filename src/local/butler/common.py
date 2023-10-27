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
from distutils import dir_util
import io
import os
import platform
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import urllib.request
import zipfile

from local.butler import constants

INVALID_FILENAMES = ['src/third_party/setuptools/script (dev).tmpl']


class GcloudError(Exception):
  """Gcloud error."""


class GsutilError(Exception):
  """Gsutil error."""


class Gcloud:
  """Project specific gcloud."""

  def __init__(self, project_id):
    self.project_id = project_id

  def run(self, *args):
    arguments = ['gcloud', '--project=' + self.project_id]
    arguments.extend(args)
    return _run_and_handle_exception(arguments, GcloudError)


class Gsutil:
  """gsutil runner."""

  def run(self, *args):
    arguments = ['gsutil']
    arguments.extend(args)
    return _run_and_handle_exception(arguments, GsutilError)


def _run_and_handle_exception(arguments, exception_class):
  """Run a command and handle its error output."""
  print('Running:', ' '.join(shlex.quote(arg) for arg in arguments))
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
    _print(f'| {line.rstrip().decode("utf-8")}')
    lines.append(line)

  return b''.join(lines)


def execute_async(command,
                  extra_environments=None,
                  cwd=None,
                  stderr=subprocess.STDOUT):
  """Execute a bash command asynchronously. Returns a subprocess.Popen."""
  environments = os.environ.copy()
  if extra_environments is not None:
    environments.update(extra_environments)

  return subprocess.Popen(
      command,
      shell=True,
      stdout=subprocess.PIPE,
      stderr=stderr,
      env=environments,
      cwd=cwd)


def execute(command,
            print_output=True,
            exit_on_error=True,
            extra_environments=None,
            cwd=None,
            stderr=subprocess.STDOUT):
  """Execute a bash command."""

  def _print(s):
    if print_output:
      print(s)

  print_string = f'Running: {command}'
  if cwd:
    print_string += f' (cwd="{cwd}")'
  _print(print_string)

  proc = execute_async(command, extra_environments, cwd=cwd, stderr=stderr)
  output = process_proc_output(proc, print_output)

  proc.wait()
  if proc.returncode != 0:
    _print(f'| Return code is non-zero ({proc.returncode}).')
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
    execute(f'pkill -KILL -f "{name}"', exit_on_error=False)


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
  print(f'Installed chromedriver at: {chromedriver_path}')


def _pip():
  """Get the pip binary name."""
  return 'pip3'


def _pipfile_to_requirements(pipfile_dir, requirements_path, dev=False):
  """Output a requirements.txt given a locked Pipfile."""
  dev_arg = ''
  if dev:
    dev_arg = '--dev'

  return_code, output = execute(
      f'python -m pipenv requirements {dev_arg}',
      exit_on_error=False,
      cwd=pipfile_dir,
      extra_environments={'PIPENV_IGNORE_VIRTUALENVS': '1'},
      stderr=subprocess.DEVNULL)
  if return_code != 0:
    # Older pipenv version.
    return_code, output = execute(
        f'python -m pipenv lock -r --no-header {dev_arg}',
        exit_on_error=False,
        cwd=pipfile_dir,
        extra_environments={'PIPENV_IGNORE_VIRTUALENVS': '1'},
        stderr=subprocess.DEVNULL)

  if return_code != 0:
    raise RuntimeError('Failed to generate requirements from Pipfile.')

  with open(requirements_path, 'wb') as f:
    f.write(output)


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
    raise OSError(f'Unknown platform: {platform_name}.')

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
        f'{_pip()} download --no-deps --only-binary=:all: '
        f'--platform={pip_platform} --abi={pip_abi} -r {requirements_path} -d '
        f'{temp_dir}',
        exit_on_error=False)

    if return_code != 0:
      print(f'Did not find package for platform: {pip_platform}')
      continue

    execute(f'unzip -o -d {target_path} "{temp_dir}/*.whl"')
    shutil.rmtree(temp_dir, ignore_errors=True)
    break

  if return_code != 0:
    raise RuntimeError(
        f'Failed to find package in supported platforms: {pip_platforms}')


def _remove_invalid_files():
  """Remove invalid file whose filename is invalid to appengine."""
  for name in INVALID_FILENAMES:
    if os.path.exists(name):
      os.remove(name)


def install_dependencies(platform_name=None):
  """Install dependencies for bots."""
  _pipfile_to_requirements('src', 'src/requirements.txt')
  # Hack: Use "dev-packages" to specify App Engine only packages.
  _pipfile_to_requirements('src', 'src/appengine/requirements.txt', dev=True)

  _install_pip('src/requirements.txt', 'src/third_party')
  if platform_name:
    _install_platform_pip(
        'src/platform_requirements.txt',
        'src/third_party',
        platform_name=platform_name)

  _install_pip('src/appengine/requirements.txt', 'src/appengine/third_party')

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
    execute(rf'cmd /c mklink /j {target} {src}')
  else:
    os.symlink(src, target)

  assert os.path.exists(target), f'Failed to create {target} symlink for {src}.'

  print(f'Created symlink: source: {src}, target {target}.')


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


def get_all_files(directory):
  """Returns a list of all files recursively under a given directory."""
  all_files = []
  for root, _, files in os.walk(directory):
    for filename in files:
      filepath = os.path.join(root, filename)
      all_files.append(filepath)
  return all_files


def test_bucket(env_var):
  """Get the integration test bucket."""
  bucket = os.getenv(env_var)
  if not bucket:
    raise RuntimeError(f'You need to specify {env_var} for integration testing')

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

  raise OSError(f'Unknown platform: {platform.system()}.')


def get_modified_time(filename):
  return os.stat(filename)[stat.ST_MTIME]


def is_newer(src, dst):
  if not os.path.exists(dst):
    return True

  src_time = get_modified_time(src)
  dst_time = get_modified_time(dst)
  return src_time > dst_time


def copy_if_newer(src, dst):
  if is_newer(src, dst):
    return shutil.copy2(src, dst)
  return False


def update_dir(src_dir, dst_dir):
  """Recursively copy from src_dir to dst_dir, replacing files but only if
  they're newer or don't exist."""
  # TODO(metzman): Replace this with
  # shutil.copytree(src_dir, dst_dir, copy_function=copy_if_newer)
  # After we migrate to python3.9.
  dir_util.copy_tree(src_dir, dst_dir, update=True)
