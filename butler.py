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
"""Butler is here to help you with command-line tasks (e.g. running unit tests,
   deploying).

   You should code a task in Butler if any of the belows is true:
   - you run multiple commands to achieve the task.
   - you keep forgetting how to achieve the task.

   Please do `python butler.py --help` to see what Butler can help you.
"""

import argparse
import importlib
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

# guard needs to be at the top because it checks Python dependecies.
from local.butler import guard

guard.check()


class _ArgumentParser(argparse.ArgumentParser):
  """Custom ArgumentParser."""

  def __init__(self, *args, **kwargs):
    """Override formatter_class to show default argument values in message."""
    kwargs['formatter_class'] = argparse.ArgumentDefaultsHelpFormatter
    argparse.ArgumentParser.__init__(self, *args, **kwargs)

  def error(self, message):
    """Override to print full help for ever error."""
    sys.stderr.write(f'error: {message}\n')
    self.print_help()
    sys.exit(2)


def _setup_args_for_remote(parser):
  """Setup sub-parsers for the remote command."""
  parser.add_argument(
      '-i',
      '--instance-name',
      required=True,
      help=('The instance name (e.g. clusterfuzz-linux-0005).'))
  parser.add_argument('--project', help='The Project ID.')
  parser.add_argument('--zone', help='The Project Zone.')

  subparsers = parser.add_subparsers(dest='remote')

  parser_tail = subparsers.add_parser(
      'tail', help='Print the last `size` lines of log_name.')
  parser_tail.add_argument('log_name', help='The log file name (without .log).')
  parser_tail.add_argument(
      'line_count', type=int, help='The number of lines to be showed.')

  parser_tailf = subparsers.add_parser(
      'tailf',
      help=('Print the last lines of logs and wait for more. '
            'This is equivalent to tail -f.'))
  parser_tailf.add_argument(
      'log_names', nargs='+', help='The log file names (without .log).')

  stage = subparsers.add_parser(
      'stage',
      help=('Stage a zip file by'
            ' (1) Build a zip with `butler.py package`'
            ' (2) Send the zip to the instance,'
            ' (3) Unzip it to the clusterfuzz path, and'
            ' (4) Restart run_bot.py.'))
  stage.add_argument(
      '-c', '--config-dir', required=True, help='Path to application config.')

  parser_rdp = subparsers.add_parser(
      'rdp',
      help=('Launch Remmina with correct configuration (e.g. IP address for the'
            ' instance).'))
  parser_rdp.add_argument(
      '--share-path',
      help=('The share path that is mounted on the remote instance.'
            'It is convenient for sending files to the remote instance.'))

  subparsers.add_parser('restart', help='Restart a bot by killing run_bot.py.')

  subparsers.add_parser('reboot', help='Reboot with `sudo reboot`.')


def main():
  """Parse the command-line args and invoke the right command."""
  parser = _ArgumentParser(
      description='Butler is here to help you with command-line tasks.')
  subparsers = parser.add_subparsers(dest='command')

  subparsers.add_parser(
      'bootstrap',
      help=('Install all required dependencies for running an appengine, a bot,'
            'and a mapreduce locally.'))

  parser_py_unittest = subparsers.add_parser(
      'py_unittest', help='Run Python unit tests.')
  parser_py_unittest.add_argument(
      '-p', '--pattern', help='Pattern for test files. Default is *_test.py.')
  parser_py_unittest.add_argument(
      '-u',
      '--unsuppress-output',
      action='store_true',
      help='Unsuppress output from `print`. Good for debugging.')
  parser_py_unittest.add_argument(
      '-m', '--parallel', action='store_true', help='Run tests in parallel.')
  parser_py_unittest.add_argument(
      '-v', '--verbose', action='store_true', help='Print logs from tests.')
  parser_py_unittest.add_argument(
      '-t', '--target', required=True, choices=['appengine', 'core', 'modules'])
  parser_py_unittest.add_argument(
      '-c', '--config-dir', help='Config dir to use for module tests.')

  parser_js_unittest = subparsers.add_parser(
      'js_unittest', help='Run Javascript unit tests.')
  parser_js_unittest.add_argument(
      '-p',
      '--persist',
      action='store_true',
      help=('Do not close browser when tests '
            'finish. Good for debugging.'))

  subparsers.add_parser('format', help='Format changed code in current branch.')
  subparsers.add_parser('lint', help='Lint changed code in current branch.')

  parser_package = subparsers.add_parser(
      'package', help='Package clusterfuzz with a staging revision')
  parser_package.add_argument(
      '-p', '--platform', choices=['linux', 'macos', 'windows', 'all'])

  parser_deploy = subparsers.add_parser('deploy', help='Deploy to Appengine')
  parser_deploy.add_argument(
      '-f',
      '--force',
      action='store_true',
      help='Force deploy from any branch.')
  parser_deploy.add_argument(
      '-c', '--config-dir', required=True, help='Path to application config.')
  parser_deploy.add_argument(
      '--staging', action='store_true', help='Deploy to staging.')
  parser_deploy.add_argument(
      '--prod', action='store_true', help='Deploy to production.')
  parser_deploy.add_argument(
      '--targets', nargs='*', default=['appengine', 'zips'])

  parser_run_server = subparsers.add_parser(
      'run_server', help='Run the local Clusterfuzz server.')
  parser_run_server.add_argument(
      '-b',
      '--bootstrap',
      action='store_true',
      help='Bootstrap the local database.')
  parser_run_server.add_argument(
      '--storage-path',
      default='local/storage',
      help='storage path for local database.')
  parser_run_server.add_argument(
      '--skip-install-deps',
      action='store_true',
      help=('Don\'t install dependencies before running this command (useful '
            'when you\'re restarting the server often).'))
  parser_run_server.add_argument(
      '--log-level', default='info', help='Logging level')
  parser_run_server.add_argument(
      '--clean', action='store_true', help='Clear existing database data.')

  parser_run = subparsers.add_parser(
      'run', help='Run a one-off script against a datastore (e.g. migration).')
  parser_run.add_argument(
      'script_name',
      help='The script module name under `./local/butler/scripts`.')
  parser_run.add_argument(
      '--script_args', action='append', help='Script specific arguments')
  parser_run.add_argument(
      '--non-dry-run',
      action='store_true',
      help='Run with actual datastore writes. Default to dry-run.')
  parser_run.add_argument(
      '-c', '--config-dir', required=True, help='Path to application config.')
  parser_run.add_argument(
      '--local', action='store_true', help='Run against local server instance.')

  parser_run_bot = subparsers.add_parser(
      'run_bot', help='Run a local clusterfuzz bot.')
  parser_run_bot.add_argument(
      '--name', default='test-bot', help='Name of the bot.')
  parser_run_bot.add_argument(
      '--server-storage-path',
      default='local/storage',
      help='Server storage path.')
  parser_run_bot.add_argument('directory', help='Directory to create bot in.')
  parser_run_bot.add_argument(
      '--android-serial',
      help='Serial number of an Android device to connect to instead of '
      'running normally.')

  parser_remote = subparsers.add_parser(
      'remote', help=('Run command-line tasks on a remote bot.'))
  _setup_args_for_remote(parser_remote)

  parser_clean_indexes = subparsers.add_parser(
      'clean_indexes', help=('Clean up undefined indexes (in index.yaml).'))
  parser_clean_indexes.add_argument(
      '-c', '--config-dir', required=True, help='Path to application config.')

  parser_create_config = subparsers.add_parser(
      'create_config', help='Create a new deployment config.')
  parser_create_config.add_argument(
      'new_config_dir', type=str, help='The new config directory to create.')
  parser_create_config.add_argument(
      '--project-id', type=str, required=True, help='Your Cloud Project ID.')
  parser_create_config.add_argument(
      '--firebase-api-key',
      type=str,
      required=True,
      help='Firebase web API key (for authentication).')
  parser_create_config.add_argument(
      '--oauth-client-secrets-path',
      type=str,
      required=True,
      help='Path to client_secrets.json.')
  parser_create_config.add_argument(
      '--gce-zone',
      type=str,
      default='us-central1-f',
      help='Region for GCE VMs.')
  parser_create_config.add_argument(
      '--appengine-location',
      type=str,
      default='us-central',
      help='Location for App Engine.')

  subparsers.add_parser(
      'integration_tests', help='Run end-to-end integration tests.')

  args = parser.parse_args()
  if not args.command:
    parser.print_help()
    return

  _setup()
  command = importlib.import_module(f'local.butler.{args.command}')
  command.execute(args)


def _setup():
  """Set up configs and import paths."""
  os.environ['ROOT_DIR'] = os.path.abspath('.')
  os.environ['PYTHONIOENCODING'] = 'UTF-8'

  sys.path.insert(0, os.path.abspath(os.path.join('src')))
  from clusterfuzz._internal.base import modules
  modules.fix_module_search_paths()


if __name__ == '__main__':
  main()
