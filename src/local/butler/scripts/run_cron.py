# Copyright 2024 Google LLC
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
"""Generic runner for executing cron jobs locally.

This script serves as the entry point for running cron jobs via the `butler.py`
command-line tool. It dynamically imports and executes the `main` function of
a specified cron script from the `clusterfuzz._internal.cron` directory.

The name of the target cron script and any arguments for it must be passed
after the `--script_args` flag.

Usage:
  # Run the 'retry_stuck_tasks' cron job with its default parameters.
  python butler.py run run_cron --script_args retry_stuck_tasks

  # Run the 'retry_stuck_tasks' cron and pass custom arguments to it.
  python butler.py run run_cron --script_args retry_stuck_tasks --max-retries=2

  # Run in non-dry-run mode using the 'run' command's global flag.
  python butler.py run --non-dry-run run_cron --script_args retry_stuck_tasks
"""

import argparse
import importlib

from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment


def _setup_environment():
  """
  Configures the environment for the cron job run.
  """
  logs.configure('run_cron')
  environment.set_bot_environment()


def _import_and_run_cron(script_name: str, script_args: list[str]) -> None:
  """
  Dynamically imports and executes the main function of a cron script,
  passing along any additional arguments.

  Args:
    script_name: The name of the cron script to execute.
    script_args: A list of string arguments to pass to the script's main func.
  """
  module_path = f'clusterfuzz._internal.cron.{script_name}'
  try:
    cron_module = importlib.import_module(module_path)
    main_func = getattr(cron_module, 'main')

    main_func(script_args)

  except ImportError:
    logs.error(f'Failed to find cron job module: {module_path}')
  except AttributeError:
    logs.error(
        f'Cron job module {module_path} does not have a "main" function.')
  except TypeError as e:
    logs.error(f'Error calling main function in {module_path}: {e}. '
               'Does its "main" function accept an argument?')


def _prepare_cron_arguments(
    args: argparse.Namespace) -> tuple[str | None, list[str]]:
  """
  Parses arguments to extract the script name and its specific arguments.

  It isolates the logic of handling the arguments list and gracefully
  propagates global flags like --non-dry-run into the arguments for the
  target script.

  Args:
    args: The parsed arguments object from the parent butler command.

  Returns:
    A tuple containing the script name and the final list of arguments to be
    passed to it. Returns (None, []) if no script is specified.
  """
  if not args.script_args:
    logs.error('Please specify a cron job script to run.')
    return None, []

  script_name = args.script_args[0]
  final_script_args = args.script_args[1:]

  if getattr(args, 'non_dry_run', False):
    final_script_args.append('--non-dry-run')

  return script_name, final_script_args


def execute(args: argparse.Namespace):
  """
  Dynamically loads and executes a cron job script from the command line.
  """
  _setup_environment()

  script_name, script_args = _prepare_cron_arguments(args)
  if not script_name:
    return

  _import_and_run_cron(script_name, script_args)
