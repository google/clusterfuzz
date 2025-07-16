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
"""Executes update task locally, so we can run it through a debugger."""

import argparse
import importlib

from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment


def _get_cron_script_details(
    args: argparse.Namespace,) -> tuple[str | None, list[str]]:
  """
  Parses command-line arguments to get the script name and its own arguments.

  Args:
    args: The parsed arguments from argparse.

  Returns:
    A tuple containing the script name (or None) and a list of its arguments.
  """
  if not args.script_args:
    logs.error('Please specify a cron job script to run.')
    return None, []

  script_name = args.script_args[0]
  script_arguments = args.script_args[1:]
  return script_name, script_arguments


def _setup_environment(script_name: str) -> None:
  """
  Configures the environment for the cron job run.
  """
  logs.configure(f'run_cron')
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


def execute(args: argparse.Namespace) -> None:
  """
  Dynamically loads and executes a cron job script from the command line.
  """
  script_name, script_args = _prepare_cron_arguments(args)
  if not script_name:
    return

  _setup_environment(script_name)
  _import_and_run_cron(script_name, script_args)
