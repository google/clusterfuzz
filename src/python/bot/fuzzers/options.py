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
"""Fuzzer options."""

import configparser
import os
import random
import re
import six

from bot.fuzzers import utils as fuzzer_utils
from bot.fuzzers.afl import constants as afl_constants
from metrics import logs
from system import environment

OPTIONS_FILE_EXTENSION = '.options'

# Whitelist for env variables .options files can set.
ENV_VAR_WHITELIST = set([afl_constants.DONT_DEFER_ENV_VAR])


class FuzzerOptionsException(Exception):
  """Exceptions for fuzzer options."""


class FuzzerArguments(object):
  """Fuzzer flags."""

  def __init__(self, flags):
    self.flags = flags

  def __contains__(self, key):
    return key in self.flags

  def __getitem__(self, key):
    return self.flags[key]

  def __setitem__(self, key, value):
    self.flags[key] = value

  def get(self, key, default=None, constructor=None):
    """Return value for |key|, calling the |constructor| on it, or |default| if
    the key does not exist, or if the constructor threw an exception."""
    try:
      value = self[key]
      if constructor:
        value = constructor(value)

      return value
    except Exception:
      pass

    return default

  def dict(self):
    """Return arguments as a dict."""
    return self.flags

  def list(self):
    """Return arguments as a list."""
    return ['-%s=%s' % (key, value) for key, value in six.iteritems(self.flags)]


class FuzzerOptions(object):
  """Represents fuzzer and related options."""

  OPTIONS_RANDOM_REGEX = re.compile(
      r'^\s*random\(\s*(\d+)\s*,\s*(\d+)\s*\)\s*$')

  def __init__(self, options_file_path, cwd=None):
    if not os.path.exists(options_file_path):
      raise FuzzerOptionsException('fuzzer options file does not exist.')

    if cwd:
      self._cwd = cwd
    else:
      self._cwd = os.path.dirname(options_file_path)

    self._config = configparser.ConfigParser()
    with open(options_file_path, 'r') as f:
      try:
        self._config.read_file(f)
      except configparser.Error:
        raise FuzzerOptionsException('Failed to parse fuzzer options file.')

  def _get_dict_path(self, relative_dict_path):
    """Return a full path to the dictionary."""
    return os.path.join(self._cwd, relative_dict_path)

  def _get_option_section(self, section):
    """Get an option section."""
    if not self._config.has_section(section):
      return {}

    return dict(self._config.items(section))

  def get_env(self):
    """Returns dict containing env variables and their values set by "env"
    section. Only includes env variables permitted by |ENV_VAR_WHITELIST|.
    Variables are assumed to contain no lower case letters.
    """
    env = {}
    for var_name, var_value in six.iteritems(self._get_option_section('env')):

      var_name = var_name.upper()
      if var_name in ENV_VAR_WHITELIST:
        env[var_name] = var_value

    return env

  def get_engine_arguments(self, engine):
    """Return a list of fuzzer options."""
    arguments = {}
    for option_name, option_value in six.iteritems(
        self._get_option_section(engine)):
      # Check option value for usage of random() function.
      match = self.OPTIONS_RANDOM_REGEX.match(option_value)
      if match:
        min_value, max_value = match.groups()
        option_value = str(random.SystemRandom().randint(
            int(min_value), int(max_value)))

      if option_name == 'dict':
        option_value = self._get_dict_path(option_value)

      arguments[option_name] = option_value

    return FuzzerArguments(arguments)

  def get_asan_options(self):
    """Return a list of ASAN_OPTIONS overrides."""
    return self._get_option_section('asan')

  def get_msan_options(self):
    """Return a list of MSAN_OPTIONS overrides."""
    return self._get_option_section('msan')

  def get_ubsan_options(self):
    """Return a list of UBSAN_OPTIONS overrides."""
    return self._get_option_section('ubsan')

  def get_hwasan_options(self):
    """Return a list of HWSAN_OPTIONS overrides."""
    return self._get_option_section('hwasan')

  def get_grammar_options(self):
    """Return a list og grammar options"""
    return self._get_option_section('grammar')


def get_fuzz_target_options(fuzz_target_path):
  """Return a FuzzerOptions for the given target, or None if it does not
  exist."""
  options_file_path = fuzzer_utils.get_supporting_file(fuzz_target_path,
                                                       OPTIONS_FILE_EXTENSION)

  if environment.is_trusted_host():
    options_file_path = fuzzer_utils.get_file_from_untrusted_worker(
        options_file_path)

  if not os.path.exists(options_file_path):
    return None

  options_cwd = os.path.dirname(options_file_path)

  try:
    return FuzzerOptions(options_file_path, cwd=options_cwd)
  except FuzzerOptionsException:
    logs.log_error('Invalid options file: %s.' % options_file_path)
    return None
