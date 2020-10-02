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
"""Fuchsia utilities for handling fuzzers."""

import datetime
import errno
import glob
import os
import six
import subprocess
import time


class Fuzzer(object):
  """Represents a Fuchsia fuzz target.

    This represents a binary fuzz target produced the Fuchsia build, referenced
    by a component manifest, and included in a fuzz package.  It provides an
    interface for running the fuzzer in different common modes, allowing
    specific command line arguments to libFuzzer to be abstracted.

    Attributes:
      device: A Device where this fuzzer can be run
      host: The build host that built the fuzzer
      pkg: The GN fuzzers_package name
      tgt: The GN fuzzers name
  """

  # Matches the prefixes in libFuzzer passed to |Fuzzer::DumpCurrentUnit| or
  # |Fuzzer::WriteUnitToFileWithPrefix|.
  ARTIFACT_PREFIXES = [
      'crash', 'leak', 'mismatch', 'oom', 'slow-unit', 'timeout'
  ]

  class NameError(ValueError):
    """Indicates a supplied name is malformed or unusable."""

  class StateError(ValueError):
    """Indicates a command isn't valid for the fuzzer in its current state."""

  @classmethod
  def _matches_sanitizer(cls, tgt, sanitizer):
    """ Returns whether or not a target is for a given sanitizer. """
    tgt, ext = os.path.splitext(tgt)
    # Remove the leading '.' from the extension.
    ext = ext[1:]
    if ext == sanitizer:
      return True
    # If there's no extension, assume it's an ASAN fuzzer.
    if sanitizer == 'asan' and ext == '':
      return True
    return False

  @classmethod
  def _is_example(cls, pkg, tgt):
    """ Returns whether or not a given pkg/tgt pair is an example fuzzer.
    (Helper function to prevent us from wasting cycles on example fuzzers in
    production). """
    # Strip any sanitizer extensions
    tgt = os.path.splitext(tgt)[0]
    return ((pkg == 'example-fuzzers' and
             tgt not in ('out_of_memory_fuzzer', 'toy_example_arbitrary')) or
            (pkg == 'zircon_fuzzers' and tgt == 'noop-fuzzer'))

  @classmethod
  def filter(cls, fuzzers, name, sanitizer=None, example_fuzzers=True):
    """Filters a list of fuzzer names.

      Takes a list of fuzzer names in the form `pkg`/`tgt` and a name to filter
      on.  If the name is of the form 'x/y', the filtered list will include all
      the fuzzer names where 'x' is a substring of `pkg` and y is a substring
      of `tgt`; otherwise it includes all the fuzzer names where `name` is a
      substring of either `pkg` or `tgt`.

      Returns:
        A list of fuzzer names matching the given name.

      Raises:
        FuzzerNameError: Name is malformed, e.g. of the form 'x/y/z'.
    """
    if not name and not sanitizer:
      return fuzzers
    if name:
      names = name.split('/')
      if len(names) == 2 and (names[0], names[1]) in fuzzers:
        return [(names[0], names[1])]
      if len(names) == 1:
        return list(
            set(Fuzzer.filter(fuzzers, '/' + name))
            | set(Fuzzer.filter(fuzzers, name + '/')))
      if len(names) != 2:
        raise Fuzzer.NameError('Malformed fuzzer name: ' + name)
    filtered = []
    for pkg, tgt in fuzzers:
      if name:
        if not (names[0] in pkg and names[1] in tgt):
          continue
      if sanitizer:
        if not Fuzzer._matches_sanitizer(tgt, sanitizer):
          continue
      if not example_fuzzers:
        if Fuzzer._is_example(pkg, tgt):
          continue
      # Remove the sanitizer extension name.
      # Clusterfuzz only needs to know foo/bar, not foo/bar.asan.
      filtered.append((pkg, os.path.splitext(tgt)[0]))
    return filtered

  @classmethod
  def from_args(cls, device, args):
    """Constructs a Fuzzer from command line arguments."""
    fuzzers = Fuzzer.filter(device.host.fuzzers, args.name)
    if len(fuzzers) != 1:
      raise Fuzzer.NameError('Name did not resolve to exactly one fuzzer: \'' +
                             args.name + '\'. Try using \'list-fuzzers\'.')
    return cls(device, fuzzers[0][0], fuzzers[0][1], args.output,
               args.foreground)

  def __init__(self,
               device,
               pkg,
               tgt,
               output=None,
               foreground=False,
               sanitizer=''):
    self.device = device
    self.host = device.host
    self.pkg = pkg
    self.tgt = tgt
    self.last_fuzz_cmd = None
    if output:
      self._output = output
    else:
      self._output = self.host.join('test_data', 'fuzzing', self.pkg, self.tgt)
    self._results_output = self.host.join('test_data', 'fuzzing', self.pkg,
                                          self.tgt)
    self._foreground = foreground

    # Required for backwards compatibility with older builds where Zircon
    # fuzzers had a sanitizer suffix
    if pkg == 'zircon_fuzzers' and sanitizer:
      if (pkg, tgt) not in self.host.fuzzers:
        self.tgt += '.' + sanitizer

  def __str__(self):
    return self.pkg + '/' + self.tgt

  def data_path(self, relpath=''):
    """Canonicalizes the location of mutable data for this fuzzer."""
    return '/data/r/sys/fuchsia.com:%s:0#meta:%s.cmx/%s' % (self.pkg, self.tgt,
                                                            relpath)

  def measure_corpus(self):
    """Returns the number of corpus elements and corpus size as a pair."""
    try:
      sizes = self.device.ls(self.data_path('corpus'))
      return (len(sizes), sum(sizes.values()))
    except subprocess.CalledProcessError:
      return (0, 0)

  def list_artifacts(self):
    """Returns a list of test unit artifacts, i.e. fuzzing crashes."""
    artifacts = []
    try:
      lines = self.device.ls(self.data_path())
      for artifact, _ in six.iteritems(lines):
        for prefix in Fuzzer.ARTIFACT_PREFIXES:
          if artifact.startswith(prefix):
            artifacts.append(artifact)
      return artifacts
    except subprocess.CalledProcessError:
      return []

  def is_running(self):
    """Checks the device and returns whether the fuzzer is running."""
    return self.tgt in self.device.getpids()

  def require_stopped(self):
    """Raise an exception if the fuzzer is running."""
    if self.is_running():
      raise Fuzzer.StateError(
          str(self) + ' is running and must be stopped first.')

  def results(self, relpath=None):
    """Returns the path in the previously prepared results directory."""
    if relpath:
      return os.path.join(self._output, 'latest', relpath)
    return os.path.join(self._output, 'latest')

  def results_output(self, relpath=None):
    if relpath:
      return os.path.join(self._results_output, relpath)
    return self._results_output

  def url(self):
    return 'fuchsia-pkg://fuchsia.com/%s#meta/%s.cmx' % (self.pkg, self.tgt)

  def run(self, fuzzer_args, logfile=None):
    fuzz_cmd = ['run', self.url(), '-artifact_prefix=data/'] + fuzzer_args
    print('+ ' + ' '.join(fuzz_cmd))
    self.last_fuzz_cmd = self.device.get_ssh_cmd(['ssh', 'localhost'] +
                                                 fuzz_cmd)
    return self.device.ssh(fuzz_cmd, quiet=True, logfile=logfile)

  def start(self, fuzzer_args):
    """Runs the fuzzer.

      Executes a fuzzer in the "normal" fuzzing mode. It spawns the fuzzer,
      but does not wait until it completes. As a result, callers will
      typically want to subsequently call Fuzzer.monitor()

      The command will be like:
      run fuchsia-pkg://fuchsia.com/<pkg>#meta/<tgt>.cmx \
        -artifact_prefix=data/ -jobs=1 data/corpus/

      See also: https://llvm.org/docs/LibFuzzer.html#running

      Args:
        fuzzer_args: Command line arguments to pass to libFuzzer

      Returns:
        The fuzzer's process ID. May be 0 if the fuzzer stops immediately.
    """
    self.require_stopped()
    results = os.path.join(self._output, datetime.datetime.utcnow().isoformat())
    try:
      os.makedirs(results)
    except OSError as e:
      if e.errno != errno.EEXIST:
        raise
    self._results_output = results
    self.logfile = self.results_output('fuzz-0.log')

    if [x for x in fuzzer_args if x.startswith('-jobs=')]:
      if self._foreground:
        fuzzer_args.append('-jobs=0')
      else:
        fuzzer_args.append('-jobs=1')
    self.device.ssh(['mkdir', '-p', self.data_path('corpus')])
    # If all the arguments are prepended with '-', then no corpus has been
    # passed in, and we need to add one.
    # This list comprehension returns a list of all arguments that do *not*
    # start with '-'.
    # Thus, if the list is empty, we append data/corpus/.
    # TODO(flowerhack): Strictly speaking, libfuzzer doesn't *need* a corpus
    # directory to run, and a user may find it confusing that one is
    # automagically created.
    # Change this to *not* be the default.  (If we'd like it to make it the
    # default for e.g. most non-Clusterfuzz callers, we can have some variable
    # that those callers pass in to set this.)
    if not [x for x in fuzzer_args if not x.startswith('-')]:
      fuzzer_args.append('data/corpus/')
    if 'repro' in fuzzer_args:
      # If this is a reproducer run, we don't need the corpus.
      if 'data/corpus/' in fuzzer_args:
        fuzzer_args.remove('data/corpus/')
      fuzzer_args.remove('repro')

    # Fuzzer logs are saved to fuzz-*.log when running in the background.
    # We tee the output to fuzz-0.log when running in the foreground to
    # make the rest of the plumbing look the same.
    if self._foreground:
      return self.run(fuzzer_args, logfile=self.results_output('fuzz-0.log'))
    self.device.rm(self.data_path('fuzz-*.log'))
    return self.run(fuzzer_args)

  def monitor(self, retcode=0):
    """Waits for a fuzzer to complete and symbolizes its logs.

        Polls the device to determine when the fuzzer stops. Retrieves,
        combines and symbolizes the associated fuzzer and kernel logs. Fetches
        any referenced test artifacts, e.g. crashes.
        """
    while self.is_running():
      time.sleep(2)
    if not self._foreground:
      self.device.fetch(self.data_path('fuzz-*.log'), self.results_output())
    logs = glob.glob(self.results_output('fuzz-*.log'))
    guess_pid = len(logs) == 1
    artifacts = []
    for log in logs:
      artifacts += self.device.process_logs(log, guess_pid, retcode)
    for artifact in artifacts:
      self.device.fetch(self.data_path(artifact), self.results_output())

  def stop(self):
    """Stops any processes with a matching component manifest on the device."""
    pids = self.device.getpids()
    if self.tgt in pids:
      self.device.ssh(['kill', str(pids[self.tgt])])

  def repro(self, fuzzer_args):
    """Runs the fuzzer with test input artifacts.

      Executes a command like:
      run fuchsia-pkg://fuchsia.com/<pkg>#meta/<tgt>.cmx \
        -artifact_prefix=data -jobs=1 data/<artifact>...

      See also: https://llvm.org/docs/LibFuzzer.html#options

      Returns: Number of test input artifacts found.
    """
    artifacts = self.list_artifacts()
    if artifacts:
      self.run(fuzzer_args + ['data/' + a for a in artifacts])
    return len(artifacts)

  def merge(self, fuzzer_args, merge_control_file=None):
    """Attempts to minimizes the fuzzer's corpus.

      Executes a command like:
      run fuchsia-pkg://fuchsia.com/<pkg>#meta/<tgt>.cmx \
        -artifact_prefix=data -jobs=1 \
        -merge=1 -merge_control_file=data/.mergefile \
        data/corpus/ data/corpus.prev/'

      See also: https://llvm.org/docs/LibFuzzer.html#corpus

      Returns: Same as measure_corpus
    """
    self.require_stopped()
    if self.measure_corpus() == (0, 0):
      return (0, 0)

    # If all the arguments are prepended with '-', then no corpus has been
    # passed in, so we need to execute the "default" behavior: assuming
    # "corpus" is the only relevant directory, and making a new corpus
    # directory.
    # If corpora have been passed in, we trust that the caller has passed
    # them in the order they want.
    if not [x for x in fuzzer_args if not x.startswith('-')]:
      self.device.ssh(['mkdir', '-p', self.data_path('corpus')])
      self.device.ssh(['mkdir', '-p', self.data_path('corpus.prev')])
      self.device.ssh(
          ['mv',
           self.data_path('corpus/*'),
           self.data_path('corpus.prev')])
      self.device.ssh(['mkdir', '-p', self.data_path('corpus')])
      fuzzer_args.append('data/corpus/')
      fuzzer_args.append('data/corpus.prev/')

    if not merge_control_file:
      merge_control_file = 'data/.mergefile'

    merge_args = ['-merge=1', '-merge_control_file=' + merge_control_file]
    self.run(merge_args + fuzzer_args)

    # Cleanup
    self.device.rm(self.data_path('.mergefile'))
    self.device.rm(self.data_path('corpus.prev'), recursive=True)
    return self.measure_corpus()
