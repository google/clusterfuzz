Change Log
==========

## Next Version
- Various bug fixes.

## Version 1.5.0
- Added Golang stack parsing.
- Added Sanitizer options minimization.
- Added HELP_FORMAT for custom crash reproduction instructions.
  See documentation [here](configs/test/project.yaml#L99).
- Added feature to show reproducible variants for a crash on other jobs
  (`Reproducer` column in `Testcase analysis on other jobs` section).
- Refactored engine fuzzer code for easy pluggability.
- Reproduce tool improvements - performance fixes, added android support.
- UI improvements - search filter in dropdowns.
- Various bug fixes.

## Version 1.4.0
- Implemented issue tracker policy and finishing the refactoring for supporting
  different issue trackers.
- Disabled external mutators (Radamsa and ML RNN) for fuzz targets built with
  libprotobuf-mutator library.
- Added support for auxiliary fuzzing builds (e.g. DFSan instrumented builds for
  libFuzzer).
- Refactored `build_manager` and `fuzz_task`.
- Optimized performance of the most frequently used pages (Testcases and
  Testcase Details).
- Added explicit schema for the BigQuery import calls (used to load the fuzzer
  stats data into BigQuery).
- Added experimental implementation of the Multi-Armed Bandit algorithm for
  fuzzing strategy selection.
- Implemented `variant` task that runs testcases on different jobs in order to
  provide more information about the bugs.
- Implemented the new version of the reproduce tool, which currently works on
  Linux.
- Various bug fixes.

## Version 1.3.0
- Fixed security severity listbox not working.
- More Python 2->3 conversions using futurize.
- Delete button on jobs page.
- New interface for issue management, as part of refactor to support more issue
  trackers.
- Android code refactoring.
- Various bug fixes.

## Version 1.2.1
- Various bug fixes.

## Version 1.2.0
- Use Firebase auth for authentication.
- Use Sendgrid for emails.
- Remove various dependencies on App Engine SDK.
- Add support for `close_fd_mask` in AFL fuzzing.
- Add metrics `new_features` and `new_edges` in libFuzzer fuzzing.
- Support for multiple device per host in Android startup script.
- Fix corpus minimization in libFuzzer and AFL to prioritize smaller units.
- Preparation for Python 2->3 migration using futurize.
- Various bug fixes.

## Version 1.1.0
- Add support for
  [android-cuttlefish](https://github.com/google/android-cuttlefish).
- Add production startup scripts for Android.
- Add support for libFuzzer fork mode.
- Add support for [Stackdriver Profiler](https://cloud.google.com/profiler/).
- Add an initial permissive CSP, to be improved in later releases.
- Fuzzer weights now scale based on the severity of discovered issues instead of
  imposing a fixed penalty beyond a threshold.
- Various bug fixes.

## Version 1.0.1
- Bug fixes to improve local development.

## Version 1.0.0
- Initial release.
