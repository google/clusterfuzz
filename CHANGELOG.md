Change Log
==========

## Version 2.5.0
- Restructured internal imports to make pip package cleaner.
- AFL++ support.
- Many bug fixes.

## Version 2.4.0
- Various improvements for libClusterFuzz.
- Local development improvements.
- Add AFL support to the fuzzing engine pipeline.
- Various bug fixes.

## Version 2.3.0
- Improved ML-based fuzzing.
- Various bug fixes.

## Version 2.2.0
- Replaced webapp2 usage with Flask.
- Improved Syzkaller support.
- Added support for generic blackbox fuzzers.
- Removed remaining Python 2 compatibility code.
- Various bug fixes.

## Version 2.1.0
- Jobs page is now paginated.
  - Next version requires new DB migrations due to addition of search keywords in Jobs.
  - To perform migrations, please use:
```
python butler.py run -c path/to/config --non-dry-run migration.jobs_keywords
```
- Jobs page now has the ability to specify Fuzzer-Job mappings.
- Past crash regressions are now stored in the corpus backup.
- Set handle_<signal>=2 by default for sanitizer options in engine jobs.
- Fix local GCS issues.
- Remove more Python 2 support.
- Various bug fixes.

## Version 2.0.2
- Improved Syzkaller support.
- Support narrower bisection for regression/fix ranges.
- Improve Rust crash detection signatures.
- Improved Android KASan support.
- Batch datastore operations more aggressively.
- Improved grouping of crashes involving inline frames.
- Enable entropic fuzzing strategy in libFuzzer.
- Test past crash regressions in corpus pruning task.
- Various bug fixes.

## Version 2.0.1
- Various bug fixes.

## Version 2.0.0
- Various bug fixes.

## Version 1.9.0
- Python 3 migration is complete.
- Added Peach mutation strategy for engine fuzzers.
- Added support for Google Cloud IAP authentication.
- Added stop gaps to prevent corpus explosion (e.g. corpus element must be less than 5 MB).
- Use ANTLR grammar for tokenization during testcase minimization (html, js).
- Store statistics on corpus cross-pollination during corpus pruning.
- Removed dependency on Google App Engine SDK.
- Removed unused Go code.
- Various bug fixes.

## Version 1.8.0
- Added an uploader permission type to allow certain users to upload to any job/fuzzer.
- More Python 3 conversion changes.
- Bumped up libFuzzer rss limit to 2.5GB.
- Various bug fixes.

## Version 1.7.1
- Various bug fixes.

## Version 1.7.0
- Better crash type reporting on various UBSan issues.
- Initial support for Honggfuzz.
- Additional fixes in preparation for migration to Python 3.
- Migrated off deprecated App Engine Memcache to Cloud MemoryStore for Redis.
- Added libFuzzer fuzzing support for Android (using HWASan).
- Automatically correct certain common mistakes in dictionaries.
- Various bug fixes.

## Version 1.6.1
- Various bug fixes.

## Version 1.6.0
- Added platform support for Fuchsia OS.
- Migrated libFuzzer to the new pluggable engine pipeline.
- Stack parsing improvements.
- Various bug fixes.

## Version 1.5.1
- Fixed XSS in login page.

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
