Change Log
==========

## Next Version
- Various bug fixes.

## Version 1.3.0
- Various bug fixes.
- Fixed security severity listbox not working.
- More Python 2->3 conversions using futurize.
- Delete button on jobs page.
- New interface for issue management, as part of refactor to support more issue
  trackers.
- Android code refactoring.

## Version 1.2.1
- Various bug fixes.

## Version 1.2.0
- Various bug fixes.
- Use Firebase auth for authentication.
- Use Sendgrid for emails.
- Remove various dependencies on App Engine SDK.
- Add support for `close_fd_mask` in AFL fuzzing.
- Add metrics `new_features` and `new_edges` in libFuzzer fuzzing.
- Support for multiple device per host in Android startup script.
- Fix corpus minimization in libFuzzer and AFL to prioritize smaller units.
- Preparation for Python 2->3 migration using futurize.

## Version 1.1.0
- Various bug fixes.
- Add support for
  [android-cuttlefish](https://github.com/google/android-cuttlefish).
- Add production startup scripts for Android.
- Add support for libFuzzer fork mode.
- Add support for [Stackdriver Profiler](https://cloud.google.com/profiler/).
- Add an initial permissive CSP, to be improved in later releases.
- Fuzzer weights now scale based on the severity of discovered issues instead of
  imposing a fixed penalty beyond a threshold.

## Version 1.0.1
- Bug fixes to improve local development.

## Version 1.0.0
- Initial release.
