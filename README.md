# ClusterFuzz

<p align="center">
  <img src="docs/images/logo.png" width="400">
</p>

ClusterFuzz is a scalable fuzzing infrastructure which finds security and
stability issues in software.

It is used by Google for fuzzing the Chrome Browser, and serves as the fuzzing
backend for [OSS-Fuzz].

ClusterFuzz provides many features which help seamlessly integrate fuzzing into
a software project's development process:
- Highly scalable. Google's internal instance runs on over 25,000 machines.
- Accurate deduplication of crashes.
- Fully automatic bug filing and closing for issue trackers
  ([Monorail] only for now).
- Testcase minimization.
- Regression finding through [bisection].
- Statistics for analyzing fuzzer performance, and crash rates.
- Easy to use web interface for management and viewing crashes.
- [Firebase authentication].
- Support for coverage guided fuzzing (e.g. libFuzzer and AFL) and blackbox
  fuzzing.

## Overview

<p align="center">
  <img src="docs/images/overview.png">
</p>

## Documentation
You can find detailed documentation [here](https://google.github.io/clusterfuzz).

## Trophies
As of January 2019, ClusterFuzz has found [~16,000] bugs
in Chrome and [~11,000] bugs in over [160] open source projects integrated with
[OSS-Fuzz].

## Getting Help
You can [file an issue](https://github.com/google/clusterfuzz/issues/new) to ask
questions, request features, or ask for help.

## Staying Up to Date
We will use [clusterfuzz-announce(#)googlegroups.com](https://groups.google.com/forum/#!forum/clusterfuzz-announce) to make announcements about ClusterFuzz.

[~16,000]: https://bugs.chromium.org/p/chromium/issues/list?can=1&q=label%3AClusterFuzz+-status%3AWontFix%2CDuplicate
[~11,000]: https://bugs.chromium.org/p/oss-fuzz/issues/list?can=1&q=-status%3AWontFix%2CDuplicate+-Infra
[160]: https://github.com/google/oss-fuzz/tree/master/projects
[OSS-Fuzz]: https://github.com/google/oss-fuzz
[Monorail]: https://opensource.google.com/projects/monorail
[bisection]: https://en.wikipedia.org/wiki/Bisection_(software_engineering)
[Firebase authentication]: https://firebase.google.com/docs/auth
