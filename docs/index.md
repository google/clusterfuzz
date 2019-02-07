---
layout: default
title: ClusterFuzz
permalink: /
nav_order: 1
has_children: true
---

# ClusterFuzz

<p align="center">
  <img src="{{ site.baseurl }}/images/logo.png" width="400">
</p>

ClusterFuzz is a scalable [fuzzing](https://en.wikipedia.org/wiki/Fuzzing)
infrastructure which finds security and stability issues in software.

It is used by Google for fuzzing the Chrome Browser, and serves as the fuzzing
backend for [OSS-Fuzz].

ClusterFuzz provides many features to seamlessly integrate fuzzing into
a software project's development process:
- Highly scalable. Google's internal instance runs on over 25,000 machines.
- Accurate deduplication of crashes.
- Fully automatic bug filing and closing for issue trackers ([Monorail] only for now).
- Testcase minimization.
- Regression finding through [bisection](https://en.wikipedia.org/wiki/Bisection_(software_engineering)).
- Statistics for analyzing fuzzer performance, and crash rates.
- Easy to use web interface for management and viewing crashes.
- Support for [coverage guided fuzzing] (e.g. libFuzzer and AFL) and
  [blackbox fuzzing].

[Monorail]: https://opensource.google.com/projects/monorail

## Trophies
As of January 2019, ClusterFuzz has found [~16,000] bugs
in Chrome and [~11,000] bugs in over [160] open source projects integrated with
[OSS-Fuzz].

[~16,000]: https://bugs.chromium.org/p/chromium/issues/list?can=1&q=label%3AClusterFuzz+-status%3AWontFix%2CDuplicate
[~11,000]: https://bugs.chromium.org/p/oss-fuzz/issues/list?can=1&q=-status%3AWontFix%2CDuplicate+-Infra
[160]: https://github.com/google/oss-fuzz/tree/master/projects
[OSS-Fuzz]: https://github.com/google/oss-fuzz
[Monorail]: https://opensource.google.com/projects/monorail
[blackbox fuzzing]: {{ site.baseurl }}/setting-up-fuzzing/blackbox-fuzzing/
[coverage guided fuzzing]: {{ site.baseurl }}/setting-up-fuzzing/libfuzzer-and-afl/
