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
infrastructure that finds security and stability issues in software.

Google uses ClusterFuzz to fuzz all Google products and as the fuzzing
backend for [OSS-Fuzz].

ClusterFuzz provides many features to seamlessly integrate fuzzing into
a software project's development process:
- Highly scalable. Can run on any size cluster (e.g. Google's instance runs on
  30,000 VMs).
- Accurate deduplication of crashes.
- Fully automatic bug filing, triage and closing for various issue trackers
  (e.g. [Monorail], [Jira]).
- Supports multiple [coverage guided fuzzing engines]
  ([libFuzzer], [AFL++] and [Honggfuzz])
  for optimal results (with [ensemble fuzzing] and [fuzzing strategies]).
- Support for [blackbox fuzzing].
- Testcase minimization.
- Regression finding through [bisection].
- Statistics for analyzing fuzzer performance, and crash rates.
- Easy to use web interface for management and viewing crashes.
- Support for various authentication providers using [Firebase].

[Monorail]: https://opensource.google.com/projects/monorail

## Trophies
As of May 2022, ClusterFuzz has found 25,000+ bugs in Google (e.g. [Chrome])
and [36,000+] bugs in over [550] open source projects integrated with [OSS-Fuzz].

[Chrome]: https://bugs.chromium.org/p/chromium/issues/list?can=1&q=label%3AClusterFuzz+-status%3AWontFix%2CDuplicate
[36,000+]: https://bugs.chromium.org/p/oss-fuzz/issues/list?q=-status%3AWontFix%2CDuplicate%20-component%3AInfra&can=1
[550]: https://github.com/google/oss-fuzz/tree/master/projects
[OSS-Fuzz]: https://github.com/google/oss-fuzz
[Monorail]: https://opensource.google.com/projects/monorail
[Jira]: https://www.atlassian.com/software/jira
[bisection]: https://en.wikipedia.org/wiki/Bisection_(software_engineering)
[Firebase]: https://firebase.google.com/docs/auth
[libFuzzer]: http://llvm.org/docs/LibFuzzer.html
[AFL++]: https://github.com/AFLplusplus/AFLplusplus
[Honggfuzz]: https://github.com/google/honggfuzz
[blackbox fuzzing]: {{ site.baseurl }}/setting-up-fuzzing/blackbox-fuzzing/
[coverage guided fuzzing engines]: {{ site.baseurl }}/setting-up-fuzzing/libfuzzer-and-afl/
[fuzzing strategies]: https://i.blackhat.com/eu-19/Wednesday/eu-19-Arya-ClusterFuzz-Fuzzing-At-Google-Scale.pdf#page=27
[ensemble fuzzing]: https://www.usenix.org/system/files/sec19-chen-yuanliang.pdf
