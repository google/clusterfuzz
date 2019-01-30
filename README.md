# ClusterFuzz

<p align="center">
  <img src="docs/images/logo.png">
</p>

ClusterFuzz is a scalable fuzzing infrastructure which finds security and stability issues in software.

It is used by Google for fuzzing the Chrome Browser, and serves as the fuzzing backend for OSS-Fuzz.

ClusterFuzz provides many features which help seamlessly integrate fuzzing into
a software project's development process:
- Highly scalable. Google's internal instance runs on over 25,000 machines.
- Accurate deduplication of crashes.
- Fully automatic bug filing and closing for issue trackers ([Monorail] only for now):
- Testcase minimization.
- Regression finding through [bisection](https://en.wikipedia.org/wiki/Bisection_(software_engineering)).
- Statistics for analyzing fuzzer performance, and crash rates.
- Easy to use web interface for management and viewing crashes.

## Overview

![overview](docs/images/overview.png)

## Documentation
You can find detailed documentation

[here](https://google.github.io/clusterfuzz).
