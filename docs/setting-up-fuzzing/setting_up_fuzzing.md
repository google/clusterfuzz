---
layout: default
title: Setting up fuzzing
has_children: true
nav_order: 3
permalink: /setting-up-fuzzing/
---

# Setting up fuzzing

These pages walk you through setting up fuzzing jobs.

The two types of fuzzing supported on ClusterFuzz are coverage guided fuzzing
(using [libFuzzer] and [AFL]) and blackbox fuzzing. See [this page] for a comparison.

[AFL]: http://lcamtuf.coredump.cx/afl/
[libFuzzer]: https://llvm.org/docs/LibFuzzer.html
[this page]: {{ site.baseurl }}/reference/coverage-guided-vs-blackbox/
