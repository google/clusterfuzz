---
layout: default
title: Analyzing fuzzer performance
permalink: /using-clusterfuzz/workflows/analyzing-fuzzing-performance/
nav_order: 3
parent: Workflows
grand_parent: Using ClusterFuzz
---

# Analyzing fuzzer performance

ClusterFuzz automates fuzzing as much as possible, but it's the responsibility
of users to write and maintain fuzzers that can find security bugs. This page
gives recommendations on how to analyze the performance of the fuzzers running
on ClusterFuzz.

**Note**: this page only applies to [fuzz targets] doing [coverage guided]
fuzzing with [libFuzzer] or [AFL].

[AFL]: http://lcamtuf.coredump.cx/afl/
[libFuzzer]: https://llvm.org/docs/LibFuzzer.html
[coverage guided]: {{ site.baseurl }}/reference/coverage-guided-vs-blackbox/
[fuzz targets]: {{ site.baseurl }}/reference/glossary/#fuzz-target

- TOC
{:toc}

---

## When to analyze fuzz target performance

It's important to regularly monitor the performance of fuzz targets, especially
after a new target is created. If a target finds many new crashes, fixing them
is probably more important than analyzing performance. But if a target has not
found any crashes in a while, you should probably examine its performance.

## Performance factors

* **Speed** is crucial for fuzzing. There is no minimum threshold. The faster a
  fuzz target generates testcases, the better.
* **Code coverage** should grow over time. A fuzz target should be continuously
  generating new "interesting" testcases that exercise various parts of the
  target program.
* **Blocking issues** should be resolved. If a fuzz target frequently reports a
  Timeout, Out-of-Memory, or other crashes, it will be blocking the target from
  finding more interesting issues.

## Fuzzer stats

The *Fuzzer stats* page provides metrics on fuzzer performance. Using
the filters on the page, you can see how those metrics (e.g. execution speed or
number of crashes) change over time (if you choose "Group by Day"). You can
compare different fuzzers to one another using "Group by Fuzzer". There is also
a "Group by Time" filter that shows fuzzer stats as charts rather than raw
numbers.

This feature requires a [production setup]({{ site.baseurl }}/production-setup/),
as fuzzer stats are stored in [BigQuery]. The stats are usually delayed by up to
24 hours, as data is uploaded to BigQuery once a day.

[BigQuery]: https://cloud.google.com/bigquery/

## Performance report

ClusterFuzz provides automatically generated performance reports that identify
performance issues and give recommendations on how those issues can be resolved.
The reports also prioritize issues and provide fuzzer logs that demonstrate the
issues.

## Coverage report

Code coverage is a very important metric for evaluating fuzzer performance.
Looking at the code coverage report, you can see which exact parts of the target
program are tested by the fuzzer and which parts are never executed. If you set
up a [code coverage builder] for ClusterFuzz, you can find links to the coverage
reports on the Fuzzer stats page. Otherwise, you can generate code coverage
reports locally. For C and C++ targets, we recommend using [Clang Source-based
Code Coverage].

[code coverage builder]: {{ site.baseurl }}/using-clusterfuzz/advanced/code-coverage/

## Fuzzer logs

If none of the above gives you enough information about fuzzer performance,
looking into the fuzzer logs may help. On the fuzzer stats page, you can find a
link to the GCS bucket storing the logs. You can also navigate to that manually
using the Google Cloud Storage [web interface].

[Clang Source-based Code Coverage]: https://clang.llvm.org/docs/SourceBasedCodeCoverage.html
[web interface]: https://console.cloud.google.com/storage/browser
