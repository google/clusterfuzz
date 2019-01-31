---
layout: default
title: libFuzzer and AFL
parent: Setting up fuzzing
nav_order: 1
permalink: /setting-up-fuzzing/libfuzzer-and-afl/
---

# libFuzzer and AFL
This page walks you through setting up [coverage guided fuzzing] using
[libFuzzer] or [AFL].

- TOC
{:toc}

---

## Prerequisites

### Compiler
LibFuzzer and AFL (they way it is used by ClusterFuz) need to use
instrumentation from the clang compiler. In our documentation, we use features
provided by clang 6.0 or greater. To get a clang that can be used to follow the
examples, download one from the [clang releases page] or install one using your
package manager. We will refer to this compiler as `$CC`. You should use this
command so that you can copy and paste the example commands:

```bash
export CC=path/to/clang
export CXX=path/to/clang
```

### Platform
This document assumes you are using Linux and have a ClusterFuzz server and bot
running on Linux, see [here] for how to do that. The examples should work on
Windows and Mac where libFuzzer is fully supported. For Windows, you will need
to change the commands to work in cmd.exe and you will need clang 9.0 or greater
which you can download from the [LLVM Snapshot Builds page].

## Builds

### LibFuzzer
LibFuzzer targets are easy to build. Just compile a [fuzz target] with
`-fsanitize=fuzzer` and a [sanitizer] such as [AddressSanitizer]
(`-fsanitize=address`).

```bash
$ $CC -fsanitize=address,fuzzer fuzzer.cc -o fuzzer
# Test out the build by fuzzing it.
$ ./fuzzer -runs=10
# Create a fuzzer build to upload to ClusterFuzz.
$ zip fuzzer-build.zip fuzzer
```

libFuzzer builds are zip files that contain any fuzzers you want to run and
their dependencies.

### AFL
ClusterFuzz supports fuzzing libFuzzer harness functions
(`LLVMFuzzerTestOneInput`) with AFL. To compile a fuzz target for AFL, run our
[script] which downloads and builds AFL and `FuzzingEngine.a`, a library you can
link the target against to make it AFL compatible. Then compile your target
using `-fsanitize-coverage=trace-pc-guard`.


```bash
# Build afl-fuzz and FuzzingEngine.a
$ ./build_afl.bash
$ $CC -fsanitize=address -fsanitize-coverage=trace-pc-guard fuzzer.cc FuzzingEngine.a -o fuzzer
# Test out the build by fuzzing it. INPUT_CORPUS is a directory containing files. Ctrl-C when done.
$ AFL_SKIP_CPUFREQ=1 ./afl-fuzz -i $INPUT_CORPUS -o output -m none ./fuzzer
# Create a fuzzer build to upload to ClusterFuzz.
$ zip fuzzer-build.zip fuzzer afl-fuzz afl-showmap
```

AFL builds are zip files that contain any targets you want to fuzz, their
dependencies, and AFL's dependencies: `afl-fuzz` and `afl-showmap` (both built
by the script).

## Creating a job type
LibFuzzer jobs must contain the string 'libfuzzer' in their name, AFL jobs must
contain the string 'afl' in their name. `libfuzzer_asan` and `afl_asan` are
examples of correct names for libFuzzer and AFL jobs that use ASan.

To create a job for libFuzzer or AFL:
* Navigate to the Jobs page.
* Go to the form to "ADD NEW JOB".
* Fill out the "Name" and "Platform" (LINUX). If setting up an AFL job, use the
  templates "afl" and "engine_asan". If setting up a libFuzzer job, use the
  templates "libfuzzer" and "engine_$SANITIZER_NAME" depending on which
  sanitizer you are using (e.g. "libfuzzer_asan").
* Select your build (your zip containing the fuzz target binary) to upload as a
  "Custom Build".
* Use the "ADD" button to add the job to ClusterFuzz.

Next we must let ClusterFuzz know which fuzzer the job can be used with:
* Navigate to the Fuzzers page.
* Edit the desired fuzzer (afl or libFuzzer).
* Click "Select/modify jobs".
* Mark the desired job.
* Press "SUBMIT".

## Checking results
You can observe ClusterFuzz fuzzing your build by looking at the [bot logs]. Any
bugs it finds can be found on the Testcases page. If you are running ClusterFuzz
in production (ie: not locally), you can also view [crash stats] and [fuzzer
stats] (one generally needs to wait a day to view fuzzer stats).

## AFL limitations
Though ClusterFuzz supports fuzzing with AFL, it doesn't support using it for
corpus pruning and crash minimization. Therefore, if you use AFL, you should
also use libFuzzer as ClusterFuzz will use it for minimization and pruning.

[AFL]: http://lcamtuf.coredump.cx/afl/
[libFuzzer]: https://llvm.org/docs/LibFuzzer.html
[fuzz target]:https://llvm.org/docs/LibFuzzer.html#id22
[sanitizer]: https://github.com/google/sanitizers
[AddressSanitizer]: https://github.com/google/sanitizers/wiki/AddressSanitizer
[clang releases page]: http://releases.llvm.org/download.html
[latest AFL source]:http://lcamtuf.coredump.cx/afl/releases/afl-latest.tgz
[afl_driver.cpp]: https://raw.githubusercontent.com/llvm-mirror/compiler-rt/master/lib/fuzzer/afl/afl_driver.cpp
[script]: {{ site.baseurl }}/setting-up-fuzzing/build_afl.bash
[here]: {{ site.baseurl }}/getting-started/local_instance/
[LLVM Snapshot Builds page]: https://llvm.org/builds/
[bot logs]: {{ site.baseurl }}/getting-started/local-instance/#viewing-logs
[fuzzer stats]: {{ site.baseurl }}/ui-overview/#Fuzzer-Statistics
[crash stats]: {{ site.baseurl }}/ui-overview/#Crash-Statistics
[coverage guided fuzzing]: {{ site.baseurl }}/reference/coverage-guided-vs-blackbox/#coverage-guided-fuzzing
