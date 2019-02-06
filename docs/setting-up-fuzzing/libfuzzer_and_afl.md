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
LibFuzzer and AFL need to use instrumentation from the Clang compiler. In our
documentation, we use features provided by Clang **6.0** or greater. To get a
Clang that can be used to follow the examples, download one from the [Clang
releases page] or install one using your package manager. We will refer to these
compilers as `$CC` and `$CXX`. Set these in the environment so that you can easily
copy and paste the example commands:

```bash
export CC=path/to/clang
export CXX=path/to/clang++
```

### Platform
libFuzzer is supported on Linux, macOS, and Windows. For Windows, you will need
to change the commands to work in cmd.exe and you will need Clang **9.0** or
greater which you can download from the [LLVM Snapshot Builds page].

AFL is only supported on Linux.

[LLVM Snapshot Builds page]: https://llvm.org/builds/

## Builds

### libFuzzer
LibFuzzer targets are easy to build. Just compile a [fuzz target] with
`-fsanitize=fuzzer` and a [sanitizer] such as [AddressSanitizer]
(`-fsanitize=address`).

```bash
$CXX -fsanitize=address,fuzzer fuzzer.cc -o fuzzer
# Test out the build by fuzzing it.
./fuzzer -runs=10
# Create a fuzzer build to upload to ClusterFuzz.
zip fuzzer-build.zip fuzzer
```

libFuzzer builds are zip files that contain any targets you want to fuzz and
their dependencies.

[sanitizer]: {{ site.baseurl }}/reference/glossary/#sanitizer

### AFL
ClusterFuzz supports fuzzing libFuzzer harness functions
(`LLVMFuzzerTestOneInput`) with AFL. To compile a fuzz target for AFL, run our
[script] which downloads and builds AFL and `FuzzingEngine.a`, a library you can
link the target against to make it AFL compatible. Then compile your target
using `-fsanitize-coverage=trace-pc-guard`.


```bash
# Build afl-fuzz and FuzzingEngine.a
./build_afl.bash
$CXX -fsanitize=address -fsanitize-coverage=trace-pc-guard fuzzer.cc FuzzingEngine.a -o fuzzer
# Test out the build by fuzzing it. INPUT_CORPUS is a directory containing files. Ctrl-C when done.
AFL_SKIP_CPUFREQ=1 ./afl-fuzz -i $INPUT_CORPUS -o output -m none ./fuzzer
# Create a fuzzer build to upload to ClusterFuzz.
zip fuzzer-build.zip fuzzer afl-fuzz afl-showmap
```

AFL builds are zip files that contain any targets you want to fuzz, their
dependencies, and AFL's dependencies: `afl-fuzz` and `afl-showmap` (both built
by the [script]).

AFL only supports [AddressSanitizer].

## Creating a job type
LibFuzzer jobs **must** contain the string **"libfuzzer"** in their name, AFL
jobs **must** contain the string **"afl"** in their name.
**"libfuzzer_asan_my_project"** and **"afl_asan_my_project"** are examples of
correct names for libFuzzer and AFL jobs that use [ASan].

To create a job for libFuzzer or AFL:
1. Navigate to the *Jobs* page.
2. Go to the "ADD NEW JOB" form.
3. Fill out the "Name" and "Platform" (LINUX).
  1. If setting up an **AFL** job, use the templates **"afl"** and
     **"engine_asan"**.
  2. If setting up a **libFuzzer** job, use the templates **"libfuzzer"** and
     **"engine_$SANITIZER"** depending on which sanitizer you are using (e.g.
     **"engine_asan"**).
4. Select your build (your zip containing the fuzz target binary) to upload as a
   "Custom Build". If you are running ClusterFuzz in production, it is
   recommended to set up a [build pipeline] and follow [these] instructions on
   providing continuous builds rather than using a "Custom Build".
5. Use the "ADD" button to add the job to ClusterFuzz.

Next we must let ClusterFuzz know which fuzzer the job can be used with:
1. Navigate to the *Fuzzers* page.
2. Click "EDIT" for the desired fuzzer (afl or libFuzzer).
3. Click "Select/modify jobs".
4. Mark the desired job.
5. Click "SUBMIT".

[ASan]: https://clang.llvm.org/docs/AddressSanitizer.html
[these]: {{ site.baseurl }}/production-setup/setting-up-fuzzing-job/

### Enabling corpus pruning
It is important that you enable [corpus pruning] to run once a day to prevent
uncontrolled corpus growth. This **must** be done by setting **"CORPUS_PRUNE =
True"** in the Environment String for your **libFuzzer ASan** job.

## Checking results
You can observe ClusterFuzz fuzzing your build by looking at the [bot logs]. Any
bugs it finds can be found on the *Testcases* page. If you are running
ClusterFuzz in production (ie: not locally), you can also view [crash stats] and
[fuzzer stats] (one generally needs to wait a day to view fuzzer stats).

## AFL limitations
Though ClusterFuzz supports fuzzing with AFL, it doesn't support using it for
[corpus pruning] and [crash minimization]. Therefore, if you use AFL, you should
also use libFuzzer which supports these tasks.

[AFL]: http://lcamtuf.coredump.cx/afl/
[AddressSanitizer]: https://clang.llvm.org/docs/AddressSanitizer.html
[Clang releases page]: http://releases.llvm.org/download.html
[afl_driver.cpp]: https://raw.githubusercontent.com/llvm-mirror/compiler-rt/master/lib/fuzzer/afl/afl_driver.cpp
[bot logs]: {{ site.baseurl }}/getting-started/local-instance/#viewing-logs
[build pipeline]: {{ site.baseurl }}/production-setup/build-pipeline/
[corpus pruning]: {{ site.baseurl }}/reference/glossary/#corpus-pruning
[coverage guided fuzzing]: {{ site.baseurl }}/reference/coverage-guided-vs-blackbox/#coverage-guided-fuzzing
[crash minimization]: {{ site.baseurl }}/reference/glossary/#minimization
[crash stats]: {{ site.baseurl }}/using-clusterfuzz/ui-overview/#crash-statistics
[fuzz target]:https://llvm.org/docs/LibFuzzer.html#id22
[fuzzer stats]: {{ site.baseurl }}/using-clusterfuzz/ui-overview/#fuzzer-statistics
[latest AFL source]:http://lcamtuf.coredump.cx/afl/releases/afl-latest.tgz
[libFuzzer]: https://llvm.org/docs/LibFuzzer.html
[script]: {{ site.baseurl }}/setting-up-fuzzing/build_afl.bash
