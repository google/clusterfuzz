---
layout: default
title: libFuzzer and AFL++
parent: Setting up fuzzing
nav_order: 1
permalink: /setting-up-fuzzing/libfuzzer-and-afl/
---

# libFuzzer and AFL
This page walks you through setting up [coverage guided fuzzing] using
[libFuzzer] or [AFL]. It also serves as a reference for using more advanced
features such as dictionaries and seed corpus.

- TOC
{:toc}

---

## Prerequisites

### Compiler
LibFuzzer and AFL need to use instrumentation from the Clang compiler. In our
documentation, we use features provided by Clang **6.0** or greater. However,
for serious use of ClusterFuzz, we recommend using as close to trunk Clang as
possible. To get a Clang build that is close to trunk you can download it from
the [snapshots page] (Windows) or follow the instructions on the [apt page]
(Ubuntu/Debian). Otherwise you can download a Clang release from the [releases
page] or install one using your package manager. We will refer to these
compilers in examples as `$CC` and `$CXX`. Set these in the environment so that
you can copy and paste the example commands:

```bash
export CC=/path/to/clang
export CXX=/path/to/clang++
```

[releases page]: http://releases.llvm.org/download.html
[apt page]: https://apt.llvm.org/
[snapshots page]: https://llvm.org/builds/

### Platform
libFuzzer is supported on Linux, macOS, and Windows. For Windows, you will need
to change the commands to work in cmd.exe and you will need Clang **9.0** or
greater which you can download from the [LLVM Snapshot Builds page].

AFL is only supported on Linux.

[LLVM Snapshot Builds page]: https://llvm.org/builds/

## Builds

### libFuzzer
LibFuzzer targets are easy to build. Just compile and link a [fuzz target] with
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
(`LLVMFuzzerTestOneInput`) with AFL++. AFL++ must be used with [AddressSanitizer].
To build a fuzz target for AFL, run our [script] which downloads and builds AFL
and `FuzzingEngine.a`, a library you can link the target against to make it AFL
compatible. Then compile and link your target using
`-fsanitize-coverage=trace-pc-guard` and `-fsanitize=address`.

Note: This will not use AFL++ to it's full potential as advanced fuzzing
features like CMPLOG and COMPCOV will not be enabled.
It is therefore recommended to use oss-fuzz to create (multiple) fuzzing
packages instead, as each package is instrumented with random options.


```bash
# Build afl-fuzz and FuzzingEngine.a
./build_afl.bash
# Compile target using ASan, coverage instrumentation, and link against FuzzingEngine.a
$CXX -fsanitize=address -fsanitize-coverage=trace-pc-guard fuzzer.cc FuzzingEngine.a -o fuzzer
# Test out the build by fuzzing it. INPUT_CORPUS is a directory containing files. Ctrl-C when done.
AFL_SKIP_CPUFREQ=1 ./afl-fuzz -i $INPUT_CORPUS -o output -m none ./fuzzer
# Create a fuzzer build to upload to ClusterFuzz.
zip fuzzer-build.zip fuzzer afl-fuzz afl-showmap
```

AFL builds are zip files that contain any targets you want to fuzz, their
dependencies, and AFL's dependencies: `afl-fuzz` and `afl-showmap` (both built
by the [script]).

## Creating a job type
LibFuzzer jobs **must** contain the string **"libfuzzer"** in their name, AFL++
jobs **must** contain the string **"afl"** in their name. Jobs must also contain
the name of the sanitizer they are using (e.g. "asan", "msan",  or "ubsan").
**"libfuzzer_asan_my_project"** and **"afl_asan_my_project"** are examples of
correct names for libFuzzer and AFL jobs that use AddressSanitizer.

To create a job for libFuzzer or AFL:
1. Navigate to the *Jobs* page.
2. Go to the "ADD NEW JOB" form.
3. Fill out the "Name" and "Platform" (LINUX).
4. Enable the desired fuzzer in the "Select/modify fuzzers" field, e.g.
   **libFuzzer**, **honggfuzz**, or **afl**.
5. If setting up an **AFL** job, use the templates **"afl"** and
   **"engine_asan"**.
6. If setting up a **honggfuzz** job, use the templates **"honggfuzz"** and 
   **"engine_asan"**.
7. If setting up a **libFuzzer** job, use the templates **"libfuzzer"** and
   **"engine_$SANITIZER"** depending on which sanitizer you are using (e.g.
   **"engine_asan"**).
8. Select your build (your zip containing the fuzz target binary) to upload as a
   "Custom Build". If you are running ClusterFuzz in production, it is
   recommended to set up a [build pipeline] and follow [these] instructions on
   providing continuous builds rather than using a "Custom Build".
9. Use the "ADD" button to add the job to ClusterFuzz.

[these]: {{ site.baseurl }}/production-setup/setting-up-fuzzing-job/

### Enabling corpus pruning
It is important that you enable [corpus pruning] to run once a day to prevent
uncontrolled corpus growth. This **must** be done by setting `CORPUS_PRUNE =
True` in the **"Environment String"** for your libFuzzer ASan job.

## Checking results
You can observe ClusterFuzz fuzzing your build by looking at the [bot logs]. Any
bugs it finds can be found on the *Testcases* page. If you are running
ClusterFuzz in production (ie: not locally), you can also view [crash stats] and
[fuzzer stats] (one generally needs to wait a day to view fuzzer stats).

## Seed corpus
You can optionally upload a zip file in your build containing sample inputs for
ClusterFuzz to give to your fuzzer. We call this a seed corpus. For a given fuzz
target, ClusterFuzz will use a file as a seed corpus if:

* It is in the same directory in the build as the fuzz target.
* It has the same name as the fuzz target (not including `.exe` extension)
  followed by `_seed_corpus.zip` (i.e. `<fuzz_target>_seed_corpus.zip` for
  `<fuzz_target>`).

We recommend zipping directories of interesting inputs at build time to create a
seed corpus.

## Dictionaries
ClusterFuzz supports using [libFuzzer/AFL Dictionaries]. A dictionary is a list
of tokens that AFL or libFuzzer can insert during fuzzing. For a given fuzz
target, ClusterFuzz will use a file as a dictionary if:

* It is in the same directory in the build as the fuzz target.
* It has the same name as the fuzz target (not including `.exe` extension)
  followed by `.dict` (i.e. `<fuzz_target>.dict` for `<fuzz_target>`).

[libFuzzer/AFL Dictionaries]: https://llvm.org/docs/LibFuzzer.html#dictionaries

## AFL limitations
Though ClusterFuzz supports fuzzing with AFL, it doesn't support using it for
[corpus pruning] and [crash minimization]. Therefore, if you use AFL, you should
also use libFuzzer which supports these tasks.

[AFL++]: https://github.com/AFLplusplus/AFLplusplus
[AddressSanitizer]: https://clang.llvm.org/docs/AddressSanitizer.html
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
