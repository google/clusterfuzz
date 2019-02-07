---
layout: default
title: Blackbox fuzzing
parent: Setting up fuzzing
nav_order: 2
permalink: /setting-up-fuzzing/blackbox-fuzzing/
---

# Blackbox fuzzing
This page walks you through setting up your first [blackbox fuzzer].

- TOC
{:toc}
---

## Providing builds
In order to begin fuzzing, you need to build your target with a [sanitizer]. The
most commonly used [sanitizer] for fuzzing is
[AddressSanitizer](https://clang.llvm.org/docs/AddressSanitizer.html), which
instruments your code with checks for memory safety issues. Clang is the
supported compiler, but GCC may also work.

This is dependent on the build system of your project. At a very high level,
this will mean adding the `-fsanitize=address` flag to your C/C++ compiler and
linker flags.

## Creating a job type
A [job] type is a specification for how to run a particular target program for
fuzzing. It consists of environment variables values.

The name of the [job] is **important**, and must include either **"asan"**,
**"msan"**, **"ubsan"**, or **"tsan"** in its name depending on which
[sanitizer] you are using. For example, a valid name may be
**"asan_linux_app"**.

A basic job type for a binary called **"app"** might look like:
```
APP_NAME = app
APP_ARGS = --some_interesting_option --some_very_important_option
REQUIRED_APP_ARGS = --some_very_important_option
CUSTOM_BINARY = True
TEST_TIMEOUT = 30
```

Breaking this down,
1. `APP_NAME` denotes the name of the target program.
2. `APP_ARGS` are arguments to be passed to the target application.
   This variable should include both optional and required arguments you want to
   pass.
3. `REQUIRED_APP_ARGS` are arguments that must be passed to the target
   application. These arguments will be always used, while the others specified
   in APP_ARGS and not specified here can be removed by ClusterFuzz during
   testcase minimization if they aren't needed to reproduce a crash.
4. `CUSTOM_BINARY` indicates whether or not to use a user uploaded archive,
   rather than pulling from a GCS bucket.
5. `TEST_TIMEOUT` is the maximum timeout in seconds per individual testcase.

To create a job:
1. Navigate to the *Jobs* page.
2. Go to the "ADD NEW JOB" form.
3. Fill out the "Name" and "Platform".
4. Select your build (your zip containing the fuzz target binary) to upload as a
  "Custom Build".
5. Use the "ADD" button to add the job to ClusterFuzz.

## Uploading a fuzzer
A [blackbox fuzzer] on ClusterFuzz is a program which accepts a corpus as
input, and outputs mutated or generated testcases to an output directory. This
program must take the following named arguments:

1. `--input_dir <directory>`. This is the input directory which contains the
   corpus for the given fuzzer.
2. `--output_dir <directory>`. This is the output directory which the fuzzer
   should write to.
3. `--no_of_files <n>`. This is the number of testcases which the fuzzer should
   write to the output directory.

The main entry point for this fuzzer should be a filename which starts with
`run`. For example, a fuzzer in Python may be named `run.py`.

To upload this to ClusterFuzz, package this into a zip archive along with its
dependencies and:
1. Navigate to the *Fuzzers* page.
2. Click the "CREATE NEW" button.
3. Fill out the "Name" of the fuzzer.
4. Select the fuzzer archive for upload.
5. Click "Select/modify jobs".
6. Mark the job(s) created above.
7. Click "SUBMIT".

## Checking results
Give the bots some time to start running your uploaded fuzzers. You can check
which bots are running your fuzzers by checking the *Bots* page. Once a bot has
finished running your fuzzer, you can see a sample console output from the run
and a sample testcase by visiting the *Fuzzers* page (see the second column).
You may check [bot logs] as well.

[blackbox fuzzer]: {{ site.baseurl }}/reference/coverage-guided-vs-blackbox/#blackbox-fuzzing
[fuzzer]: {{ site.baseurl }}/reference/glossary/#fuzzer
[job]: {{ site.baseurl }}/reference/glossary/#job-type
[sanitizer]: {{ site.baseurl }}/reference/glossary/#sanitizer
[bot logs]: {{ site.baseurl }}/getting-started/local-instance/#viewing-logs
