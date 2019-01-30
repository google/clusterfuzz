---
layout: default
title: Blackbox fuzzing
parent: Setting up fuzzing
nav_order: 2
permalink: /setting-up-fuzzing/blackbox-fuzzing/
---

# Blackbox fuzzing

This page walks you through setting up your first [blackbox fuzzer]. A blackbox
fuzzer generates static testcases, that are later run against a target program
one at a time. Blackbox fuzzers are useful for cases when your target expects structured
grammar input (e.g. HTML, Javascript, etc), so the fuzzer can create inputs that obey
the parsing and lexical rules of that particular grammar.

---
- TOC
{:toc}
---

## Providing builds
In order to begin fuzzing, you need to build your target with a [sanitizer]. The
most commonly used [sanitizer] for fuzzing is [Address
Sanitizer](https://clang.llvm.org/docs/AddressSanitizer.html), which instruments
your code with checks for memory safety issues.

This is dependent on the build system of your project. At a very high level, this
will mean adding the `-fsanitize=address` flag to your C/C++ compiler flags.

## Creating a job type
A [job] type is a specification for how to run a particular target program for
fuzzing. It consists of environment variables values.

For example, a basic job type for a binary called `app` might look like:

```
APP_NAME = app
APP_ARGS = -args -to -pass -to -app
CUSTOM_BINARY = True
TEST_TIMEOUT = 30
```

Breaking this down,
1. `APP_NAME` denotes the name of the binary.
2. `APP_ARGS` are arguments which should be passed to the binary.
3. `CUSTOM_BINARY` indicates whether or not to use a user uploaded archive,
   rather than pulling from a GCS bucket.
4. `TEST_TIMEOUT` is the maximum timeout per individual testcase.

### Job name
The name of the [job] is **important**, and must include either `asan`, `msan`,
`ubsan`, or `tsan` in its name depending on which [sanitizer] you are using.

For example, the job above may be named `asan_app`.

## Uploading a fuzzer
A [blackbox fuzzer] on ClusterFuzz is a program which accepts a corpus as
input, and outputs mutated or generated testcases to an output directory. This
program must take the following named arguments:

1. `--input_dir <directory>`. This is the input directory which contains the
   corpus for the given fuzzer.
2. `--output_dir <directory>`. This is the output directory which the fuzzer
   should write to.
3. `--no_of_files <n>`. This is the number of testcases which the fuzzer should
   output to the output directory.

The main entrypoint for this fuzzer should be a filename which starts with
`run`. For example, a fuzzer in Python may be named `run.py`.

To upload this to ClusterFuzz, package this into a zip archive along with its
dependencies and follow the upload steps on the *Fuzzers* page. Remember to
associate this fuzzer with the job name(s) created above, which is a necessary
step to actually start running this fuzzer against those job(s).

## Checking results
Give the bots some time to start running your uploaded fuzzers. You can check
which bots are running your fuzzers by checking the *Bots* page. Once a bot
has finished running your fuzzer, you can see a sample console output from the
run and a sample testcase by visiting the Fuzzers page (see second column).

[blackbox fuzzer]: https://en.wikipedia.org/wiki/Fuzzing#Aware_of_program_structure
[fuzzer]: {{ site.baseurl }}/reference/glossary/#fuzzer
[job]: {{ site.baseurl }}/reference/glossary/#job
[sanitizer]: {{ site.baseurl }}/reference/glossary/#sanitizer
