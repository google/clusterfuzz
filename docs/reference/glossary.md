---
layout: default
title: Glossary
parent: Reference
nav_order: 1
permalink: /reference/glossary/
---

# Glossary
This page provides a glossary of what certain terms mean in the context of
ClusterFuzz.

- TOC
{:toc}
---

## Bot
A machine which runs ClusterFuzz [tasks](#task).

## Corpus
A set of inputs for a [fuzz target](#fuzz-target). In most contexts, it refers
to a set of minimal test inputs that generate maximal code coverage.

## Corpus pruning
A task which takes a [corpus](#corpus) and removes unnecessary inputs while
maintaining the same code coverage.

## Crash state
A signature that we generate from the crash stacktrace for deduplication
purposes.

## Crash type
The type of a crash. ClusterFuzz uses this to determine the severity.

For security vulnerabilities this may be (but not limited to):
- Bad-cast
- Heap-buffer-overflow
- Heap-double-free
- Heap-use-after-free
- Stack-buffer-overflow
- Stack-use-after-return
- Use-after-poison

Other crash types include:
- Null-dereference
- Timeout
- Out-of-memory
- Stack-overflow
- ASSERT

## Fuzz target
A function or program that accepts an array of bytes and does something
interesting with these bytes using the API under test. See the
[libFuzzer documentation](https://llvm.org/docs/LibFuzzer.html#fuzz-target)
for a more detailed explanation. A fuzz target is typically given the array of
bytes by [libFuzzer] or [AFL] for coverage guided fuzzing.

## Fuzzer
A program which generates/mutates inputs of a certain format for testing a
target program. For example, this may be a program which generates valid
JavaScript testcases for fuzzing an JavaScript engine such as V8.

## Fuzzing engine
A tool used for performing coverage guided fuzzing. The fuzzing engine typically
mutates inputs, gets coverage information, and adds inputs to the corpus based
on new coverage information. ClusterFuzz supports the fuzzing engines
[libFuzzer] and [AFL]. See our guide on setting up
[libFuzzer and AFL]({{site.baseurl }}/setting-up-fuzzing/libfuzzer-and-afl/)
for more details.

## Job type
A specification for how to run a particular target program for fuzzing, and
where the builds are located. Consists of environment variable values.

## Minimization
A [task](#task) that tries to minimize a [testcase](#testcase) to its smallest
possible size, such that it still triggers the same underlying bug on the target
program.

## Reliability of reproduction
A crash is reliably reproducible if the target program consistently crashes with
the same [crash state](#crash-state) for the given input.

## Regression range
A range of commits in which the bug was originally introduced. It is of the form
`x:y` where:
* x is the start [revision](#revision) (inclusive).
* y is the end [revision](#revision) (exclusive).

## Revision
A number (not a git hash) that can be used to identify a particular build. This
number should increment with every source code revision. For SVN, this can be
just the SVN source code revision. For Git, you need to create an equivalent
mapping from numbers to git hashes. The mapping number can be an id that starts
at `1` and is incremented or can be a date format (e.g. `20190110`).

## Sanitizer
A [dynamic testing](https://en.wikipedia.org/wiki/Dynamic_testing) tool that
uses compile-time instrumentation to detect bugs during program execution.
Examples:
* [ASan] (aka AddressSanitizer)
* [LSan](https://clang.llvm.org/docs/LeakSanitizer.html) (aka LeakSanitizer)
* [MSan](https://clang.llvm.org/docs/MemorySanitizer.html) (aka MemorySanitizer)
* [UBSan](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html)
  (aka UndefinedBehaviorSanitizer)
* [TSan](https://clang.llvm.org/docs/ThreadSanitizer.html) (aka ThreadSanitizer)

Sanitizers are best supported by the [Clang] compiler. [ASan], or
AddressSanitizer, is usually the most important sanitizer as it reveals the most
memory corruption bugs.

## Task
A unit of work to be performed by a [bot](#bot), such as a fuzzing session or
minimizing a testcase.

## Testcase
An input for the target program that causes a crash or bug. On a testcase
details page, you can download a "Minimized Testcase" or "Unminimized Testcase",
these refer to the input that needs to be passed to the target program.

[ASan]: https://clang.llvm.org/docs/AddressSanitizer.html
[libFuzzer]: https://llvm.org/docs/LibFuzzer.html
[AFL]: http://lcamtuf.coredump.cx/afl/
[Clang]: https://clang.llvm.org/
