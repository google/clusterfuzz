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
A set of test inputs. In most contexts, it refers to a set of minimal test
inputs that generate maximal code coverage.

## Fuzz target
A function/program that accepts an array of bytes and does something interesting
with these bytes using the API under test. See
[here](https://llvm.org/docs/LibFuzzer.html#fuzz-target). This is used by
[libFuzzer] and [AFL] for coverage guided fuzzing.

## Fuzzer
A program which generates/mutates inputs of a certain format for testing a
target program. For example, this may be a program which generates valid
JavaScript testcases for fuzzing an JavaScript engine such as V8.

## Fuzzing engine
An engine for performing coverage guided fuzzing. The two supported engines are
[libFuzzer] and [AFL].

## Job type
A specification for how to run a particular target program for fuzzing, and
where the builds are located. Consists of environment variable values.

## Minimization
A [task](#task) that tries to minimize a [testcase](#testcase) to its smallest
possible size, such that it still triggers the same underlying bug on the target
program.

## Regression range
A range of commits in which the bug was originally introduced. It is of the form `x:y` where:
* x is the start [revision](#revision) (inclusive).
* y is the end [revision](#revision) (exclusive).

## Revision
A number (not a git hash) that can be used to identify a particular build. This number
should increment with every source code revision. For SVN, this can be just the svn source
code revision. For GIT, you need to create an equivalent git hash to a number mapping. It
can start from a particular number (e.g. `1`) or use date format as number (e.g. `20190110`).

## Sanitizer
A [dynamic testing](https://en.wikipedia.org/wiki/Dynamic_testing) tool that can detect bugs
during program execution.
Examples:
[ASan](http://clang.llvm.org/docs/AddressSanitizer.html),
[DFSan](http://clang.llvm.org/docs/DataFlowSanitizer.html),
[LSan](http://clang.llvm.org/docs/LeakSanitizer.html),
[MSan](http://clang.llvm.org/docs/MemorySanitizer.html),
[TSan](http://clang.llvm.org/docs/ThreadSanitizer.html),
[UBSan](http://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html).

[libFuzzer]: https://llvm.org/docs/LibFuzzer.html
[AFL]: http://lcamtuf.coredump.cx/afl/

## Task
A unit of work to be performed by a [bot](#bot), such as a fuzzing session or minimizing
a testcase.

## Testcase
An input for the target program with an associated behavior caused by that
input. In ClusterFuzz UI, a testcase usually means a crash / bug / issue. On a
testcase details page, you can download a "Minimized Testcase" or "Unminimized
Testcase", these refer to the input that needs to be passed to the target
program.
