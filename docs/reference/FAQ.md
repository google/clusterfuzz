---
layout: default
title: FAQ
parent: Reference
nav_order: 4
permalink: /reference/faq/
---

- TOC
{:toc}

# What languages does ClusterFuzz support?

ClusterFuzz definitely supports C, C++ when compiled with
[clang](https://clang.llvm.org/). It should also support Rust and it probably
supports other languages that can be compiled with an LLVM-based toolchain (e.g.
Swift).

## Why is an LLVM-based toolchain required?

An LLVM-based toolchain is required (or at least strongly recommended) for two
reasons:
* Because ClusterFuzz relies on LLVM [sanitizers]({{ site.baseurl }}/reference/glossary/#Sanitizer) 
  for detecting and identifying bugs.

* Because use of [libFuzzer and AFL] in ClusterFuzz requires coverage
  instrumentation only LLVM can provide.

## What if I really don't want to use an LLVM-based toolchain?

We strongly recommend using an LLVM-based toolchain. That said, you may be able
to use some parts of ClusterFuzz with [gcc](https://gcc.gnu.org/) or extend
ClusterFuzz to support your use of gcc. However, if you do this, you are in
unexplored territory and we can not support this. Gcc can probably be used for
[blackbox fuzzing]({{ site.baseurl }}/setting-up-fuzzing/blackbox-fuzzing/)
without modifying ClusterFuzz since gcc supports ASan. Using gcc with AFL or
libFuzzer would probably require considerable changes to ClusterFuzz to get
working. In the end, it is probably easier to make whatever changes are needed
to build with clang.

## Why isn't $MY_LANGUAGE Supported?

In theory, ClusterFuzz is language agnostic and can be extended to support
fuzzing code written in any language. In practice though, it is less easy to
find interesting bugs in
[memory safe](https://en.wikipedia.org/wiki/Memory_safety) languages so
ClusterFuzz doesn't have support for fuzzing most of them.

## How can I extend ClusterFuzz to support fuzzing my language

Only experts should consider doing this. The first step is getting ClusterFuzz
to recognize errors thrown by programs written in your language. This should
make blackbox fuzzing possible. If you would like to add coverage-guided fuzzing
support for your language, you need to a launcher like there is for AFL and
libFuzzer that is capable of running fuzzers written in your language.

## Are there plans to support fuzzing in other languages?

The only language we are considering adding support for at this time is
[Go](https://golang.org/).

[SanitizerCoverage]: https://clang.llvm.org/docs/SanitizerCoverage.html
[libFuzzer and AFL]: {{ site.baseurl }}/setting-up-fuzzing/libfuzzer-and-afl/
