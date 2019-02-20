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
[clang](https://clang.llvm.org/). It has also been tested with Rust and may work
with other languages that can be compiled with an LLVM-based toolchain (e.g.
Swift).

## Why is an LLVM-based toolchain needed for full support?

An LLVM-based toolchain is needed for full ClusterFuzz support for two reasons:
* Because ClusterFuzz relies on LLVM [sanitizers]({{ site.baseurl }}/reference/glossary/#Sanitizer) 
  for detecting and identifying bugs.

* Because use of [libFuzzer and AFL] in ClusterFuzz requires coverage
  instrumentation only LLVM can provide.

## What if I really don't want to use an LLVM-based toolchain?

We strongly recommend using an LLVM-based toolchain. That said, you may be able
to use some parts of ClusterFuzz with [GCC](https://gcc.gnu.org/) or extend
ClusterFuzz to support your use of GCC. However, if you do this, you are in
unexplored territory and we can not support this. GCC may work for
[blackbox fuzzing]({{ site.baseurl }}/setting-up-fuzzing/blackbox-fuzzing/)
without modifying ClusterFuzz since GCC supports ASan. Using GCC with AFL or
libFuzzer would probably require considerable changes to ClusterFuzz to get
working. In the end, it is probably easier to make whatever changes are needed
to build with clang.

## Why isn't $MY_LANGUAGE supported?

In theory, ClusterFuzz is language agnostic and can be extended to support
fuzzing code written in any language. In practice though, it is less easy to
find interesting bugs in
[memory safe](https://en.wikipedia.org/wiki/Memory_safety) languages so
ClusterFuzz doesn't have support for fuzzing most of them.

[SanitizerCoverage]: https://clang.llvm.org/docs/SanitizerCoverage.html
[libFuzzer and AFL]: {{ site.baseurl }}/setting-up-fuzzing/libfuzzer-and-afl/
