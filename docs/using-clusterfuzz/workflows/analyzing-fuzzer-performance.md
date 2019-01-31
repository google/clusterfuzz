---
layout: default
title: Analyzing fuzzer performance
permalink: /using-clusterfuzz/workflows/analyzing-fuzzing-performance/
nav_order: 3
parent: Workflows
grand_parent: Using ClusterFuzz
---

# Analyzing fuzzer performance

ClusterFuzz automates fuzzing as much as possible, but it's responsibility of
the users to write and maintain fuzzers in order to find security
vulnerabilities and other software bugs. This page gives some recommendations on
how to analyze performance of the fuzzers running on ClusterFuzz infrastructure.

- TOC
{:toc}

## When to analyze fuzzer performance

It's important to regularly monitor the performance of fuzzers, especially after
a new fuzzer is created. If a fuzzer keeps finding new issues, it might be more
important to prioritize fixing those issues first, but if a fuzzer has not
reported anything for a while, that is a strong signal that you need to check
its performance.

## Fuzzer stats

TODO: mention that stats are delayed by up to 24 hours

## Performance report

TODO: detects typical issues, prioritizes them, shows log examples, fix
recommendations

## Fuzzer logs

TODO: go to the logs bucket when things are not clear or you need more detail
