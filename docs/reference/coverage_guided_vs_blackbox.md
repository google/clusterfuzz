---
layout: default
title: Coverage guided vs blackbox fuzzing
parent: Reference
nav_order: 2
permalink: /reference/coverage-guided-vs-blackbox/
---

# Coverage guided vs blackbox fuzzing
The two types of fuzzing supported on ClusterFuzz are coverage guided fuzzing
(using [libFuzzer] and [AFL]) and blackbox fuzzing.

---

## Coverage guided fuzzing
Coverage guided fuzzing (also known as greybox fuzzing) uses program
instrumentation to trace the code coverage reached by each input fed to a
[fuzz target]. [Fuzzing engines] use this information to make informed decisions
about which inputs to mutate to maximize coverage.

For every target, the fuzzing engine builds a [corpus] of inputs. These grow in
coverage over time as the engine discovers new inputs through mutation.

The fuzzing engines supported on ClusterFuzz are [libFuzzer] (recommended) and [AFL].

### When should I use coverage guided fuzzing?
Coverage guided fuzzing is recommended as it is generally the most effective.
This works best when:
- The target is self-contained.
- The target is deterministic.
- The target can execute dozens or more times per second (ideally hundreds or
  more).

For example, binary format (e.g. image format) parsers are very well suited to
this.

## Blackbox fuzzing
A blackbox fuzzer generates inputs for a target program without knowledge of its
internal behaviour or implementation.

A blackbox fuzzer may generate inputs from scratch, or rely on a static corpus
of valid input files to base mutations on. Unlike coverage guided fuzzing, the
corpus does not grow here.

### When should I use blackbox fuzzing?
Blackbox fuzzing works well when:
- The target is large.
- The target is not deterministic for the same input.
- The target is slow.
- The input format is complicated or highly structured (e.g. a programming
  language such as JavaScript).

For example, a browser DOM fuzzer may generate HTML inputs that are run
against a target such as Chrome, without any coverage feedback to guide its
mutations.

[AFL]: http://lcamtuf.coredump.cx/afl/
[libFuzzer]: https://llvm.org/docs/LibFuzzer.html
[corpus]: {{ site.baseurl }}/reference/glossary/#corpus
[fuzz target]: {{ site.baseurl }}/reference/glossary/#fuzz-target
[Fuzzing engines]: {{ site.baseurl }}/reference/glossary/#fuzzing-engine
