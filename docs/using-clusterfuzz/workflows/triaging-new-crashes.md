---
layout: default
title: Triaging new crashes
permalink: /using-clusterfuzz/workflows/triaging-new-crashes/
nav_order: 1
parent: Workflows
grand_parent: Using ClusterFuzz
---

# Overview

ClusterFuzz was built to remove as much manual work from fuzzing as possible.
Bug triage, in particular, has historically been a difficult and manual process.
This document describes some common workflows where ClusterFuzz may save time
with triage.

- TOC
{:toc}

---

## Filtering test cases

Some test cases are more interesting than others. In order to help you find the
interesting ones, the Testcases page provides filters and search functionality.
Depending on what you're interested in, for example bugs identified as security
vulnerabilities, you can filter or search for only those bugs.

By default, only privileged users may see issues with security implications.
This allows you to grant access to some users without leaking potentially
sensitive information. See [Access control] for giving full or more granular access.

## Finding a culprit

Once you've found an interesting test case, ClusterFuzz provides a report to aid
in root cause analysis and help find which changelist may have introduced the
bug. Especially for larger projects, this can save a great deal of manual work.

### Regression revision range

Though only available for reproducible crashes, the regression range is often
the most useful information for triage. It shows the range of commits in which
the issue was introduced.

The more frequently you archive builds, the narrower these ranges will be. If
you archive every revision of your build, ClusterFuzz can point to the exact
commit which introduced the bug.

### Crash stacktrace

Especially when using Sanitizers, the stack traces associated with a bug contain
relevant information that can help you determine the cause of the crash. This is
more of an art than an exact science, and there is no one process to follow to
find a culprit changelist using this information.

That said, it is often helpful to look for changes in the regression range, if
available, that modify the same files seen in the stack traces. When that isn't
an option, "git blame" or similar tools may be helpful to find a developer more
familiar with the code in question who may be a good first point of contact.

### Crash statistics

ClusterFuzz also provides statistics on how often issues occur, and under what
conditions. For example, ClusterFuzz tracks which platform issues reproduce on
and which fuzzers found them.

These sometimes provide useful insights for bugs where other methods fail. For
example, if nothing directly modifies a file in a crash stack but you find that
it only reproduces on a specific platform, a large behavior change on that
platform may be the culprit. For a non-reproducible crash, it may be useful to
know that it started occurring 3 days ago, the same time as a risky change.

[Access control]: {{ site.baseurl }}/advanced/access-control
