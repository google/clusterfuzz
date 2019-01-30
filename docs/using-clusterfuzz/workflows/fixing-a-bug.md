---
layout: default
title: Fixing a bug
permalink: /using-clusterfuzz/workflows/fixing-a-bug/
nav_order: 2
parent: Workflows
grand_parent: Using ClusterFuzz
---

# Overview

As important as it is to find bugs, that wouldn't be useful if it wasn't also
easy for developers to fix them. ClusterFuzz provides the necessary information
to reproduce issues, then confirms that fixes are correct.

This document focuses on the testcase details page, since it contains the
majority of the relevant information for fixing a bug.

- TOC
{:toc}

---

## Reproducing an issue

The Overview section of the report contains links to download the testcase and
build that triggered the issue.

At the top of the crash stacktrace, which may need to be expanded to see the
full report, ClusterFuzz shows the command line and any important environment
variables that were set when the crash initially occurred. The environment
variables might or might not be required to reproduce the crash.

## Fixed testing

ClusterFuzz continues to run testcases daily until it detects them as fixed.
When an issue is detected as fixed, the Fixed status of the bug will be updated
to "Yes" and the **Fixed Revision Range** section will link to a range of commits
containing the fix.

If the testcase has been associated with a bug, ClusterFuzz will also leave a
comment and change the issue status to indicate that it has verified the fix is
correct.

## Unreproducible crashes

ClusterFuzz does not consider unreproducible testcases, i.e. testcases that cannot
consistently reproduce the crash, as important. However, if an unreproducible
crash is happening frequently and is one of the top crashes, it does consider
them important and will file a tracking bug for it.

When ClusterFuzz finds a reproducible testcase for the same crash signature,
it creates a new report with this testcase and deletes the older report with the
unreproducible testcase. So, it is recommended to wait a few days to see if a
reproducible testcase can be found. If not, you can try running the unreproducible
testcase multiple times to see if you can get a consistent crash locally.
If that fails, we recommend pushing a speculative fix and then letting ClusterFuzz
verify if the crash stops happening over the next couple of days.

If a tracking bug is filed, ClusterFuzz will automatically look at crash statistics
every day and close the bug as Verified if that crash stops happening frequently
(i.e. no crash seen in a period of *2 weeks*). If a bug is not filed,
unreproducible testcases get automatically closed if they are not seen for a *week*.
