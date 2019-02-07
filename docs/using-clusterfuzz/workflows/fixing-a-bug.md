---
layout: default
title: Fixing a bug
permalink: /using-clusterfuzz/workflows/fixing-a-bug/
nav_order: 2
parent: Workflows
grand_parent: Using ClusterFuzz
---

# Fixing a bug

Finding bugs is primarily useful if it can help get bugs fixed. To make fixing
bugs easier, ClusterFuzz provides the necessary information to reproduce issues,
and confirms that fixes are correct.

This document focuses on the testcase details page, since it contains the
majority of the relevant information for fixing a bug.

- TOC
{:toc}

---

## Reproducing an issue

The *Overview* section of the report contains links to download the testcase and
build that triggered the issue.

At the top of the crash stacktrace (which may need to be expanded), ClusterFuzz
shows the command line and any important environment variables that were set
when the crash initially occurred. The environment variables may be be required
to reproduce the crash.

## Fixed testing

Once a day, ClusterFuzz re-runs testcases against the latest build until it
detects them as fixed. When an issue is detected as fixed, the Fixed status of
the bug will be updated to "Yes" and the *Fixed Revision Range* section will
link to a range of commits containing the fix.

If the testcase has been associated with a bug, ClusterFuzz will also leave a
comment and change the issue status to indicate that it has verified the fix is
correct.

## Unreliable crashes

ClusterFuzz does not consider testcases that do not [reliably reproduce] as
important. However, if a [crash state] is seen very frequently despite not
having a single reliable testcase for it, ClusterFuzz will file a bug for it.

When ClusterFuzz finds a reliably reproducible testcase for the same [crash
state], it creates a new report and deletes the older report with the
unreliable testcase. It is recommended in such cases to wait a few days to see if a
reproducible testcase can be found.

If not, you can try running the testcase multiple times to see if you can get a
consistent crash locally. If that fails, we recommend pushing a speculative fix
based on the crash stacktrace and then letting ClusterFuzz verify if the crash
stops happening over the next couple of days.

If a tracking bug is filed, ClusterFuzz will automatically look at [crash statistics]
every day and close the bug as Verified if that crash stops happening frequently
(i.e. no crash seen in a period of *2 weeks*). If a bug is not filed,
unreproducible testcases get automatically closed if they are not seen for a *week*.

[crash statistics]: {{ site.baseurl }}/using-clusterfuzz/ui-overview/#crash-statistics
[crash state]: {{ site.baseurl }}/reference/glossary/#crash-state
[reliably reproduce]: {{ site.baseurl }}/reference/glossary/#reliability-of-reproduction
