---
layout: default
title: Setting up a fuzzing job
parent: Production setup
permalink: /production-setup/setting-up-fuzzing-job/
nav_order: 3
---

# Setting up a fuzzing job

This page walks you through setting up a fuzzing job in production. That process
repeats the steps described in [setting up fuzzing], but also requires extra
configuration for automated build updates.

- TOC
{:toc}

---

## Prerequisites

To take full advantage of continuous fuzzing, you should set up a
[build pipeline] first. By doing this, ClusterFuzz will automatically find bugs
in your most recent changes, report ranges of commits where regressions are
introduced, and verify fixes.

If you wish to run with a single build while preparing a [build pipeline], you
can follow the [setting up fuzzing] instructions directly.

## Creating a job definition

You can create a job definition on the _Jobs_ page. To understand the process of
job creation, see [setting up fuzzing]. That page explains the difference
between two fuzzing approaches ([coverage guided vs blackbox]) and provides
guidance on how to set up a job for each of those.

## Specifying a continuous build

To allow ClusterFuzz to take advantage of your [build pipeline] you must point
to the [Google Cloud Storage] bucket where your builds are stored in your job
definition's "Environment String".

```
RELEASE_BUILD_BUCKET_PATH = gs://my-bucket/my-build-([0-9]+).zip
CUSTOM_BINARY = False

# These are only needed for blackbox fuzzing.
APP_NAME = myapp
APP_ARGS = -args -to -pass -to -myapp
...
```

The `RELEASE_BUILD_BUCKET_PATH` in the above example is a regular expression
that specifies which bucket to read build archives from. Any files in the bucket
that match the specified expression are treated as potential builds for this
job. In this example, a build at the path `gs://my-bucket/my-build-123.zip`
would be a match, and would be used by this job.

The `([0-9]+)` regex in `RELEASE_BUILD_BUCKET_PATH` is used to compute the
[revision number] for this build. This is used to determine which builds are
newer than others. The build with the highest revision number will always be
selected for fuzzing. ClusterFuzz expects that any build with a greater revision
number than another is the newer build.

**Note**: The parentheses around the revision number regex are required and is
the match group that ClusterFuzz uses to determine which part of the expression
represents the revision number.

For a complete list of options, look at `bot/env.yaml` in the source checkout.

## Advanced options

### Ignoring outdated revisions

In addition to the variables defined above, you may also define the
`MIN_REVISION` variable. This can be useful when you make significant,
non-backwards-compatible changes in your build such that older revisions will
not work properly and need to be discarded.

### Linking to documentation

A job can specify a `HELP_URL` which each test case report for this job will
link to. This allows you to provide instructions to developers on how they
should treat the bugs they are assigned.

### Job definition reference

For a more comprehensive overview of the options, see the [job definition]
reference page.

[Google Cloud Storage]: https://cloud.google.com/storage/
[coverage guided vs blackbox]: {{ site.baseurl }}/reference/coverage-guided-vs-blackbox/
[build pipeline]: {{ site.baseurl }}/production-setup/build-pipeline/
[job definition]: {{ site.baseurl }}/reference/job-definition/
[revision number]: {{ site.baseurl }}/reference/glossary/#revision
[setting up fuzzing]: {{ site.baseurl }}/setting-up-fuzzing/
