---
layout: default
title: Architecture
permalink: /architecture/
nav_order: 1
parent: ClusterFuzz
---

# Architecture
![overview]({{ site.baseurl }}/images/overview.png)

ClusterFuzz provides an automated end-to-end infrastructure for finding and
triaging crashes, minimizing reproducers, [bisecting], and verification of fixes.

- TOC
{:toc}

---

## Supported platforms
ClusterFuzz is written in Python and Go. It runs on **Linux**, **macOS**, and **Windows**.

## Requirements
It runs on the [Google Cloud Platform](https://cloud.google.com/), and depends
on a number of services:
- Compute Engine (Not strictly necessary. Bots can run anywhere).
- App Engine
- Cloud Storage
- Cloud Datastore
- Cloud Pub/Sub
- BigQuery
- Stackdriver Logging and Monitoring

**Note**: The only bug tracker supported now is the Chromium hosted
[Monorail](https://opensource.google.com/projects/monorail). Support for custom
bug trackers will be added in the near future.

### Local instance
It's possible to run ClusterFuzz locally without these dependencies by using
local Google Cloud emulators, but some features which depend on BigQuery and
Stackdriver will be disabled due to lack of emulator support.

## Operation
The two main components of ClusterFuzz are:

- App Engine instance
- A pool of [bots]({{ site.baseurl }}/reference/glossary/#bot)

The App Engine instance provides a web interface to access crashes, stats and
other information. It's also responsible for scheduling regular cron jobs.

Bots are machines which run scheduled tasks. They lease tasks from platform
specific queues. The main tasks that bots run are:
- `fuzz`: Run a fuzzing session.
- `progression`: Check if a testcase still reproduces or if it's fixed.
- `regression`: Calculate the revision range in which a crash was introduced.
- `minimize`: Perform testcase [minimization].
- `corpus_pruning`: Minimize a [corpus]({{ site.baseurl
  }}/reference/glossary/#corpus) to smallest size based on coverage (libFuzzer only).
- `analyze`: Run a manually uploaded testcase against a job to see if it crashes.

### Bots
There are 2 kinds of bots on ClusterFuzz - preemptible and non-preemptible.

Preemptible means that the machine can shutdown at any time. On these machines
we only run `fuzz` task. These machines are often cheaper on cloud providers, so
it's recommended to scale using these machines.

Non-preemptible machines are not expected to shutdown. They are able to run all
tasks (including `fuzz`) and other critical tasks such as `progression` which
must run uninterrupted.

[bisecting]: https://en.wikipedia.org/wiki/Bisection_(software_engineering)
[minimization]: {{ site.baseurl }}/reference/glossary/#minimization
