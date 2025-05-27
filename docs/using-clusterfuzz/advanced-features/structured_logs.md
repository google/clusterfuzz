---
layout: default
title: Structured Logs
parent: Advanced features
grand_parent: Using ClusterFuzz
permalink: /using-clusterfuzz/advanced/structured-logs/
nav_order: 3
---

# Structured Logs

This document describes the structured logging technique implemented in ClusterFuzz to increase observability, and the fields available in each execution context.

- TOC
{:toc}

---

## Structured Logging in ClusterFuzz

A set of consistent structured metadata is added to ClusterFuzz log entries, enabling better filtering and faster indexed queries for tracing and troubleshooting.

The fields are described in the following section. Notice that they are categorized by context, but most logs will belong to more than one context depending on the location they are called. For instance, all entries should contain the common context; logs called while running a task also contain the task context; logs called during a testcase-related execution append the testcase context; and so on.

In addition, code is instrumented with these contexts in the top-level and propagates them throughout the call stack to allow tracing the execution steps using the structured labels (e.g., task id).

## Structured Fields by Context

* [Common Context](https://github.com/google/clusterfuzz/blob/master/src/clusterfuzz/_internal/metrics/logs.py#L663):
  * `clusterfuzz_version`: source code commit hash that produced the running artifact (from github.com/google/clusterfuzz).
  * `clusterfuzz_config_version`: config code commit hash that produced the running artifact (from go/clusterfuzz-config).
  * `instance_id`: identifier for the instance where the bot is running (can be a batch instance, a GCE VM, a k8s pod, a self-hosted instance, or an appengine instance),
  * `operating_system`: name of the operating system.
  * `os_version`: version of the operating system.

* [Task context](https://github.com/google/clusterfuzz/blob/master/src/clusterfuzz/_internal/metrics/logs.py#L914):
  * `task_id`: ID assigned to a task execution (either generated artificially or actually corresponding to the complete utask execution).
  * `task_name`:  Task name (analyze, fuzz, corpus_pruning, etc).
  * `task_argument`:  Argument passed to the task (distinct for each task type).
  * `task_job_name`: Job type associated with the task execution.
  * `stage`: For untrusted tasks, this is the task stage, i.e., preprocess, main or postprocess. (for trusted tasks, it is set to n/a).
* [Testcase-related context](https://github.com/google/clusterfuzz/blob/master/src/clusterfuzz/_internal/metrics/logs.py#L954):
  * `testcase_id`: testcase ID/key.
  * `group_id`: group ID that the testcase belongs to (zero if not grouped).
* [Fuzzer context](https://github.com/google/clusterfuzz/blob/master/src/clusterfuzz/_internal/metrics/logs.py#L931):
  * `fuzz_target`: fuzz target binary name.
  * `fuzzer`: fuzz engine name.
  * `job`: job type associated with the testcase.

  *Note: for testcase-based tasks, these fields are retrieved from the testcase metadata itself. For fuzz task and corpus pruning, which operate on top of these fields, they are retrieved from the task arguments (for fuzz task, the fuzz target may be updated if one is picked during preprocess).*
* [Cronjob context](https://github.com/google/clusterfuzz/blob/master/src/clusterfuzz/_internal/metrics/logs.py#L993):
  * `task_id`: ID generated artificially for the cronjob execution.
  * `task_name`: name of the cronjob module.

* [Grouper context](https://github.com/google/clusterfuzz/blob/master/src/clusterfuzz/_internal/metrics/logs.py#L1004):
  * `testcase_id`: testcase ID/key.
  * `group_id`: group ID that the testcase belongs to (zero if not grouped).

  *Note: this is a variation of the testcase-related context, however log entries are duplicated for the pair of testcases being grouped.*

## How to query in GCP
For Google Cloud Logging, all fields described are available under:
```py
jsonPayload.extras.<field_name>
```
*Note: for python standard logging, these fields are added to the extras argument.*

Queries can be done using the GCP Logging explorer and the query language available. For instance, querying for logs from a specific task and specific job:

```
jsonPayload.extras.task_name = "minimize"
jsonPayload.extras.task_job_name = "linux_asan_jsc"
```
Or querying for the lifecycle of a certain testcase:

```
jsonPayload.extras.testcase_id="1234567"
```

Or even querying for any logs that contain a fuzz target for a certain source revision:

```
jsonPayload.extras.clusterfuzz_version="b4de7f"
jsonPayload.extras.fuzz_target:*
```
