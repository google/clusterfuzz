---
layout: default
title: Using ClusterFuzz
has_children: true
nav_order: 5
permalink: /using-clusterfuzz/
---

These documents walk you through some key features of ClusterFuzz and common
workflows.

`FUZZ_TARGET_BUILD_BUCKET_PATH` can be specified in ProjectConfig in `project_setup`
in MockConfig. You should define the buckets if you define `FUZZ_TARGET_BUILD_BUCKET_PATH`
in MockConfig.

The format of `FUZZ_TARGET_BUILD_BUCKET_PATH` is `gs://bucket/subdir/%TARGET%/([0-9]+).zip.`

If the `FUZZ_TARGET_BUILD_BUCKET_PATH` is specified, build_manager will pick a fuzz
target (if it hasn't picked already), and substitute `%TARGET%` with the actual target
name. The only new behavior, as the resulting bucket path can then be passed as a regular setup.

