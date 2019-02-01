---
layout: default
title: UI overview
has_children: false
parent: Using ClusterFuzz
nav_order: 1
permalink: /using-clusterfuzz/ui-overview/
---

# UI overview
This page gives a brief overview of ClusterFuzz web interface pages. We do not
document every page in detail, as the interface is supposed to be intuitive and
most page elements have tooltips.

Once you successfully deployed the server (either locally or in production),
you should be able to access the following pages.

- TOC
{:toc}
---

## Testcases
This is the default main page. The Testcases page provides information about the
issues that were detected by fuzzers running on ClusterFuzz. The page includes
various filters as well as a search functionality.

## Fuzzer Statistics
The Fuzzer Statistics page provides a variety of metrics about performance of
the fuzzers. For in-process fuzz targets, the page also provides performance
reports and improvement recommendations, as well as links to the metadata
associated with a particular fuzz target.

## Crash Statistics
This page provides various statistics about the crashes that were detected by
ClusterFuzz. These statistics include frequency of crashes, platforms affected,
trends over time.

## Upload Testcase
This page provides a convenient way to upload a single testcase to be tested
with a specific target. The most common use case for this is to test a bug that
was reported by an external researcher or found by some other system.

## Jobs
This page provides a way to create new or modify existing job configurations.

## Configuration
This is an administrative page with a variety of settings including ClusterFuzz
access control, credentials, etc. This page is available to admin users only.
