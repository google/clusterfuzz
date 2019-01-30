---
layout: default
title: Access control
parent: Advanced features
grand_parent: Using ClusterFuzz
permalink: /using-clusterfuzz/advanced/access-control/
nav_order: 1
---

# Access control

This page explains how you can restrict access to various parts of the ClusterFuzz web interface.
This is controlled by defining the user(s) as part of one of the following groups.

- TOC
{:toc}
---

## Regular users

Regular users are usually the developers in your project, who triage and fix bugs. They
can access most pages of the ClusterFuzz web interface, but with restricted permissions.
This includes:
* Testcases page (excludes security vulnerabilities)
* Testcase report page (excludes security vulnerabilities)
* Crash statistics page (excludes security vulnerabilities)
* Crashes by range page (excludes security vulnerabilities)
* Fuzzer statistics page
* Upload testcase page
* Fuzzers page (view only)
* Corpora page (view only)
* Bots page

They do not have access to the following pages:
* Job page
* Configuration page

## Privileged users

Privileged users are usually a restricted set of people that define the inner workings
of the ClusterFuzz sub-system. These users can access all pages that a regular user can
and additionally:
* Have access to security bugs (Security: "YES" in report).
* Upload new fuzzers on Fuzzers page.
* Upload new corpora on Corpora page.
* Create new jobs on Jobs page.

Privileged users are defined by the [Administrators](#administrators) on the Configuration page.

## Administrators

An [administrator](https://cloud.google.com/appengine/docs/standard/python/users/adminusers)
has access to all parts of the ClusterFuzz web interface.
This includes:
* Access to the Configuration page.
  * Can define new privileged users using:
    * In "Privileged Users" field as `user@example.com`.
    * In "User permissions" section.
* Everything that a privileged or regular can do (see above).
