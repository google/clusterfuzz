---
layout: default
title: Getting started
has_children: true
nav_order: 2
permalink: /getting-started/
---

# Getting started
These pages walk you through the process of setting up ClusterFuzz locally for
development and testing purposes.

You should run integrations tests while setting up ClusterFuzz. You can find all tests
in `local/tests/run_all_tests`. You should enable the option of `INTEGRATION=1 $SCRIPT_DIR/run_tests`.

Run the integration tests - `python butler.py integration_tests`.

Mark the testcase as integration because that depends on network resources and/or is slow.
The integration tests should, at least, be run before merging and are counted toward
test coverage. It can be enabled using the env INTEGRATION=1.

