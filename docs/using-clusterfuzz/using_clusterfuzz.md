---
layout: default
title: Using ClusterFuzz
has_children: true
nav_order: 5
permalink: /using-clusterfuzz/
---

These documents walk you through some key features of ClusterFuzz and common
workflows.

For doing generic project setup using cron you can

- write a projects.json file as a source for project setup
- make built type configurable
- support custom build path template from project info using 'build_path' key.
- make srcmap setup optional
- add MockConfig for making it easier for mock out local config.

Config.yaml stores values for defining deployment crons.ymals.

