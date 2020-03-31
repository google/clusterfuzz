---
layout: default
title: Running unit tests
parent: Contributing code
nav_order: 2
permalink: /contributing-code/running-unit-tests/
---

# Running unit tests

- TOC
{:toc}
---

## Test core changes

You can run unit tests for the core functionality using:

### Python code

```bash
python butler.py py_unittest -t core
```

Optional switches you can use:
* `-m`: Execute tests in-parallel (recommended).
* `-v`: Run tests in verbose mode (with INFO log level).
* `-u`: Show output from `print` (useful for debugging).
* `-p <test_name/test_prefix_with_wildcards>`: Execute a particular test or set of tests matching
a particular prefix. E.g. `-p libfuzzer_*` will execute all libFuzzer tests.

## Test App Engine changes

Most of the App Engine code is written in Python. You can run unit tests for the App Engine
changes (e.g. UI, cron) using:

```bash
python butler.py py_unittest -t appengine
```

You can use any switch as defined above in the python core changes section.
