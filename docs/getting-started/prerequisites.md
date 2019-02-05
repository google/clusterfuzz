---
layout: default
title: Prerequisites
parent: Getting started
nav_order: 1
permalink: /getting-started/prerequisites/
---

# Prerequisites

- TOC
{:toc}

---
## Requirements
Many features of ClusterFuzz depend on [Google Cloud
Platform](https://cloud.google.com) services (see
[this]({{ base.siteurl }}/architecture/#requirements) page for more details).
However, it's possible to run it locally without these dependencies for testing
purposes.

While ClusterFuzz runs on a number of platforms, local development is only
supported on **Linux**.

## Getting the code
```bash
$ git clone https://github.com/google/clusterfuzz
$ cd clusterfuzz
```

## Installing prerequisites

### Google Cloud SDK
Install the Google Cloud SDK by following the instructions
[here](https://cloud.google.com/sdk/).

Once this is done, run:

```bash
$ gcloud auth application-default login
$ gcloud auth login
```

### Python programming language
Install Python 2.7. You can download it
[here](https://www.python.org/downloads/release/python-2715/).

If you already have Python installed, you can verify its version by running `python --version`.
The required version is 2.7.10 or newer.

### Go programming language
Install the Go programming language by following the instructions
[here](https://golang.org/doc/install).


### Other dependencies
We provide a script for installing all other development dependencies on Linux.
Our supported distros include:

- **Ubuntu** (14.04, 16.04, 17.10, 18.04, 18.10)
- **Debian** 8 (jessie) or later

To install the dependencies, run the script:

```bash
$ local/install_deps.bash
```

## Loading virtualenv
Activate the virtualenv created by the `local/install_deps.bash` script. This
loads all the python dependencies in the current environment.

```bash
$ source ENV/bin/activate
```

Verify everything works by running:
```bash
$ python butler.py --help
```
