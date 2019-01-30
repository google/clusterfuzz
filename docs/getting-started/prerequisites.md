---
layout: default
title: Prerequisites
parent: Getting started
nav_order: 1
permalink: /getting-started/prerequisites/
---

- TOC
{:toc}

---
## Requirements
ClusterFuzz is written in Python 2.7 and Go.

Many features of ClusterFuzz depend on the [Google Cloud
Platform](https://cloud.google.com/). However, it's possible to run it locally
without these dependencies for testing purposes.

### Supported platforms for fuzzing
- Linux
- Windows
- macOS

Local development is only supported on Linux.

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

### Go programming language

Install the Go programming language by following the instructions
[here](https://golang.org/doc/install).


### Other dependencies
We provide a script for installing all other development dependencies on Linux.
Our supported distros include:

- **Ubuntu** (14.04, 16.04, 17.10, 18.04, 18.10)
- **Debian** 8 (jessie) or later

```bash
$ local/install_deps.bash
```

## Loading virtualenv
Activate the virtualenv created by the `install_deps.bash` script. This loads all the python
dependencies in the current environment.

```bash
$ source ENV/bin/activate
```

Verify everything works by running:
```bash
$ python butler.py --help
```
