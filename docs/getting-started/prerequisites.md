---
layout: default
title: Prerequisites
parent: Getting started
nav_order: 1
permalink: /getting-started/prerequisites/
---

# Prerequisites
{: .no_toc}

This page explains how to set up your environment for using ClusterFuzz.

- TOC
{:toc}

---
## Requirements
Many features of ClusterFuzz depend on [Google Cloud
Platform](https://cloud.google.com) services, but it's possible to run it locally without these dependencies for testing purposes. See the [Architecture page]({{ site.baseurl }}/architecture/#requirements) for more details.

**Note:** Local development is only supported on **Linux** platform.

## Getting the code

Clone the ClusterFuzz repository to your machine by running the following command:

```bash
git clone https://github.com/google/clusterfuzz
cd clusterfuzz
git pull
```

We recommend that you use the [latest release
version](https://github.com/google/clusterfuzz/releases/latest) of our code
(rather than master branch) for stability reasons. You can check out a
particular release using:

```bash
git checkout tags/vX.Y.Z
```
where X.Y.Z is the release version (for example, 1.0.1). 

## Installing prerequisites

### Google Cloud SDK
Install the Google Cloud SDK by following the [online
instructions](https://cloud.google.com/sdk/).

### Log in to your Google Cloud account
**Note:** This is **not** necessary if you're [running ClusterFuzz locally].

If you're planning to [set up ClusterFuzz in production], you should
authenticate your account with the `gcloud` tool:

```bash
gcloud auth application-default login
gcloud auth login
```

[set up ClusterFuzz in production]: {{ "/production-setup/" | relative_url }}
[running ClusterFuzz locally]: {{ "/getting-started/local-instance/" | relative_url }}

### Python programming language
[Download Python 3.7](https://www.python.org/downloads/release/python-377/),
then install it. If you have Python installed already, you can verify its
version by running `python --version`.

We recommend building using python source from the official repo, as it installs
the needed python headers and pip. Otherwise, make sure to explicitly install
them.

### Go programming language
[Install the Go programming language](https://golang.org/doc/install).

### Other dependencies
We provide a script for installing all other development dependencies on Linux
and macOS.

Our supported systems include:

- **Ubuntu** (14.04, 16.04, 17.10, 18.04, 18.10)
- **Debian** 8 (jessie) or later
- Recent versions of **macOS** with [homebrew] (experimental)

To install the dependencies, run the script:
```bash
local/install_deps.bash
```

[homebrew]: https://brew.sh/

## Loading pipenv
After you run the `local/install_deps.bash` script, activate pipenv by running the following command:

```bash
pipenv shell
```
This loads all the Python dependencies in the current environment.

You can verify that everything works by running:
```bash
python butler.py --help
```
