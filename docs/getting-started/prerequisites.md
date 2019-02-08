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
[this]({{ site.baseurl }}/architecture/#requirements) page for more details).
However, it's possible to run it locally without these dependencies for testing
purposes.

While ClusterFuzz runs on a number of platforms, local development is only
supported on **Linux** and **macOS**.

## Getting the code
```bash
git clone https://github.com/google/clusterfuzz
cd clusterfuzz
```

## Installing prerequisites

### Google Cloud SDK
Install the Google Cloud SDK by following the instructions
[here](https://cloud.google.com/sdk/).

### (Optional) Log in to your Google Cloud account
This is **not** necessary if you are simply running ClusterFuzz [locally].

If you are planning to set up ClusterFuzz in [production], you should
authenticate your account with the `gcloud` tool:

```bash
gcloud auth application-default login
gcloud auth login
```

[production]: {{ "/production-setup/" | relative_url }}
[locally]: {{ "/getting-started/local-instance/" | relative_url }}

### Python programming language
Install Python 2.7. You can download it
[here](https://www.python.org/downloads/release/python-2715/).

If you already have Python installed, you can verify its version by running `python --version`.
The minimum required version is 2.7.10.

### Go programming language
Install the Go programming language by following the instructions
[here](https://golang.org/doc/install).


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

## Loading virtualenv
Activate the virtualenv created by the `local/install_deps.bash` script. This
loads all the python dependencies in the current environment.

```bash
source ENV/bin/activate
```

Verify everything works by running:
```bash
python butler.py --help
```
