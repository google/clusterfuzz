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

This step is only necessary on the **macOS** platform. For **Linux** user, Google Cloud SDK
will be installed later by the script under the "[Other dependencies](#other-dependencies)" section.

Install the Google Cloud SDK by following the [online
instructions](https://cloud.google.com/sdk/).

### Python programming language

[Download Python 3.7](https://www.python.org/downloads/release/python-377/), then install it ([see this guide for instructions](https://realpython.com/installing-python/#how-to-build-python-from-source-code)).
If you have Python installed already, you can verify its version by running `python --version`.
You'll want to install Python 3.7 if your local version is different.

We recommend building using python source from the official repo, as it installs
the needed python headers and pip. Otherwise, make sure to explicitly install
the specific version of pip for Python 3.7 (e.g. configuring the build with the
`--with-ensurepip=install` flag).

You shouldn’t need pyenv to manage python versions for ClusterFuzz. Instead,
set the Python version in the pipenv shell.

### Go programming language

[Install the Go programming language](https://golang.org/doc/install).

### Other dependencies

We provide a script for installing all other development dependencies on Linux
and macOS.

Our supported systems include:

- **Ubuntu** (16.04, 17.10, 18.04, 18.10, 20.04)
- **Debian** 8 (jessie) or later
- Recent versions of **macOS** with [homebrew] (experimental)
- Note: Only x86 architectures are currently supported

To install the dependencies, run the script:

```bash
local/install_deps.bash
```

[homebrew]: https://brew.sh/

## Log in to your Google Cloud account

**Note:** This is **not** necessary if you're [running ClusterFuzz locally].

If you're planning to [set up ClusterFuzz in production], you should
authenticate your account with the `gcloud` tool:

```bash
gcloud auth application-default login
gcloud auth login
```

[set up ClusterFuzz in production]: {{ "/production-setup/" | relative_url }}
[running ClusterFuzz locally]: {{ "/getting-started/local-instance/" | relative_url }}

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

### Debugging Common Dependency Issues

If you are having trouble installing dependencies due to Python versioning, try:

```
$ PYTHON=python3.7 ./local/install_deps.bash
```

Then run:

```
$ pipenv shell
$ python --version
```

The version should be the one you built from source and used to build your dependencies. If it is not, set the pipenv shell version of Python:

```
$ pipenv install --python 3.7
```

Assuming your shell has the expected version of Python assigned, the following command should run all appengine tests:

```
python3.7 butler.py py_unittest -t appengine
```

If, at this point, you see an error to the effect that the config.yaml is missing, sync the pipenv environment’s dependencies with the outer environment’s dependencies:

```
$ cd src; pipenv sync
```

#### Refreshing the Python Environment

You might get stuck in a mode where the python version is the global value, rather than the version you set for the pipenv environment - even when apparently leaving the virtual environment through the `exit`command. If this happens, you may still be in a virtual environment (especially if you see `(clusterfuzz)`before the command prompt). To escape this virtual environment, use the command `deactivate`, then run `python3.7 -m pipenv shell` again to start the pipenv shell with the correct python version.

## ClusterFuzz Development Tips

- Before committing, run `python butler.py format` to clean up formatting
- Make sure you lint all updated files with `python butler.py lint`. (It's also possible, though not recommended, to lint individual files with `pylint --score=no --jobs=0 <name of directory>`.)
