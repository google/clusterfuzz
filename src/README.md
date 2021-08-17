# ClusterFuzz

This directory contains the source of ClusterFuzz.

## Building and testing libClusterFuzz
Run `./build.sh` to build the pip package.

For testing, use a fresh Python 3 virtualenv, and install the package by running
`pip install dist/*.whl`.

Then,

```bash
$ cd tests
$ python -m unittest
```

## Publishing
Increment the version field in `setup.py`, then run `./build.sh` to build the
pip package. TODO: Tie pip package version to ClusterFuzz version once it's
stable.

Per
[https://packaging.python.org/tutorials/packaging-projects/#uploading-the-distribution-archives],
to publish the pip package,

```bash
$ python3 -m pip install --user --upgrade twine
$ python3 -m twine upload dist/*
```
