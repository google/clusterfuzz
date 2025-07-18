# ClusterFuzz

This directory contains the source of ClusterFuzz.

## 🐍 Project Setup (`asdf`)

This project uses a `.tool-versions` file. Follow these steps to install the correct Python version.

1.  **Install `asdf`**
    Follow the [official `asdf` guide](https://www.google.com/search?q=%5Bhttps://asdf-vm.com/guide/getting-started.html%5D\(https://asdf-vm.com/guide/getting-started.html\)).

2.  **Add Plugins**
    ```bash
    asdf plugin add python
    asdf plugin add gcloud https://github.com/jthegedus/asdf-gcloud
    ```

3.  **Install tools**
    Run this command inside the project directory. It will read the version from the `.tool-versions` file.

    ```bash
    asdf install
    python3.11 -m pip install pipenv
    ```

4.  **Install Deps**
    Run this command inside the project directory. This script will use `pipenv` to set up a virtual environment and install all the required packages specified in the `Pipfile`, ensuring your local setup is consistent with the project's requirements.

    ```bash
    ./local/install_deps.bash
    ```

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
