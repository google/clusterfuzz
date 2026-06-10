# Agent Instructions

This document provides instructions for agents on how to perform common development tasks in this repository.

## Initial Setup

This project uses `asdf` to manage tool versions. Before you can install the project's dependencies, you need to install and configure `asdf`.

### 1. Install `asdf`

First, make sure you have `git` and `curl` installed. Then, clone the `asdf` repository:

```bash
git clone https://github.com/asdf-vm/asdf.git ~/.asdf --branch v0.14.0
```

### 2. Configure Your Shell

Add `asdf` to your shell's startup file. For `bash`, run:

```bash
echo -e "\n. \"$HOME/.asdf/asdf.sh\"" >> ~/.bashrc
```

Then, source your `.bashrc` to apply the changes to your current session:

```bash
source ~/.bashrc
```

### 3. Install `asdf` Plugins and Tools

Now, from the root of this project, run the following commands to install the necessary `asdf` plugins and the tools specified in the `.tool-versions` file:

```bash
asdf plugin add python
asdf plugin add gcloud https://github.com/jthegedus/asdf-gcloud
asdf install
```

### 4. Install `pipenv`

Once `asdf` has installed the correct python version, you need to install `pipenv`:

```bash
python -m pip install pipenv
```

### 5. Install Project Dependencies

Now you are ready to install the project's dependencies. Run the following command from the root of the repository:

```bash
./local/install_deps.bash
```

## Using Butler
Before each time you use the `butler.py` script, verify that you are inside the virtual environment, if not activate it by running `python -m pipenv shell`, or pre append any `python butler.py` call with
`pipenv run`

For instance:
```bash
pipenv run python butler.py lint
```
Is the same as running
```bash
python butler.py lint
```
if you are inside a virtual environment.

## Testing

To run all unit tests, execute the following commands:

```bash
python butler.py py_unittest -t appengine -m
python butler.py py_unittest -t core -m
```

The `-m` flag runs the tests in parallel, which is recommended.

### Running a single test file

To run a single test file, you can use the `-p` or `--pattern` flag. For example, to run the tests in `deploy_test.py`, you can use the following command:

```bash
python butler.py py_unittest -t core -p deploy_test.py
```

## Linting

To check the code for style and linting issues, run the following command:

```bash
python butler.py lint
```

This will lint the changed code in your current branch.

## Formatting

To automatically format the code to match the project's style guidelines, run:

```bash
python butler.py format
```

This will format the changed code in your current branch.
It's possible to get into a state where linting and formatting contradict each other. In this case, STOP, the human will fix it.

## Development Containers (Optional)

Agents can optionally run the development environment and commands inside a dev container using the Dev Containers CLI (`devcontainer`).

> [!IMPORTANT]
> This approach is **optional**. Before starting a container or running commands inside a container, the agent MUST explicitly ask the user for permission if they want to proceed with such an approach.

If the user approves:
1. Ensure Docker is running, or ask the user to start it.
2. Build/start the dev container:
   ```bash
   devcontainer up --workspace-folder .
   ```
3. Run butler commands inside the container using `devcontainer exec`:
   ```bash
   devcontainer exec --workspace-folder . pipenv run python butler.py <command>
   ```
   *Note: On Apple Silicon (ARM64) hosts, the initial setup script exits early. The agent must manually run the python dependencies script inside the container before executing other commands:*
   ```bash
   devcontainer exec --workspace-folder . env PYTHON=python3 bash local/install_python_deps_linux.bash
   ```
