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

## Testing

To run all unit tests, execute the following commands:

```bash
python3.11 -m pipenv butler.py py_unittest -t appengine -m
python3.11 -m pipenv butler.py py_unittest -t core -m
```

The `-m` flag runs the tests in parallel, which is recommended.

### Running a single test file

To run a single test file, you can use the `-p` or `--pattern` flag. For example, to run the tests in `deploy_test.py`, you can use the following command:

```bash
python3.11 -m pipenv butler.py py_unittest -t core -p deploy_test.py
```

## Linting

To check the code for style and linting issues, run the following command:

```bash
python3.11 -m pipenv butler.py lint
```

This will lint the changed code in your current branch.

## Formatting

To automatically format the code to match the project's style guidelines, run:

```bash
python3.11 -m pipenv butler.py format
```

This will format the changed code in your current branch.
It's possible to get into a state where linting and formatting contradict each other. In this case, STOP, the human will fix it.

## Project Knowledge (from `docs`)

### Overview
ClusterFuzz is a scalable, distributed fuzzing infrastructure written in Python. It is used to find security and stability issues (e.g., ASan, MSan, UBSan, TSan) in software through coverage-guided (via libFuzzer and AFL++) or blackbox fuzzing.

### Architecture
- **App Engine**: Provides a web interface for crash viewing, management, and stats. 
- **Bots**: Machines that pull tasks from a queue and execute a command (e.g:`fuzz`, `progression`, `regression`, `minimize`, `corpus_pruning`). Preemptible untrusted bots typically only run `fuzz` tasks to reduce cost, while non-preemptible bots handle critical verification tasks.

### Core Entities
- **Job**: Environment variable specifications for running fuzzers (e.g., `APP_NAME`, `RELEASE_BUILD_BUCKET_PATH`, `CORPUS_PRUNE`, `CUSTOM_BINARY`). Job names encode components (e.g., `libfuzzer_asan_linux_openssl`).
- **Fuzz Target**: A function or binary that accepts mutated byte inputs from engines like libFuzzer.
- **Corpus**: Minimum set of inputs that generated maximal code coverage. Pruning is key to efficiency.
- **Crash State**: Signature used to deduplicate crashes.

### Key Directories
- `src/appengine`: Web interface backend handlers and templates.
- `src/clusterfuzz`: Core Python logic. `_internal/` contains deeply complex private modules.
- `docs/`: Comprehensive project documentation. Always consult this directory for deep-dive answers.

### Local Workflows
Remember to invoke `butler.py` via `python3.11 -m pipenv butler.py`:
- `run_server`: Spins up the local web UI (`localhost:9000`).
- `run_bot /path/to/my-bot`: Starts a local fuzzing bot.
