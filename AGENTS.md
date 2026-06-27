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

## Remote Swarming Development & Validation Workflow

This section outlines the step-by-step cycle for developing, deploying, launching, and verifying changes on remote Swarming bots.

### Step 1: Local Development & Formatting
Make your code changes in your feature branch. Always run formatting and linting locally before committing:
```bash
pipenv run python butler.py format
pipenv run python butler.py lint
```

### Step 2: Push & Deploy to Remote `dev`
For changes to run on remote Swarming bots, they must be committed, merged, and pushed to the remote **`dev`** branch:
1. Commit and push your feature branch:
   ```bash
   git add <modified_files>
   git commit -m "Your description"
   git push origin <your-feature-branch>
   ```
2. Merge into `dev` and push:
   ```bash
   git checkout dev
   git pull origin dev
   git merge <your-feature-branch>
   git push origin dev
   git checkout <your-feature-branch>
   ```
3. **⚠️ Crucial Rebuild Wait Time**: After pushing to `dev`, you **MUST wait 20 to 25 minutes** before triggering any Swarming tasks. This gives the remote Google Cloud Storage (GCS) builder enough time to pull your new commit, compile the binaries, and package them into the deployment ZIP bundle (`linux-3.zip`) fetched by the bots.

### Step 3: Preprocess & Launch the Swarming Task
Once the deployment package has finished rebuilding on GCS:
1. Trigger the preprocess pipeline and launch a new Swarming task:
   ```bash
   python3 scratch/preprocess_and_launch.py
   ```
2. Note the generated **Swarming Task ID** (e.g. `791f445b26114a10`) and the task URL printed in the stdout.

### Step 4: Live Monitoring & Log Retrieval
1. **Live Monitor**: Open `scratch/monitor_swarming_task.py`, update `task_id` with your new Task ID, and run the script to stream the live console output:
   ```bash
   python3 scratch/monitor_swarming_task.py
   ```
2. **Download High-Resolution Logs**: Once the task terminates:
   * Look at the live monitor output to identify the **assigned Bot Name** (e.g. `lin-192-g582`) and the final state (`COMPLETED` or `BOT_DIED`).
   * Open `scratch/read_logs.py`, update the `bot_name` and adjust the time filter window (e.g. `timestamp >= "YYYY-MM-DDTHH:MM:SSZ"`), then run:
     ```bash
     pipenv run python scratch/read_logs.py
     ```
   * This downloads all high-resolution Stackdriver bot and logcat streams into `scratch/bot_logs.txt`.
3. **Analyze**: Inspect `scratch/bot_logs.txt` using grep/editors to verify your changes (such as JNI prints or fuzzer loop outputs).

