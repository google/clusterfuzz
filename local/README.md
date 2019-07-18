This directory contains scripts for running ClusterFuzz docker images locally.

# Prerequisites

Make sure you have installed the dependencies using:
```bash
$ ../local/install_deps.bash
```

## Running a local metadata server

Provide credentials to connect to your project using one of the following ways:
* To use your own account credentials, run:
  ```bash
  $ gcloud auth application-default login
  ```
* To use a service account credentials file, run:
  ```bash
  $ export GOOGLE_APPLICATION_CREDENTIALS=<path-to-your-credentials.json>`
  ```

To run a local GCE metadata server emulating the credentials provided above:

```bash
$ ./run_metadata.bash \
  -project-id=<your-project-name> \
  -project-num=<your-project-number> \
  -deployment-bucket=<deployment.bucket attribute in your config-dir/project.yaml>
```

You can skip specifying the deployment-bucket if you plan to use local checkout.

# Running a bot locally

To run a bot image locally, run:

```bash
$ ./run_docker.bash gcr.io/clusterfuzz-images/base
```

**NOTE**: You must run this command as a non-root user. Make sure that to add your user to the
docker group using `sudo adduser $USER docker`.

By default this uses the latest deployed source, but you can also use your local
checkout by doing:

```bash
$ LOCAL_SRC=1 CONFIG_DIR_OVERRIDE=<your-config-dir> ./run_docker.bash gcr.io/clusterfuzz-images/base
```

# Running CI locally
To run the CI environment locally, run

```bash
$ ./run_ci.bash
# (inside container)
$ setup
```
