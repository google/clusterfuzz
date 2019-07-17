This directory contains scripts for running ClusterFuzz docker images locally.

# Prerequisites

## Running a local metadata server
To emulate a local GCE metadata server using your own account's credentials
(through `gcloud auth application-default login`), run:

```bash
$ ./run_metadata.bash \
  -project-id=<your-project-name> \
  -project-num=<your-project-num> \
  -deployment-bucket=<value of deployment.bucket attribute in your config-dir/project.yaml>
```

# Running bot locally
To run a bot image locally, run:

```bash
$ ./run_docker.bash gcr.io/clusterfuzz-images/base
```

By default this uses the latest deployed source, but you can also use your local
checkout by doing:

```bash
$ LOCAL_SRC=1 CONFIG_DIR_OVERRIDE=<config-dir-path> ./run_docker.bash gcr.io/clusterfuzz-images/base
```

# Running CI locally
To run the CI environment locally, run

```bash
$ ./run_ci.bash
# (inside container)
$ setup
```
