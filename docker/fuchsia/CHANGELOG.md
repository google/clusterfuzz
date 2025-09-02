# Docker Image Version Changelog: clusterfuzz/fuchsia


## Analysis Summary

The `latest` and `ubuntu20` images are based on Ubuntu 20.04, while the `ubuntu24` image is based on Ubuntu 24.04. All three images were built successfully and passed health checks. All three images required a modified entrypoint to run and perform health checks due to a startup script that depends on a GCE metadata service. The `ubuntu24` image appears to be a viable replacement, but the package differences should be reviewed for compatibility.

## Build Status

| Image Tag                       | Dockerfile               | Status  |
| ------------------------------- | ------------------------ | ------- |
| `clusterfuzz/fuchsia:latest`  | `Dockerfile`             | Success |
| `clusterfuzz/fuchsia:ubuntu20`| `ubuntu20-04.Dockerfile` | Success |
| `clusterfuzz/fuchsia:ubuntu24`| `ubuntu24-04.Dockerfile` | Success |

## Package Comparison

### Key Differences (Ubuntu 20.04 vs. Ubuntu 24.04)

The `ubuntu24` image includes a number of updated packages. The following are some of the most significant changes:

| Package                 | Ubuntu 20.04 Version | Ubuntu 24.04 Version | Notes                               |
| ----------------------- | -------------------- | -------------------- | ----------------------------------- |
| `openssh-client`        | `1:8.2p1-4ubuntu0.11` | `1:9.6p1-3ubuntu13.13` | Upgraded in Ubuntu 24.04            |

## Dockerfile Analysis

The `fuchsia` Dockerfile inherits from the `clusterfuzz/base` image, installs `openssh-client`, and copies a `start.sh` script.

The only functional difference between the `latest`, `ubuntu20`, and `ubuntu24` Dockerfiles is the `FROM` instruction, which points to the corresponding version of the `clusterfuzz/base` image. This change in the base image is what introduces all the package differences noted in this report.
