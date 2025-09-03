# Docker Image Version Changelog: clusterfuzz/oss-fuzz-worker


## Analysis Summary

The `latest` and `ubuntu20` images are based on Ubuntu 20.04, while the `ubuntu24` image is based on Ubuntu 24.04. All three images were built successfully and passed health checks. All three images required a modified entrypoint to run and perform health checks due to a startup script that depends on a GCE metadata service. The `ubuntu24` image appears to be a viable replacement, but the package differences should be reviewed for compatibility.

## Build Status

| Image Tag                       | Dockerfile               | Status  |
| ------------------------------- | ------------------------ | ------- |
| `clusterfuzz/oss-fuzz-worker:latest`  | `Dockerfile`             | Success |
| `clusterfuzz/oss-fuzz-worker:ubuntu20`| `ubuntu20-04.Dockerfile` | Success |
| `clusterfuzz/oss-fuzz-worker:ubuntu24`| `ubuntu24-04.Dockerfile` | Success |

## Package Comparison

### Key Differences (Ubuntu 20.04 vs. Ubuntu 24.04)

The `ubuntu24` image includes a number of updated packages. The following are some of the most significant changes:

| Package                 | Ubuntu 20.04 Version | Ubuntu 24.04 Version | Notes                               |
| ----------------------- | -------------------- | -------------------- | ----------------------------------- |
| `libc6-i386`            | `2.31-0ubuntu9.16`   | `2.39-0ubuntu8.5`    | Upgraded in Ubuntu 24.04            |
| `lib32gcc-s1`           | `10.5.0-1ubuntu1~20.04` | `14.1.0-1ubuntu1~24.04` | Upgraded in Ubuntu 24.04            |

## Dockerfile Analysis

The `latest` and `ubuntu20` Dockerfiles are very similar, with the main difference being the `FROM` instruction pointing to the corresponding `oss-fuzz/base` image tag.

The `ubuntu24` Dockerfile introduces these key changes:
*   **Base Image:** The `FROM` instruction is updated to `gcr.io/clusterfuzz-images/oss-fuzz/base:ubuntu24-04`.
*   **Package Name Change:** The package `lib32gcc1` (used in the latest Dockerfile) is updated to `lib32gcc-s1` in the `ubuntu20` and `ubuntu24` Dockerfiles to reflect changes in the Ubuntu package repositories.
