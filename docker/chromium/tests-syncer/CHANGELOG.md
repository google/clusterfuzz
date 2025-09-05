# Docker Image Version Changelog: clusterfuzz/chromium-tests-syncer


## Analysis Summary

The `latest` and `ubuntu20` images are based on Ubuntu 20.04, while the `ubuntu24` image is based on Ubuntu 24.04. All three images were built successfully and passed health checks. All three images required a modified entrypoint to run and perform health checks due to a startup script that depends on a GCE metadata service. The `ubuntu24` image appears to be a viable replacement, but the package differences should be reviewed for compatibility.

## Build Status

| Image Tag                       | Dockerfile               | Status  |
| ------------------------------- | ------------------------ | ------- |
| `clusterfuzz/chromium-tests-syncer:latest`  | `Dockerfile`             | Success |
| `clusterfuzz/chromium-tests-syncer:ubuntu20`| `ubuntu20-04.Dockerfile` | Success |
| `clusterfuzz/chromium-tests-syncer:ubuntu24`| `ubuntu24-04.Dockerfile` | Success |

## Package Comparison

### Key Differences (Ubuntu 20.04 vs. Ubuntu 24.04)

The `ubuntu24` image includes a number of updated packages. The following are some of the most significant changes:

| Package                 | Ubuntu 20.04 Version | Ubuntu 24.04 Version | Notes                               |
| ----------------------- | -------------------- | -------------------- | ----------------------------------- |
| `git`                   | `1:2.25.1-1ubuntu3.13` | `1:2.43.0-1ubuntu7.3` | Upgraded in Ubuntu 24.04            |
| `python-is-python3`     | `3.8.2-1`            | `3.11.4-1`           | Upgraded in Ubuntu 24.04            |
| `subversion`            | `1.13.0-3ubuntu0.2`  | `1.14.3-1build4`     | Upgraded in Ubuntu 24.04            |

## Dockerfile Analysis

The `latest` and `ubuntu20` Dockerfiles are nearly identical, with the only difference being the `FROM` instruction pointing to the corresponding `base` image tag.

The `ubuntu24` Dockerfile introduces these key changes:
*   **Base Image:** The `FROM` instruction is updated to `gcr.io/clusterfuzz-images/base:ubuntu24-04`.
*   **Python Version:** The `RUN_CMD` environment variable is updated to use `python3.11` instead of `python3.8`.
