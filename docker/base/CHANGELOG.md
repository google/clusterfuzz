# Docker Image Version Changelog: clusterfuzz/base


## Analysis Summary

The `latest` and `ubuntu20` images are nearly identical, as they are both based on Ubuntu 20.04. The `ubuntu24` image, based on Ubuntu 24.04, introduces a number of package updates and changes. All three images were built successfully, but required workarounds to run and perform health checks due to a startup script that depends on a GCE metadata service. The `ubuntu24` image appears to be a viable replacement for the older images, but the package differences should be reviewed to ensure compatibility.

## Build Status

| Image Tag                  | Dockerfile               | Status  |
| -------------------------- | ------------------------ | ------- |
| `clusterfuzz/base:latest`  | `Dockerfile`             | Success |
| `clusterfuzz/base:ubuntu20`| `ubuntu20-04.Dockerfile` | Success |
| `clusterfuzz/base:ubuntu24`| `ubuntu24-04.Dockerfile` | Success |

## Package Comparison

### Key Differences (Ubuntu 20.04 vs. Ubuntu 24.04)

| Package                 | Ubuntu 20.04 Version | Ubuntu 24.04 Version | Notes                               |
| ----------------------- | -------------------- | -------------------- | ----------------------------------- |
| `libidn11`              | `1.33-2.2ubuntu2`    | -                    | Removed in Ubuntu 24.04             |
| `libidn12`              | -                    | `1.42-1build1`       | Added in Ubuntu 24.04               |
| `libncurses5-dev`       | `6.2-0ubuntu2.1`     | -                    | Removed in Ubuntu 24.04             |
| `libncurses-dev`        | `6.2-0ubuntu2.1`     | `6.4+20240113-1ubuntu2` | Upgraded in Ubuntu 24.04            |
| `libncursesw5`          | `6.2-0ubuntu2.1`     | -                    | Removed in Ubuntu 24.04             |
| `libncursesw6`          | `6.2-0ubuntu2.1`     | `6.4+20240113-1ubuntu2` | Upgraded in Ubuntu 24.04            |
| `libssl-dev`            | `1.1.1f-1ubuntu2.24` | `3.0.13-0ubuntu3.5`  | Upgraded in Ubuntu 24.04            |
| `libssl1.1`             | `1.1.1f-1ubuntu2.24` | -                    | Removed in Ubuntu 24.04             |
| `libssl3t64`            | -                    | `3.0.13-0ubuntu3.5`  | Added in Ubuntu 24.04               |
| `python3.8`             | `3.8.10-0ubuntu1~20.04.18` | -                | Removed in Ubuntu 24.04             |
| `python3.12`            | -                    | `3.12.3-1ubuntu0.8`  | Added in Ubuntu 24.04               |

## Dockerfile Analysis

The main difference between the Dockerfiles is the base image:

*   **`Dockerfile` (latest):** Uses `ubuntu:20.04` as the final base image, but also uses `ubuntu:16.04` in a multi-stage build to copy some older libraries.
*   **`ubuntu20-04.Dockerfile`:**  Identical to the latest `Dockerfile`.
*   **`ubuntu24-04.Dockerfile`:** Uses `ubuntu:24.04` as the base image. It removes the multi-stage build with `ubuntu:16.04` and updates the package installation commands to reflect the changes in Ubuntu 24.04. For example, it installs `libidn12` instead of `libidn11`.
