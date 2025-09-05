# Docker Image Version Changelog: clusterfuzz/ci


## Analysis Summary

The `latest` and `ubuntu20` images are based on Ubuntu 20.04, while the `ubuntu24` image is based on Ubuntu 24.04. All three images were built successfully and passed health checks. All three images required a modified entrypoint to run and perform health checks due to a startup script that depends on a GCE metadata service. The `ubuntu24` image appears to be a viable replacement, but the package differences should be reviewed for compatibility.

## Build Status

| Image Tag                       | Dockerfile               | Status  |
| ------------------------------- | ------------------------ | ------- |
| `clusterfuzz/ci:latest`  | `Dockerfile`             | Success |
| `clusterfuzz/ci:ubuntu20`| `ubuntu20-04.Dockerfile` | Success |
| `clusterfuzz/ci:ubuntu24`| `ubuntu24-04.Dockerfile` | Success |

## Package Comparison

### Key Differences (Ubuntu 20.04 vs. Ubuntu 24.04)

The `ubuntu24` image includes a number of updated packages. The following are some of the most significant changes:

| Package                 | Ubuntu 20.04 Version | Ubuntu 24.04 Version | Notes                               |
| ----------------------- | -------------------- | -------------------- | ----------------------------------- |
| `bazel`                 | `7.1.1`              | `8.3.1`              | Upgraded in Ubuntu 24.04            |
| `git`                   | `1:2.25.1-1ubuntu3.13` | `1:2.43.0-1ubuntu7.3` | Upgraded in Ubuntu 24.04            |
| `google-cloud-sdk`      | `467.0.0-0`          | `536.0.1-0`          | Upgraded in Ubuntu 24.04            |
| `openjdk-11-jdk`        | `11.0.25+8-1~20.04`  | -                    | Removed in Ubuntu 24.04             |
| `openjdk-17-jdk`        | -                    | `17.0.16+8~us1-0ubuntu1~24.04.1` | Added in Ubuntu 24.04               |

## Dockerfile Analysis

The `latest` and `ubuntu20` Dockerfiles are nearly identical, with the only difference being the `FROM` instruction pointing to the corresponding `base` image tag.

The `ubuntu24` Dockerfile introduces several changes:
*   **Base Image:** The `FROM` instruction is updated to `gcr.io/clusterfuzz-images/base:ubuntu24-04`.
*   **OpenJDK:** Upgrades from OpenJDK 11 to OpenJDK 17.
*   **Bazel:** The Bazel installation is updated to use a different GPG key URL (`https://bazel.build/bazel-release.pub.gpg` instead of `https://storage.googleapis.com/www.bazel.build/bazel-release.pub.gpg`).
