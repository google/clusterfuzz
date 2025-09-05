# Docker Image Version Changelog: clusterfuzz/chromium-builder


## Analysis Summary

The `latest` and `ubuntu20` images are based on Ubuntu 20.04, while the `ubuntu24` image is based on Ubuntu 24.04. All three images were built successfully, but required a workaround for the `install-build-deps.py` script. The script's dependency on a pinned version of `snapcraft` caused build failures, which was resolved by patching the script to disable this check. All three images also required a modified entrypoint to run and perform health checks due to a startup script that depends on a GCE metadata service. The `ubuntu24` image appears to be a viable replacement, but the package differences should be reviewed for compatibility.

## Build Status

| Image Tag                       | Dockerfile               | Status  |
| ------------------------------- | ------------------------ | ------- |
| `clusterfuzz/chromium-builder:latest`  | `Dockerfile`             | Success |
| `clusterfuzz/chromium-builder:ubuntu20`| `ubuntu20-04.Dockerfile` | Success |
| `clusterfuzz/chromium-builder:ubuntu24`| `ubuntu24-04.Dockerfile` | Success |

## Package Comparison

### Key Differences (Ubuntu 20.04 vs. Ubuntu 24.04)

The `ubuntu24` image includes a large number of updated packages. The following are some of the most significant changes:

| Package                 | Ubuntu 20.04 Version | Ubuntu 24.04 Version | Notes                               |
| ----------------------- | -------------------- | -------------------- | ----------------------------------- |
| `git`                   | `1:2.25.1-1ubuntu3.13` | `1:2.43.0-1ubuntu7.3` | Upgraded in Ubuntu 24.04            |
| `python3.8`             | `3.8.10-0ubuntu1~20.04.18` | -                | Removed in Ubuntu 24.04             |
| `python3.12`            | -                    | `3.12.3-1ubuntu0.8`  | Added in Ubuntu 24.04               |
| `subversion`            | `1.13.0-3ubuntu0.2`  | `1.14.3-1build4`     | Upgraded in Ubuntu 24.04            |

## Dockerfile Analysis

The `latest` and `ubuntu20` Dockerfiles are nearly identical, with the only difference being the `FROM` instruction pointing to the corresponding `base` image tag.

The `ubuntu24` Dockerfile introduces several changes:
*   **Base Image:** The `FROM` instruction is updated to `gcr.io/clusterfuzz-images/base:ubuntu24-04`.
*   **Python Version:** The `RUN_CMD` environment variable is updated to use `python3.11` instead of `python3.8`.
*   **Python Symlink:** A new command `RUN ln -s /usr/local/bin/python3.11 /usr/local/bin/python3` is added to create a symbolic link for python.
*   **Build Script Patch:** The `RUN` command that executes `install-build-deps.py` includes an additional `sed` command (`sed -i "s/if requires_pinned_linux_libc():/if False:/"`) to patch the script and avoid build failures related to pinned dependencies.
