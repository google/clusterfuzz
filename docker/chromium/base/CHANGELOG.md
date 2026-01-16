# Docker Image Version Changelog: clusterfuzz/chromium-base


## Analysis Summary

The `latest` and `ubuntu20` images are nearly identical, both based on Ubuntu 20.04. The `ubuntu24` image, based on Ubuntu 24.04, introduces significant package updates. All three images were built successfully after applying a fix to the `install-build-deps.py` script to handle a pinned dependency that is no longer available. The `ubuntu24` image also required a symbolic link to be created for `python3`. All three images required workarounds to run and perform health checks due to a startup script that depends on a GCE metadata service. The `ubuntu24` image appears to be a viable replacement, but the package differences should be reviewed for compatibility.

## Build Status

| Image Tag                       | Dockerfile               | Status  |
| ------------------------------- | ------------------------ | ------- |
| `clusterfuzz/chromium-base:latest`  | `Dockerfile`             | Success |
| `clusterfuzz/chromium-base:ubuntu20`| `ubuntu20-04.Dockerfile` | Success |
| `clusterfuzz/chromium-base:ubuntu24`| `ubuntu24-04.Dockerfile` | Success |

## Package Comparison

### Key Differences (Ubuntu 20.04 vs. Ubuntu 24.04)

The `ubuntu24` image includes a large number of updated packages. The following are some of the most significant changes:

| Package                 | Ubuntu 20.04 Version | Ubuntu 24.04 Version | Notes                               |
| ----------------------- | -------------------- | -------------------- | ----------------------------------- |
| `libaom-dev`            | `1.0.0-3`            | `3.8.2-2ubuntu0.1`   | Upgraded in Ubuntu 24.04            |
| `libevent-dev`          | `2.1.11-stable-1`    | `2.1.12-stable-9ubuntu2` | Upgraded in Ubuntu 24.04            |
| `libgl1-mesa-dev`       | `21.2.6-0ubuntu0.1~20.04.2` | `25.0.7-0ubuntu0.24.04.1` | Upgraded in Ubuntu 24.04            |
| `libgles2-mesa-dev`     | `21.2.6-0ubuntu0.1~20.04.2` | `25.0.7-0ubuntu0.24.04.1` | Upgraded in Ubuntu 24.04            |
| `libvulkan-dev`         | `1.2.131.2-1`        | `1.3.275.0-1build1`  | Upgraded in Ubuntu 24.04            |
| `python2.7-dev`         | `2.7.18-1~20.04.7`   | -                    | Removed in Ubuntu 24.04             |
| `python3-dev`           | `3.8.2-0ubuntu2`     | `3.12.3-0ubuntu2`    | Upgraded in Ubuntu 24.04            |

## Dockerfile Analysis

The Dockerfiles for `latest` and `ubuntu20` are very similar. The `ubuntu24` Dockerfile has the following key differences:

*   **Base Image:** Uses `gcr.io/clusterfuzz-images/base:ubuntu-24-04`.
*   **Python Symlink:** Adds a symbolic link from `python3.12` to `python3` to ensure the `install-build-deps.py` script can find the python interpreter.
*   **Package Installation:** The list of installed packages is slightly different, reflecting the changes in Ubuntu 24.04. For example, `libdconf-dev` and `libgconf2-dev` are no longer installed.
