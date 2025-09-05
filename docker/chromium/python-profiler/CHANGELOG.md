# Docker Image Version Changelog: clusterfuzz/chromium-python-profiler


## Analysis Summary

The `latest` and `ubuntu20` images are based on Ubuntu 20.04, while the `ubuntu24` image is based on Ubuntu 24.04. All three images were built successfully and passed health checks. All three images required a modified entrypoint to run and perform health checks due to a startup script that depends on a GCE metadata service. The `ubuntu24` image appears to be a viable replacement, but the package differences should be reviewed for compatibility.

## Build Status

| Image Tag                       | Dockerfile               | Status  |
| ------------------------------- | ------------------------ | ------- |
| `clusterfuzz/chromium-python-profiler:latest`  | `Dockerfile`             | Success |
| `clusterfuzz/chromium-python-profiler:ubuntu20`| `ubuntu20-04.Dockerfile` | Success |
| `clusterfuzz/chromium-python-profiler:ubuntu24`| `ubuntu24-04.Dockerfile` | Success |

## Package Comparison

### Key Differences (Ubuntu 20.04 vs. Ubuntu 24.04)

The package lists for all three images are identical to their respective base images. The `ubuntu24` image includes a large number of updated packages compared to the `ubuntu20` and `latest` images.

## Dockerfile Analysis

The `chromium-python-profiler` Dockerfile is a minimal "wrapper" image. Its only purpose is to inherit from a `clusterfuzz/chromium/base` image and set a single environment variable (`RUN_CMD`). It does not install any packages or perform any configurations itself.

Because of this simplicity, the only change required to upgrade from `latest`/`ubuntu20` to `ubuntu24` is updating the `FROM` instruction to point to the corresponding `ubuntu24-04` tag of the base image. All package differences are inherited directly from this base image change.
