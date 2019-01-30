This directory contains the parts of ClusterFuzz implemented in Go.

## Helpful commands

Execute from `src` directory.

* Re-generate `.bazel` files (e.g. if you changed the dependencies)

```bash
bazel run //:gazelle
```

* Run ClusterFuzz server code locally

```bash
bazel run //go/server
```
