---
layout: default
title: Job definition
parent: Reference
nav_order: 3
permalink: /reference/job-definition/
---

# Job definition

This page walks you through various options that can be used for configuring a
ClusterFuzz [job]. You may not need to use many of these options.

- TOC
{:toc}
---

## Environment variables

Jobs can be created or edited on the *Jobs* page. A job definition mostly
consists of environment variables. If you use a job template when configuring a
job, the template will add the variables that are specified in the job template
definition.

### Common variables

* **CUSTOM_BINARY**: indicates whether a job uses a manually uploaded build or
  not. Use `CUSTOM_BINARY = True` if you upload a build when creating a job. If
  you use **RELEASE_BUILD_BUCKET_PATH** to specify a build stored in a [Google
  Cloud Storage] bucket, use `CUSTOM_BINARY = False`.
* **RELEASE_BUILD_BUCKET_PATH**: indicates a path to the build that is uploaded
  to [Google Cloud Storage] bucket. See [specifying a continuous build] for more
  detail.
* **ADDITIONAL_ASAN_OPTIONS**: provides a way to specify custom [runtime flags
  for AddressSanitizer]. The values specified here will overwrite the default
  values used by ClusterFuzz. The same type of variable is available for the
  other sanitizers, i.e. **ADDITIONAL_MSAN_OPTIONS** or
  **ADDITIONAL_UBSAN_OPTIONS** (see an example below on this page).

### LibFuzzer and AFL specific

* **CORPUS_PRUNE**: indicates whether a [corpus pruning] needs to be done using
  a given job. The default value is `False`. It's recommended to use
  `CORPUS_PRUNE = True` for libFuzzer ASan jobs only. Enabling pruning for a one
  job only is sufficient, as other libFuzzer and AFL jobs use the same corpus
  when running the same fuzz targets.

### Blackbox fuzzing specific

* **APP_NAME**: indicates the file name of a target application to be tested.
* **APP_ARGS**: arguments to be passed to the target application. This variable
  should include both optional and required arguments you want to pass.
* **REQUIRED_APP_ARGS**: arguments that must be passed to the target
  application. These arguments will be always used, while the others specified
  in **APP_ARGS** and not specified here can be removed by ClusterFuzz during
  testcase minimization if they aren't needed to reproduce a crash.
* **TEST_TIMEOUT**: indicates how many seconds a target application can spend on
  processing an individual testcase.

## Examples
Below are some examples of job definitions used on a production instance of
ClusterFuzz.

### LibFuzzer and AFL

**Job name**: `libfuzzer_asan_zlib`

**Platform**: `LINUX`

**Templates**:

```
libfuzzer
engine_asan
```

**Environment String**:

```
RELEASE_BUILD_BUCKET_PATH = gs://clusterfuzz-builds/zlib/zlib-address-([0-9]+).zip
CUSTOM_BINARY = False
CORPUS_PRUNE = True
```

---

**Job name**: `libfuzzer_ubsan_zlib`

**Platform**: `LINUX`

**Templates**:

```
libfuzzer
engine_ubsan
```

**Environment String**:

```
RELEASE_BUILD_BUCKET_PATH = gs://clusterfuzz-builds/zlib/zlib-undefined-([0-9]+).zip
CUSTOM_BINARY = False
```

---

**Job name**: `afl_asan_zlib`

**Platform**: `LINUX`

**Templates**:

```
afl
engine_asan
```

**Environment String**:

```
RELEASE_BUILD_BUCKET_PATH = gs://clusterfuzz-builds-afl/zlib/zlib-address-([0-9]+).zip
CUSTOM_BINARY = False
```

---

### Blackbox fuzzing

**Job name**: `asan_linux_chrome`

**Platform**: `LINUX`

**Templates**: none

**Environment String**:

```
RELEASE_BUILD_BUCKET_PATH = gs://chromium-browser-asan/linux-release/asan-linux-release-([0-9]+).zip
MIN_REVISION = 441045
CUSTOM_BINARY = False
APP_NAME = chrome
APP_ARGS = --enable-experimental-extension-apis --enable-extension-apps --js-flags="--expose-gc --verify-heap" --no-first-run --use-gl=swiftshader --disable-in-process-stack-traces
REQUIRED_APP_ARGS =  --no-first-run --use-gl=swiftshader --disable-in-process-stack-traces
TEST_TIMEOUT = 15
ADDITIONAL_ASAN_OPTIONS = allocator_may_return_null=0
```

[Google Cloud Storage]: https://cloud.google.com/storage/
[corpus pruning]: {{ site.baseurl }}/reference/glossary/#corpus-pruning
[job]: {{ site.baseurl }}/reference/glossary/#job-type
[runtime flags for AddressSanitizer]: https://github.com/google/sanitizers/wiki/AddressSanitizerFlags#run-time-flags
[specifying a continuous build]: {{ site.baseurl }}/production-setup/setting-up-fuzzing-job/#specifying-a-continuous-build
