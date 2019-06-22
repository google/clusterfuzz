---
layout: default
title: Build pipeline
parent: Production setup
permalink: /production-setup/build-pipeline/
nav_order: 2
---

# Build pipeline
This document describes the requirements and recommendations for setting up a
continuous build pipeline for a project using ClusterFuzz.

- TOC
{:toc}

---

## Why do you need a build pipeline?
Fuzzing is a software testing technique which works out best if done
continuously. As your target projects evolve, ClusterFuzz needs to be able to
fuzz the most recent versions of them. Having a continuously running build
pipeline allows ClusterFuzz to identify revisions when a regression was
introduced as well as detect bug fixes and the corresponding revisions.


## Setting up a builder
ClusterFuzz does not provide any build infrastructure, as build systems can be
very different across projects. If you have existing CI infrastructure, very
likely it can be used for providing builds to ClusterFuzz.

## Sanitizers
As described in the [Setting up fuzzing] docs, your builds need to be
instrumented with a [sanitizer]. See the individual links for each sanitizer
[here] for instructions on how to use them.

[Setting up fuzzing]: {{ site.baseurl }}/setting-up-fuzzing/
[sanitizer]: {{ site.baseurl }}/reference/glossary/#sanitizer
[here]: {{ site.baseurl }}/reference/glossary/#sanitizer

## Providing the builds to ClusterFuzz
* The builds should be packed into zip or tar archives and uploaded to a
  [GCS bucket](https://cloud.google.com/storage/docs/creating-buckets).
  Uploading can be done via [gsutil tool](https://cloud.google.com/storage/docs/gsutil)
  or by using [signed URLs](https://cloud.google.com/storage/docs/access-control/signed-urls).
* The archive name should be of `any-name-([0-9]+).zip` format, where `([0-9]+)`
  stands for a revision number such as SVN commit position, a timestamp (e.g. `YYYYMMDDHHMM`), or
  another build number which **increases** with every build. Other than `zip`,
  we support
  [tar extensions](https://en.wikipedia.org/wiki/Tar_(computing)#Suffixes_for_compressed_files)
  as well.
* When [setting up a fuzzing job], specify `RELEASE_BUILD_BUCKET_PATH` env
  variable to point to the builds location, e.g.
  `gs://bucket-name/subdirectory/any-name-([0-9]+).zip`.

## Providing revisions for the build dependencies
ClusterFuzz is able to detect _regression_ and _fixed_ revision ranges not only
for your target project, but for its dependencies as well. The only requirement
is to provide a `.srcmap.json` file alongside the build archive. The filename
should be the same as the build archive name, but with `.srcmap.json` suffix
instead of `.zip`/`.tar*` (i.e. `any-name-([0-9]+).srcmap.json`).

When [setting up a fuzzing job], specify `REVISION_VARS_URL` env variable to
point to srcmap files location, e.g.
`gs://bucket-name/subdirectory/any-name-([0-9]+).srcmap.json`.

These srcmap files have the following format:

```json
{
  "/path/to/library": {
    "type": "type_of_version_control_system",
    "url": "repository_url",
    "rev": "revision_identifier",
  },
  // any number of the projects enumerated in this format
}
```

An example of `.srcmap.json` for a libpng build:

```json
{
  "/src/libpng": {
    "type": "git",
    "url": "https://github.com/glennrp/libpng.git",
    "rev": "eddf9023206dc40974c26f589ee2ad63a4227a1e"
  },
  "/src/zlib": {
    "type": "git",
    "url": "https://github.com/madler/zlib.git",
    "rev": "cacf7f1d4e3d44d871b605da3b647f07d718623f"
  },
  "/src/libfuzzer": {
    "type": "svn",
    "url": "https://llvm.org/svn/llvm-project/compiler-rt/trunk/lib/fuzzer",
    "rev": "350185"
  }
}
```

## Other artifacts and runtime dependencies

If your target program requires any additional runtime dependencies or artifacts
such as [seed corpus] or a [dictionary] for [libFuzzer or AFL], all these files
should be placed in the same directory as the target executable and be included
in the build archive.

## Build pipeline solutions
Most of the Continuous Integration systems can be used for providing builds to
ClusterFuzz. Examples include [Google Cloud Build](https://cloud.google.com/cloud-build/docs/),
[Jenkins](https://jenkins.io/), and others.

[libFuzzer or AFL]:{{ site.baseurl }}/setting-up-fuzzing/libfuzzer_and_afl/
[seed corpus]: {{ site.baseurl }}/setting-up-fuzzing/libfuzzer_and_afl/#seed-corpus
[dictionary]: {{ site.baseurl }}/setting-up-fuzzing/libfuzzer_and_afl/#dictionaries
[setting up a fuzzing job]: {{ site.baseurl }}/production-setup/setting-up-fuzzing-job/
