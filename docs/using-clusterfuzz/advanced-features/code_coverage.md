---
layout: default
title: Code coverage
parent: Advanced features
grand_parent: Using ClusterFuzz
permalink: /using-clusterfuzz/advanced/code-coverage/
nav_order: 2
---

# Code coverage
This document describes the requirements and recommendations for enabling code
coverage reports for a project using ClusterFuzz.

- TOC
{:toc}

---

## ClusterFuzz and code coverage
ClusterFuzz is capable of storing, presenting, and leveraging code coverage
information. However, ClusterFuzz does not generate code coverage reports, as
that process depends on the build system used by a project, and build systems
can be very different across projects.

## Setting up a code coverage builder
It is possible to set up an external builder or a Continuous Integration job
that would produce code coverage data for ClusterFuzz. For C and C++ projects it
is recommended to use [Clang Source-based Code Coverage](https://clang.llvm.org/docs/SourceBasedCodeCoverage.html).

## Code coverage report and stats
A typical workflow for the builder is the following:
1. Check out the latest version of the source code for the project.
2. Build all the fuzzers in the project with code coverage instrumentation.
3. Download the latest corpus backup from ClusterFuzz.
4. For every fuzzer in the project:
  - Unpack the corpus backup.
  - Run the fuzzer against the unpacked corpus.
  - Process the coverage dumps (`.profraw` files) using `llvm-profdata merge`.
  - Use the resulting `.profdata` file to generate `$fuzzer_name.json` file via
    `llvm-cov export -summary-only`.
5. Merge all `.profdata` files produced by individual fuzzers into a single
  `.profdata` file using  `llvm-profdata merge`.
6. Use the final `.profdata` file to generate `summary.json` file for the whole
  project. The resulting file will include aggregate data from the all fuzzers.
7. Use the final `.profdata` file to generate an HTML report using
  `llvm-cov show -format=html`. The report will include aggregate data from the
  all fuzzers.

As a result, the builder should produce the following artifacts:
1. JSON files with coverage stats for every fuzzer in the project.
2. JSON file with coverage stats for the whole project.
3. HTML report for the whole project.

[Here](https://github.com/google/oss-fuzz/blob/master/infra/gcb/build_and_run_coverage.py)
is an example of OSS-Fuzz code coverage job definition for
[Google Cloud Build](https://cloud.google.com/cloud-build/). It also uses
[coverage_utils.py](https://cs.chromium.org/chromium/src/tools/code_coverage/coverage_utils.py)
script from Chromium and [this bash script](https://github.com/google/oss-fuzz/blob/master/infra/base-images/base-runner/coverage).

## Coverage information file
The builder needs to upload the artifacts and a JSON file containing coverage
information to a [GCS bucket](https://cloud.google.com/storage/docs/creating-buckets)
specified in the project config (`coverage.reports.bucket`). The file name
should be equal to the project name, e.g. `zlib.json`. The JSON file(s) must be
uploaded to the following location:

```bash
gs://<bucket name>/latest_report_info/<project name>.json
# Example from OSS-Fuzz:
gs://oss-fuzz-coverage/latest_report_info/zlib.json
```
The format of the file is the following:

```json
{
    "report_date": "YYYYMMDD",
    "fuzzer_stats_dir": "gs://path_to_directory_with_per_fuzzer_summary.json_files",
    "report_summary_path": "gs://path_to_the_project_summary.json_file",
    "html_report_url": "https://link_to_the_main_page_of_the_report",
}
```

* `report_date` is the date when the report was generated.
* `fuzzer_stats_dir` is a GCS directory containing JSON files for every fuzzer
  (`$fuzzer_name.json`).
* `report_summary_path` should point to the `summary.json` file that includes
  aggregate data from the all fuzzers in the project.
* `html_report_url` should point to the `index.html` of the HTML report.


An example of a real `zlib.json` file uploaded by the code coverage job on
OSS-Fuzz.

```json
{
    "report_date": "20190112",
    "fuzzer_stats_dir": "gs://oss-fuzz-coverage/zlib/fuzzer_stats/20190112",
    "report_summary_path": "gs://oss-fuzz-coverage/zlib/reports/20190112/linux/summary.json",
    "html_report_url": "https://storage.googleapis.com/oss-fuzz-coverage/zlib/reports/20190112/linux/index.html",
}
```
