---
layout: default
title: Heartbleed example
parent: Setting up fuzzing
nav_order: 3
permalink: /setting-up-fuzzing/heartbleed-example/
---

# Finding Heartbleed

This tutorial will show you how to find [Heartbleed] using libFuzzer and
ClusterFuzz.

- TOC
{:toc}
---

## Prerequisites

We assume you are using a Linux bot.
See the [compiler section] in the libFuzzer and AFL documentation for how to get
a working compiler for following along with the examples below. Make sure to set
`CC` and `CXX`.

[Heartbleed]: https://en.wikipedia.org/wiki/Heartbleed
[Getting Started]: {{ site.baseurl }}/getting-started/
[compiler section]: {{ site.baseurl }}/setting-up-fuzzing/libfuzzer-and-afl/#compiler

## Building a libFuzzer target for OpenSSL
Run these commands to build a libFuzzer target for OpenSSL:

[comment]: <> (TODO(metzman): Check that the URLs work when repo gets published.)
```bash
# Download and unpack a vulnerable version of OpenSSL:
curl -O https://ftp.openssl.org/source/old/1.0.1/openssl-1.0.1f.tar.gz
tar xf openssl-1.0.1f.tar.gz

# Build OpenSSL with ASan and fuzzer instrumentation:
cd openssl-1.0.1f/
./config

# $CC must be pointing to clang binary, see the "compiler section" link above.
make CC="$CC -g -fsanitize=address,fuzzer-no-link"
cd ..

# Download the fuzz target and its data dependencies:
curl -O https://raw.githubusercontent.com/google/clusterfuzz/master/docs/setting-up-fuzzing/heartbleed/handshake-fuzzer.cc
curl -O https://raw.githubusercontent.com/google/clusterfuzz/master/docs/setting-up-fuzzing/heartbleed/server.key
curl -O https://raw.githubusercontent.com/google/clusterfuzz/master/docs/setting-up-fuzzing/heartbleed/server.pem

# Build OpenSSL fuzz target for ClusterFuzz ($CXX points to clang++ binary):
$CXX -g handshake-fuzzer.cc -fsanitize=address,fuzzer openssl-1.0.1f/libssl.a \
  openssl-1.0.1f/libcrypto.a -std=c++17 -Iopenssl-1.0.1f/include/ -lstdc++fs   \
  -ldl -lstdc++ -o handshake-fuzzer

zip openssl-fuzzer-build.zip handshake-fuzzer server.key server.pem
```

## Uploading the fuzzer to ClusterFuzz
First we need to create a job:

* Navigate to the *Jobs* page.
* Go to the "ADD NEW JOB" form.
* Fill out a job with the following:
    * **"libfuzzer_asan_linux_openssl"** for the "Name".
    * **"LINUX"** for the "Platform".
    * **"libFuzzer"** for the "Select/modify fuzzers".
    * **"libfuzzer"** and **"engine_asan"** for the "Templates".
    * `CORPUS_PRUNE = True` for the "Environment String".
* Select openssl-fuzzer-build.zip to upload as a "Custom Build".
* Use the "ADD" button to add the job to ClusterFuzz.

## Fuzzing and seeing results
If you follow this tutorial using [local ClusterFuzz] server and bot instances,
and you do not have any other fuzzing tasks running, you should see the string:
`fuzz libFuzzer libfuzzer_asan_linux_openssl` show up in the [bot logs]. This
means that ClusterFuzz is fuzzing your build. Soon after that you should see a
stack trace and the string: `AddressSanitizer: heap-buffer-overflow` in the log.

If you follow this tutorial using a [production instance of ClusterFuzz], you
should be able to see the string `fuzz libFuzzer libfuzzer_asan_linux_openssl`
on the *Bots* page. The timing also depends on the other workload you may have.

Some time later, you can go to the ClusterFuzz homepage (ie: the *Testcases*
page) and you will see a testcase titled **"Heap-buffer-overflow READ{\*}"**.
This is the Heartbleed vulnerability found by ClusterFuzz.

[bot logs]: {{ site.baseurl }}/getting-started/local-instance/#viewing-logs
[local ClusterFuzz]: {{ site.baseurl }}/getting-started/local-instance/
[production instance of ClusterFuzz]: {{ site.baseurl }}/production-setup/clusterfuzz/
