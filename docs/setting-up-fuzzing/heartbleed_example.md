---
layout: default
title: Heartbleed example
parent: Setting up fuzzing
nav_order: 3
permalink: /setting-up-fuzzing/heartbleed-example/
---

# Finding Heartbleed

- TOC
{:toc}
---

## Introduction and prerequisites
This tutorial will show you how to find [Heartbleed] using libFuzzer and
ClusterFuzz.
It assumes you are running an instance of ClusterFuzz with a server
and a bot. For details on how to do that, see our guide on [Getting Started].
To reduce wait times, you may want to disable any jobs you explicitly associated
with a fuzzer on the Fuzzers page.
See the [compiler section] in the libFuzzer and AFL documentation for how to get
a working compiler for following along with the examples below.

## Building a libFuzzer target for OpenSSL
Run these commands to build a libFuzzer target for OpenSSL:

[comment]: <> (TODO(metzman): Check that the URLs work when repo gets published.)
```bash
# Download and unpack a vulnerable version of OpenSSL:
$ wget https://www.openssl.org/source/openssl-1.0.1f.tar.gz
$ tar xf openssl-1.0.1f.tar.gz

# Build OpenSSL with ASan and fuzzer instrumentation:
$ cd  openssl-1.0.1f/
$ ./config
$ make CC="$CC -g -fsanitize=address,fuzzer-no-link"
$ cd ..

# Download the fuzz target and its data dependencies:
$ curl -O https://raw.githubusercontent.com/google/clusterFuzz/master/docs/setting-up-fuzzing/heartbleed/handshake-fuzzer.cc
$ curl -O https://raw.githubusercontent.com/google/clusterFuzz/master/docs/setting-up-fuzzing/heartbleed/server.key
$ curl -O https://raw.githubusercontent.com/google/clusterFuzz/master/docs/setting-up-fuzzing/heartbleed/server.pem

# Build OpenSSL fuzz target for ClusterFuzz:
$ $CC -g handshake-fuzzer.cc -fsanitize=address,fuzzer openssl-1.0.1f/libssl.a \
  openssl-1.0.1f/libcrypto.a -std=c++17 -Iopenssl-1.0.1f/include/ -lstdc++fs   \
  -ldl -lstdc++ -o handshake-fuzzer

$ zip openssl-fuzzer-build.zip handshake-fuzzer server.key server.pem
```

## Uploading the fuzzer to ClusterFuzz
First we need to create a job:

* Navigate to the Jobs page.
* Go to the "ADD NEW JOB" form.
* Fill out a job with the following:
    * "libfuzzer_openssl_asan" for the "Name".
    * "LINUX" for the "Platform".
    * "libfuzzer" and "engine_asan" for the "Templates".
* Select openssl-fuzzer-build.zip to upload as a "Custom Build".
* Use the "ADD" button to add the job to ClusterFuzz.

Then enable the job by going to the Fuzzer page and editing libFuzzer:
* Click "Select/modify jobs".
* Mark "libfuzzer_openssl_asan".
* Press "SUBMIT".

## Fuzzing and seeing results
Within five minutes, you should see "fuzz libFuzzer libfuzzer_openssl_asan" show
up in the [bot logs]. This means that ClusterFuzz is fuzzing your build. Soon
after that you should see a stack trace and the string:
"AddressSanitizer: heap-buffer-overflow" in the logs. This is the heartbleed
vulnerability. Go to the ClusterFuzz homepage (ie: the Testcases page) and you
will see a testcase titled (Heap-buffer-overflow READ{*}). This is the
heartbleed vulnerability found by ClusterFuzz.

[Heartbleed]: https://en.wikipedia.org/wiki/Heartbleed
[Getting Started]: /getting-started/
[clang]: http://releases.llvm.org/download.html
[bot logs]: {{ site.baseurl }}/getting-started/local-instance/#viewing-logs
[compiler section]: {{ site.baseurl }}/setting-up-fuzzing/libfuzzer-and-afl/#compiler
