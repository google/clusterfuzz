// Copyright 2023 The Centipede Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// A simple fuzz target that contains bugs detectable by different sanitizers.
// For now, asan and msan.

#include <unistd.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

[[maybe_unused]] static volatile void *sink;
[[maybe_unused]] static volatile void *ptr_sink;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size != 3) return 0;  // Make bugs easy to discover.

  // "uaf" => heap-use-after-free
  if (data[0] == 'u' && data[1] == 'a' && data[2] == 'f') {
    int *x = new int;
    fprintf(stderr, "uaf %p\n", x);
    sink = x;
    delete x;
    *x = 0;
  }

  // Allocate 4Gb of RAM if the input is 'oom'.
  // sanitizer_test provokes OOM by feeding 'oom' input here,
  // and checks its output format matches with the expectation of clusterfuzz.
  if (data[0] == 'o' && data[1] == 'o' && data[2] == 'm') {
    size_t oom_allocation_size = 1ULL << 32;
    void *ptr = malloc(oom_allocation_size);
    memset(ptr, 42, oom_allocation_size);
    ptr_sink = ptr;
  }

  // 'slo' => Sleep for 10 seconds to provoke timeout.
  if (data[0] == 's' && data[1] == 'l' && data[2] == 'o') {
    sleep(10);
  }

  return 0;
}
