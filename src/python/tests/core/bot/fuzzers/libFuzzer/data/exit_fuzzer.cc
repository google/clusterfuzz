// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Build with: clang -fsanitize=fuzzer exit_fuzzer.cc -O3 -o exit_fuzzer
// This fuzz target can simulate a bug in libFuzzer by returning the exitcode 1.

#include <unistd.h>

#include <cstdint>
#include <cstdlib>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (Size < 8)
    return 0;

  // Calling _exit is one of the only ways we can make the target exit with
  // status code 1 from the target.
  _exit(atoi(getenv("EXIT_FUZZER_CODE")));
}
