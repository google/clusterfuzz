// Copyright 2026 Google LLC
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

// Coverage-guided fuzz target for integration tests that crashes
// deterministically on the 5th non-empty input and reproduces under
// ClusterFuzz's -runs=100 reproduction check.

#include <cstddef>
#include <cstdint>

constexpr int crashThreshold = 5;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (!size) {
    return 0;
  }

  static int count = 0;
  if (++count >= crashThreshold) {
    // Null pointer write raises SIGSEGV (AddressSanitizer: SEGV on 0x0).
    *(volatile uint8_t *)0 = 0;
  }
  return 0;
}
