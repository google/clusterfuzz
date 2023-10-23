// Copyright 2022 The Centipede Authors.
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

#include <cstddef>
#include <cstdint>
#include <cstdlib>

// A fuzz target used for testing Centipede's ability to minimize crashes.
// Crashes on inputs like ?f???u???z?.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 3) return 0;
  if (data[1] == 'f' && data[size / 2] == 'u' && data[size - 2] == 'z') abort();
  return 0;
}
