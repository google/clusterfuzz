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

#include <cstdint>
#include <cstdio>

void Foo(const uint8_t* data, size_t size) {
  volatile int result;

  if (data[0] == 'A') {
    result = 0;
  } else if (data[0] == 'B') {
    result = 1;
  } else if (data[0] == 'C') {
    result = 2;
  } else if (data[0] == 'D') {
    result = 3;
  } else {
    *(volatile int*)0 = 0;
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (!size)
    return 0;

  Foo(data, size);
  return 0;
}
