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

#include <unistd.h>

#include <cstdint>
#include <cstdlib>

void Foo(const uint8_t *Data, size_t Size) {
  if (Size < 256) {
    return;
  }

  uint8_t Expected[256];
  for (int i = 0; i < 256; ++i) {
    Expected[i] = i;
  }

  bool blah = true;
  for (size_t i = 0; i < 256; ++i) {
    if (Data[i] != Expected[i])
      blah = false;
  }

  if (blah) {
    *((volatile uint8_t*)0) = 0;
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  Foo(Data, Size);
  return 0;
}
