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

// clang++ -g -fsanitize=address -fsanitize-coverage=trace-pc-guard \
// -O0 -std=c++11 analyze_dict_fuzzer.cc libFuzzer.a -o analyze_dict_fuzzer

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>

int ParseData(const uint8_t *Data, size_t Size) {
  int result = 0;
  std::string text(reinterpret_cast<const char*>(Data), Size);
  if (strstr(text.c_str(), "APPLE")) {
    result |= 1;
  }
  if (strstr(text.c_str(), "GINGER")) {
    result |= 2;
  }
  if (strstr(text.c_str(), "BEET")) {
    result |= 4;
  }

  return result;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (!Size)
    return 0;

  if (ParseData(Data, Size))
    return 0;

  return 0;
}
