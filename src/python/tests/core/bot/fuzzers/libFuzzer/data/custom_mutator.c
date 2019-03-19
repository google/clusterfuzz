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
// clang-6.0 -c -fPIC -Os custom_mutator.c
// clang-6.0 -shared -s -Os -o mutator-plugin.so custom_mutator.o
// zip custom_mutator_plugin-libfuzzer_asan-test_fuzzer.zip mutator-plugin.so

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

__attribute__((weak)) size_t
LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize);

int LLVMFuzzerCustomMutator(uint8_t *data, size_t size, size_t max,
                            unsigned int seed) {
  puts("CUSTOM MUTATOR");
  return LLVMFuzzerMutate(data, size, max);
}
