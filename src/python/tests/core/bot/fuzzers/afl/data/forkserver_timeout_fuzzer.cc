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
// To compile:
// clang -c -w $AFL_HOME/llvm_mode/afl-llvm-rt.o.c
// clang++ -g -c -fsanitize-coverage=trace-pc-guard forkserver_timeout_fuzzer.cc
// clang++ afl_driver.cpp forkserver_timeout_fuzzer.o afl-llvm-rt.o.o

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

__attribute__((constructor(0))) static void infite_loop() {
  system("echo hi >> /tmp/logg");
  char* first_run_file = getenv("FIRST_RUN_FILE");
  if (!first_run_file)
    return;
  system("echo removiing >> /tmp/logg");
  if (remove(first_run_file) == -1)
    return;
  system("echo looping >> /tmp/logg");
  while (true);
}

void Foo() {
  static int count = 0;
  count++;

  if (count >= 5) {
    *(volatile uint8_t*)0 = 0;
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  fprintf(stderr, "Forkserver did not timeout\n");
  if (!Size)
    return 0;
  Foo();
  return 0;
}
