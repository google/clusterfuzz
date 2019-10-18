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
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)  {
  (void) argc;
  (void) argv;
  char* later_run_file = getenv("AFL_TARGET_LATER_RUN_FILE");
  if (!later_run_file)
    return 0;
  struct stat stat_buf;
  if (stat(later_run_file, &stat_buf) == 0)
    return 0; // File exists, we aren't in first run.
  FILE* fp = fopen(later_run_file, "w");
  fclose(fp);
  // Create the file since it doesn't exist.
  while (true);
  return 0;
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
