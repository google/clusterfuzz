// Copyright 2024 Google LLC
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

#include "fuzztest/fuzztest.h"

void ConditionallyPassingFuzzTest(int a, int b) {
 	int *SomeIntArray = (int*)malloc(1*sizeof(int));
    int PositionToBeAccessed = 0;

    const char *content = getenv("FUZZTEST_SHOULD_FAIL");
    if (content != NULL) {
        PositionToBeAccessed=10;
    }

	SomeIntArray[PositionToBeAccessed]=40;
	free(SomeIntArray);
}
FUZZ_TEST(MyTestSuite, ConditionallyPassingFuzzTest);
