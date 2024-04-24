#include "fuzztest/fuzztest.h"

void ThisTestAlwaysSucceeds(int a, int b) {
 	int *SomeIntArray = (int*)malloc(10*sizeof(int));
	SomeIntArray[2]=40;
	free(SomeIntArray);
}
FUZZ_TEST(MyTestSuite, ThisTestAlwaysSucceeds);
