#include "fuzztest/fuzztest.h"

void ThisTestAlwaysFails(int a, int b) {
 	int *SomeIntArray = (int*)malloc(1*sizeof(int));
	SomeIntArray[10]=40;
	free(SomeIntArray);
}
FUZZ_TEST(MyTestSuite, ThisTestAlwaysFails);
