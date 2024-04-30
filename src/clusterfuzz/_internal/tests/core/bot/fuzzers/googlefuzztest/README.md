### How to build your own googlefuzztest binaries

* Install cmake => https://cmake.org/download
* Install abseil => https://abseil.io/docs/cpp/tools/cmake-installs
* Install protobuff => https://github.com/protocolbuffers/protobuf/blob/main/cmake/README.md
* Follow googlefuzztest quickstart => https://github.com/google/fuzztest/blob/main/doc/quickstart-cmake.md

### How to build binaries for this test suite

* cd test_data/googlefuzztest_engine_test/build
* CC=clang CXX=clang++ cmake -DCMAKE_BUILD_TYPE=RelWithDebug -DFUZZTEST_FUZZING_MODE=on ..
* cmake --build .
* cp googlefuzztest_engine_test ../googlefuzztest_engine_test
* ./googlefuzztest_engine_test (or FUZZTEST_SHOULD_FAIL=1 ./googlefuzztest_engine_test)