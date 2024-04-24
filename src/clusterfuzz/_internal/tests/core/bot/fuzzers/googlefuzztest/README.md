### How to build your own googlefuzztest binaries

* Install cmake => https://abseil.io/docs/cpp/tools/cmake-installs
* Install abseil => https://abseil.io/docs/cpp/tools/cmake-installs
* Install protobuff => https://github.com/protocolbuffers/protobuf/blob/main/cmake/README.md
* Follow googlefuzztest quickstart => https://github.com/google/fuzztest/blob/main/doc/quickstart-cmake.md

### How to build binaries for this test suite

* cd test_data/failing_fuzz_test/build
* CC=clang CXX=clang++ cmake -DCMAKE_BUILD_TYPE=RelWithDebug -DFUZZTEST_FUZZING_MODE=on ..
* cmake --build .
* cp failing_fuzz_test ../failing_fuzztest
* ./failing_fuzz_test
* Completely analogous for passing_fuzz_test