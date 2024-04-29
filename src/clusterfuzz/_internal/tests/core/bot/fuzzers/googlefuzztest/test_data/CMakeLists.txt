cmake_minimum_required(VERSION 3.2)
project(googlefuzztest_engine_test)

# GoogleTest requires at least C++17
set(CMAKE_CXX_STANDARD 17)

add_subdirectory(fuzztest)

enable_testing()

fuzztest_setup_fuzzing_flags()

add_executable(
  googlefuzztest_engine_test
  googlefuzztest_engine_test.cc
)

# If you have other dependencies than FuzzTest, link them:
# target_link_libraries(failing_fuzz_test PRIVATE other_deps)

link_fuzztest(googlefuzztest_engine_test)
