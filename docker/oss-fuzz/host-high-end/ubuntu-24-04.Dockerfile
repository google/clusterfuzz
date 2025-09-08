# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
FROM gcr.io/clusterfuzz-images/oss-fuzz/host:ubuntu-24-04

# Run less instances of ClusterFuzz on these so that each instance has more
# resoures.
ENV NUM_WORKERS_PER_HOST 8

# We need access to corpora for JS fuzzers.
ENV UPDATE_WEB_TESTS True