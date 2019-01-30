// Copyright 2018 Google LLC
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

// Package config implements configuration helpers for tests.
package config

import (
	"os"
)

// IntegrationTestBucketStatic returns the read-only bucket used for
// integration tests.
func IntegrationTestBucketStatic() string {
	return "clusterfuzz-test-data"
}

// IntegrationTestBucketMutable returns the per-user mutable bucket used for
// integration tests.
func IntegrationTestBucketMutable() string {
	// TODO(ochang): Before running tests, clear this bucket.
	return os.Getenv("CLUSTERFUZZ_MUTABLE_TEST_BUCKET")
}

// IntegrationTestsEnabled returns whether or not integration tests are enabled.
func IntegrationTestsEnabled() bool {
	return os.Getenv("INTEGRATION") == "1"
}
