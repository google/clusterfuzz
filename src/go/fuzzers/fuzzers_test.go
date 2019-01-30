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

package fuzzers

import (
	"path"
	"reflect"
	"sort"
	"testing"
)

func TestGetFuzzTargets(t *testing.T) {
	targets, err := GetFuzzTargets(path.Join("testdata", "util"))
	if err != nil {
		t.Errorf("GetFuzzTargets got an error: %s", err)
	}

	expected := []string{
		path.Join("testdata", "util", "target"),
		path.Join("testdata", "util", "target_fuzzer"),
	}
	sort.Strings(targets)
	if !reflect.DeepEqual(targets, expected) {
		t.Errorf("Wrong result from GetFuzzTargets: got %v, expected %v", targets, expected)
	}
}
