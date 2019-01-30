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

package bots

import (
	"clusterfuzz/go/base/environ"
	"clusterfuzz/go/base/fs"
)

// ClearTempDirectories clears temporary directories.
func ClearTempDirectories(clearUserProfiles bool) error {
	tmpDir := environ.GetValueStr("BOT_TMPDIR")
	err := fs.ClearDirectory(tmpDir)
	if err != nil {
		return err
	}

	if !clearUserProfiles {
		return nil
	}

	if !environ.HasValue("USER_PROFILE_ROOT_DIR") {
		return nil
	}

	userProfilesDir := environ.GetValueStr("USER_PROFILE_ROOT_DIR")
	return fs.ClearDirectory(userProfilesDir)
}

// ClearTestcaseDirectories clears testcase directories.
func ClearTestcaseDirectories() error {
	err := fs.ClearDirectory(environ.GetValueStr("FUZZ_INPUTS"))
	if err != nil {
		return err
	}

	return fs.ClearDirectory(environ.GetValueStr("FUZZ_INPUTS_DISK"))
}
