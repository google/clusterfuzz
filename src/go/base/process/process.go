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

// Package process implements process handling functionality.
package process

import (
	"github.com/pkg/errors"
	"github.com/shirou/gopsutil/process"

	"clusterfuzz/go/base/logs"
)

// KillTree kills a process and its children.
func KillTree(pid int32) error {
	proc, err := process.NewProcess(pid)
	if err != nil {
		return errors.Wrap(err, "NewProcess failed")
	}

	children, err := proc.Children()
	if err != nil {
		return errors.Wrap(err, "Children failed")
	}

	for _, proc := range children {
		err = KillTree(proc.Pid)
		if err != nil {
			logs.Warnf("Failed to kill child tree: %+v\n", err)
		}
	}

	return proc.Kill()
}
