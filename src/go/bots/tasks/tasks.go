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

package tasks

import (
	"time"

	"clusterfuzz/go/base/persist"
)

const (
	taskEndTimeKey = "task_end_time"
	taskPayloadKey = "task_payload"

	// TaskCompletionBuffer is the additional time that tasks are allowed
	// to complete beyond their lease.
	TaskCompletionBuffer = 90 * time.Minute
)

// IsTaskRunning returns whether or not a task is currently running.
func IsTaskRunning() bool {
	return persist.HasValue(taskPayloadKey)
}

// CurrentTaskPayload returns the current task payload.
func CurrentTaskPayload() string {
	return persist.GetValueStr(taskPayloadKey)
}

// CurrentTaskEndTime returns the expected end time of the current task.
func CurrentTaskEndTime() time.Time {
	if !IsTaskRunning() {
		return time.Unix(0, 0)
	}
	return time.Unix(persist.GetValueInt(taskEndTimeKey), 0)
}

// TrackTaskStart sets task metadata.
func TrackTaskStart(payload string, duration int64) {
	persist.SetValue(taskPayloadKey, payload)
	persist.SetValue(taskEndTimeKey, time.Now().Unix()+duration)
}

// TrackTaskEnd cleans up task metadata.
func TrackTaskEnd() {
	persist.DeleteValue(taskPayloadKey)
	persist.DeleteValue(taskEndTimeKey)
}
