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

package db

import (
	"cloud.google.com/go/datastore"
	"github.com/pkg/errors"
)

// IsErrorIgnorable returns whether or not the given datastore error can be ignored.
func IsErrorIgnorable(err error) bool {
	if err == nil {
		return true
	}

	switch errors.Cause(err).(type) {
	case *datastore.ErrFieldMismatch:
		return true
	default:
		return false
	}
}

// IsNoSuchEntityError returns whether or not the given error is a not found
// error.
func IsNoSuchEntityError(err error) bool {
	return errors.Cause(err) == datastore.ErrNoSuchEntity
}

// HandleError returns nil if the error can be ignored, or the error unchanged.
func HandleError(err error) error {
	if IsErrorIgnorable(err) {
		return nil
	}

	return err
}
