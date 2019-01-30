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
	"context"

	"cloud.google.com/go/datastore"
	"github.com/pkg/errors"
	"google.golang.org/api/iterator"
)

// Iterator provides an iterator for iterating through results.
type Iterator struct {
	it  *datastore.Iterator
	err error
}

// Next iterates to the next entity.
func (it *Iterator) Next(dst interface{}) bool {
	_, err := it.it.Next(dst)
	if err == iterator.Done {
		return false
	}

	err = HandleError(err)
	if err != nil {
		it.err = errors.Wrap(err, "failed to iterate")
		return false
	}

	return true
}

// Err returns the error from iteration.
func (it *Iterator) Err() error {
	return it.err
}

// RunQuery runs the given datastore.Query.
func RunQuery(ctx context.Context, q *datastore.Query) *Iterator {
	return &Iterator{it: Client().Run(ctx, q)}
}
