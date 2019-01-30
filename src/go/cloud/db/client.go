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

// Package db implements various helpers for accessing Cloud Datastore.
package db

import (
	"context"

	"cloud.google.com/go/datastore"
	"github.com/pkg/errors"

	"clusterfuzz/go/base/logs"
	"clusterfuzz/go/cloud"
)

var (
	datastoreClient *datastore.Client
)

// Init initializes the Cloud Datastore client.
func Init() {
	var err error
	datastoreClient, err = datastore.NewClient(context.Background(), cloud.ProjectID())
	if err != nil {
		logs.Panicf("Failed to set up client: %s", err)
	}
}

// Client returns the Cloud Datastore client.
func Client() *datastore.Client {
	if datastoreClient == nil {
		logs.Panicf("Client not initialized.")
	}

	return datastoreClient
}

// Get retrieves an entity by key.
func Get(ctx context.Context, key *datastore.Key, dst interface{}) error {
	return HandleError(errors.Wrap(Client().Get(ctx, key, dst), "Get failed"))
}

// Put writes an entity.
func Put(ctx context.Context, key *datastore.Key, src interface{}) (*datastore.Key, error) {
	key, err := Client().Put(ctx, key, src)
	return key, HandleError(errors.Wrap(err, "Put failed"))
}

// PutMulti is a batch version of Put.
func PutMulti(ctx context.Context, keys []*datastore.Key, src interface{}) ([]*datastore.Key, error) {
	keys, err := Client().PutMulti(ctx, keys, src)
	return keys, HandleError(errors.Wrap(err, "PutMulti failed"))
}
