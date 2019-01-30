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

// Package gcs implements a buckets.Provider for Google Cloud Storage.
package gcs

import (
	"context"
	"io"
	"strings"

	"cloud.google.com/go/storage"
	"github.com/pkg/errors"
	"google.golang.org/api/iterator"

	"clusterfuzz/go/base/buckets"
	"clusterfuzz/go/base/logs"
)

const (
	// Scheme is a constant string for Google Cloud Storage URL scheme.
	Scheme = "gs"
)

// bucketProvider is an implementation of buckets.Provider for GCS.
type bucketProvider struct {
	client *storage.Client
}

// iteratorAdapter is an Adapter to for storage.ObjectIterator -> iterator.Iterator
type iteratorAdapter struct {
	// it is the underlying storage.ObjectIterator
	it *storage.ObjectIterator

	// err is the encountered during iteration, if any.
	err error

	// bucket contains name of the GCS bucket.
	bucket string
}

// New creates a new buckets.Provider for GCS.
func New() buckets.Provider {
	ctx := context.Background()
	client, err := storage.NewClient(ctx)
	if err != nil {
		logs.Panicf("Failed to get GCS client: %v", err)
	}

	return &bucketProvider{client}
}

// getObject returns the storage.ObjectHandle for the given bucket and path.
func (p *bucketProvider) getObject(bucket, path string) *storage.ObjectHandle {
	return p.client.Bucket(bucket).Object(path)
}

// ReadObject returns an io.Reader for the remote object.
func (p *bucketProvider) ReadObject(ctx context.Context, bucket, path string) (io.ReadCloser, error) {
	reader, err := p.getObject(bucket, path).NewReader(ctx)
	return reader, errors.Wrap(err, "getting reader failed")
}

// WriteObject returns an io.PipeWriter object with specified contents.
func (p *bucketProvider) WriteObject(ctx context.Context, bucket, path string) (io.WriteCloser, error) {
	return p.getObject(bucket, path).NewWriter(ctx), nil
}

// StatObject returns information about the remote object. Returns nil if
// the object does not exist.
func (p *bucketProvider) StatObject(ctx context.Context, bucket, path string) (*buckets.ObjectInfo, error) {
	attrs, err := p.getObject(bucket, path).Attrs(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get attrs")
	}

	return &buckets.ObjectInfo{
		Bucket:   attrs.Bucket,
		Name:     attrs.Name,
		Scheme:   Scheme,
		Size:     uint64(attrs.Size),
		IsObject: true,
	}, nil
}

// ListObjects iterates through objects in the bucket.
func (p *bucketProvider) ListObjects(ctx context.Context, bucket, path string, recursive bool) (buckets.ObjectIterator, error) {
	bkt := p.client.Bucket(bucket)
	if path != "" && !strings.HasSuffix(path, "/") {
		// An object can have the same name as a path prefix. Append a
		// "/" to make sure we don't include it.
		path = path + "/"
	}

	var delimiter string
	if recursive {
		delimiter = ""
	} else {
		delimiter = "/"
	}

	query := &storage.Query{
		Delimiter: delimiter,
		Prefix:    path,
		Versions:  false,
	}
	it := bkt.Objects(ctx, query)

	return &iteratorAdapter{
		it:     it,
		bucket: bucket,
	}, nil
}

// Next returns the current item for the iterator and advances to the next item.
func (it *iteratorAdapter) Next(info *buckets.ObjectInfo) bool {
	attrs, err := it.it.Next()
	if err == iterator.Done {
		return false
	}

	if err != nil {
		it.err = errors.Wrap(err, "failed to iterate")
		return false
	}

	if attrs.Prefix != "" {
		info.IsObject = false
		info.Name = attrs.Prefix
	} else {
		info.IsObject = true
		info.Name = attrs.Name
	}
	info.Bucket = attrs.Bucket
	info.Scheme = Scheme
	info.Size = uint64(attrs.Size)

	return true
}

func (it *iteratorAdapter) Err() error {
	return it.err
}
