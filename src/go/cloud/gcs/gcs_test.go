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

// Package buckets_gcs_test contains integration tests for accessing buckets
// via GCS.
package gcs

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"reflect"
	"testing"

	"clusterfuzz/go/base/buckets"
	"clusterfuzz/go/testing/config"
)

const (
	bucketTestDir = "buckets_gcs_test"
)

var (
	tmpDir string
)

func iterateObjectNames(t *testing.T, it buckets.ObjectIterator) []string {
	var names []string
	var info buckets.ObjectInfo

	for it.Next(&info) {
		names = append(names, info.Name)
	}
	if err := it.Err(); err != nil {
		t.Fatalf("Failed to iterate objects: %+v", err)
	}

	return names
}

func TestCopyObjectFrom(t *testing.T) {
	targetPath := path.Join(tmpDir, "test_file")
	srcPath := fmt.Sprintf("gs://%s/%s/test_file", config.IntegrationTestBucketStatic(), bucketTestDir)
	err := buckets.CopyObjectFrom(context.Background(), srcPath, targetPath)
	if err != nil {
		t.Fatalf("buckets.CopyObjectFrom failed unexpectedly: %v.", err)
	}

	data, err := ioutil.ReadFile(targetPath)
	if err != nil {
		t.Fatalf("Failed to read %s: %v.", targetPath, err)
	}

	expected := "TESTDATA"
	if string(data) != expected {
		t.Fatalf("File contained %s, expected %s", data, expected)
	}
}

func TestCopyObjectTo(t *testing.T) {
	srcPath := path.Join(tmpDir, "test_copy_object_to")
	targetPath := fmt.Sprintf("gs://%s/%s/test_file", config.IntegrationTestBucketMutable(), bucketTestDir)
	expected := []byte("WRITEDATA")

	err := ioutil.WriteFile(srcPath, expected, 0600)
	if err != nil {
		t.Fatalf("Failed to write %s: %v.", srcPath, err)
	}

	err = buckets.CopyObjectTo(context.Background(), srcPath, targetPath)
	if err != nil {
		t.Fatalf("buckets.CopyObjectTo failed unexpectedly: %v.", err)
	}

	data, err := buckets.ReadObjectBytes(context.Background(), targetPath)
	if err != nil {
		fmt.Printf("targetPath = %s\n", targetPath)
		t.Fatalf("buckets.ReadObjectBytes failed unexpectedly: %v.", err)
	}

	if !bytes.Equal(data, expected) {
		t.Fatalf("File contained %s, expected %s", data, expected)
	}
}

func TestReadObject(t *testing.T) {
	path := fmt.Sprintf("gs://%s/%s/test_file", config.IntegrationTestBucketStatic(), bucketTestDir)
	data, err := buckets.ReadObjectBytes(context.Background(), path)
	if err != nil {
		t.Fatalf("buckets.ReadObjectBytes failed unexpectedly: %v.", err)
	}

	expected := "TESTDATA"
	if string(data) != expected {
		t.Fatalf("File contained %s, expected %s", data, expected)
	}
}

func TestWriteObject(t *testing.T) {
	expected := []byte("WRITEDATA")
	path := fmt.Sprintf("gs://%s/%s/test_write_object", config.IntegrationTestBucketMutable(), bucketTestDir)
	err := buckets.WriteObjectBytes(context.Background(), path, expected)
	if err != nil {
		t.Fatalf("buckets.WriteObjectBytes failed unexpectedly: %v.", err)
	}

	data, err := buckets.ReadObjectBytes(context.Background(), path)
	if err != nil {
		t.Fatalf("buckets.ReadObjectBytes failed unexpectedly: %v.", err)
	}

	if !bytes.Equal(data, expected) {
		t.Fatalf("File contained %s, expected %s", data, expected)
	}
}

func TestStatObject(t *testing.T) {
	path := fmt.Sprintf("gs://%s/%s/test_file", config.IntegrationTestBucketStatic(), bucketTestDir)
	info, err := buckets.StatObject(context.Background(), path)
	if err != nil {
		t.Fatalf("buckets.StatObject failed unexpectedly: %v.", err)
	}

	expectedName := fmt.Sprintf("%s/test_file", bucketTestDir)
	if expectedName != info.Name {
		t.Fatalf("Object name is %s, expected %s.", info.Name, expectedName)
	}

	expectedSize := uint64(8)
	if expectedSize != info.Size {
		t.Fatalf("Object size is %d, expected %d.", info.Size, expectedSize)
	}
}

func TestListObjects(t *testing.T) {
	path := fmt.Sprintf("gs://%s/%s/test_dir", config.IntegrationTestBucketStatic(), bucketTestDir)
	it, err := buckets.ListObjects(context.Background(), path, false)
	if err != nil {
		t.Fatalf("buckets.ListObjects failed unexpectedly: %v.", err)
	}

	expected := []string{
		"buckets_gcs_test/test_dir/bar",
		"buckets_gcs_test/test_dir/foo",
		"buckets_gcs_test/test_dir/subdir/",
	}
	names := iterateObjectNames(t, it)

	if !reflect.DeepEqual(expected, names) {
		t.Fatalf("Incorrect listing, got %v (%d), expected %v.", names, len(names), expected)
	}
}

func TestListObjectsRecursive(t *testing.T) {
	path := fmt.Sprintf("gs://%s/%s/test_dir", config.IntegrationTestBucketStatic(), bucketTestDir)
	it, err := buckets.ListObjects(context.Background(), path, true)
	if err != nil {
		t.Fatalf("buckets.ListObjects failed unexpectedly: %v.", err)
	}

	expected := []string{
		"buckets_gcs_test/test_dir/bar",
		"buckets_gcs_test/test_dir/foo",
		"buckets_gcs_test/test_dir/subdir/123",
	}
	names := iterateObjectNames(t, it)

	if !reflect.DeepEqual(expected, names) {
		t.Fatalf("Incorrect listing, got %v, expected %v.", names, expected)
	}
}

func TestMain(m *testing.M) {
	if !config.IntegrationTestsEnabled() {
		os.Exit(0)
	}

	tmpDir, err := ioutil.TempDir("", "")
	if err != nil {
		panic("Failed to get temp dir.")
	}

	buckets.RegisterProvider(Scheme, New())
	result := m.Run()

	os.RemoveAll(tmpDir)
	os.Exit(result)
}
