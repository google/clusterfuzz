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

// Package buckets provides interfaces for interacting with cloud buckets.
package buckets

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net/url"
	"os"

	"github.com/pkg/errors"
)

var (
	// providers is the global map of scheme -> Providers.
	providers = make(map[string]Provider)
)

// ObjectIterator is an iterator interface for objects.
type ObjectIterator interface {
	Next(info *ObjectInfo) bool
	Err() error
}

// ObjectInfo contains metadata about an object.
type ObjectInfo struct {
	// Bucket of the object.
	Bucket string

	// Name of the object.
	Name string

	// Scheme of the object.
	Scheme string

	// Size of the object.
	Size uint64

	// Whether or not this refers to an actual object. This will be false
	// for directory prefixes.
	IsObject bool
}

// Provider is a interface for accessing cloud buckets.
type Provider interface {
	// ReadObject returns an io.Reader for the remote object.
	ReadObject(ctx context.Context, bucket, path string) (io.ReadCloser, error)

	// WriteObject returns an io.WriteCloser object which can be used to
	// write data to the object.
	WriteObject(ctx context.Context, bucket, path string) (io.WriteCloser, error)

	// StatObject returns information about the remote object. Returns nil if
	// the object does not exist.
	StatObject(ctx context.Context, bucket, path string) (*ObjectInfo, error)

	// ListObjects iterates through objects in the bucket.
	ListObjects(ctx context.Context, bucket, path string, recursive bool) (ObjectIterator, error)
}

// BuildURL returns an URL constructed using the given components.
func BuildURL(scheme, bucket, name string) string {
	return fmt.Sprintf("%s://%s/%s", scheme, bucket, name)
}

// FullPath returns a full path for the object given its ObjectInfo.
func (i *ObjectInfo) FullPath() string {
	return BuildURL(i.Scheme, i.Bucket, i.Name)
}

// parseRemotePath returns the scheme, bucket name and path given a full
// scheme://bucket/object path.
func parseRemotePath(remotePath string) (string, string, string, error) {
	parsed, err := url.Parse(remotePath)
	if err != nil {
		return "", "", "", errors.Wrap(err, "invalid bucket path")
	}

	// Remove slash.
	path := parsed.Path[1:]
	return parsed.Scheme, parsed.Host, path, nil
}

// getProvider returns the bucket provider for the given scheme.
func getProvider(scheme string) (Provider, error) {
	provider, ok := providers[scheme]
	if !ok {
		return nil, errors.New("no bucket provider for scheme " + scheme)
	}

	return provider, nil
}

// deconstructRemotePath returns a bucket provider, bucket name, and the path
// for the given bucket.
func deconstructRemotePath(remotePath string) (Provider, string, string, error) {
	scheme, bucket, path, err := parseRemotePath(remotePath)
	if err != nil {
		return nil, "", "", err
	}

	provider, err := getProvider(scheme)
	if err != nil {
		return nil, "", "", err
	}

	return provider, bucket, path, nil
}

// RegisterProvider registers a new bucket provider.
func RegisterProvider(scheme string, provider Provider) {
	providers[scheme] = provider
}

// CopyObjectFrom copies a remote object to a local path.
func CopyObjectFrom(ctx context.Context, remotePath, localPath string) error {
	provider, bucket, path, err := deconstructRemotePath(remotePath)
	if err != nil {
		return err
	}
	reader, err := provider.ReadObject(ctx, bucket, path)
	if err != nil {
		return err
	}
	defer reader.Close()

	file, err := os.Create(localPath)
	if err != nil {
		return errors.Wrap(err, "file creation failed")
	}
	defer file.Close()

	_, err = io.Copy(file, reader)
	return errors.Wrap(err, "copy failed")
}

// CopyObjectTo copies a local object to a remote path.
func CopyObjectTo(ctx context.Context, localPath, remotePath string) error {
	provider, bucket, path, err := deconstructRemotePath(remotePath)
	if err != nil {
		return err
	}

	writer, err := provider.WriteObject(ctx, bucket, path)
	if err != nil {
		return err
	}
	defer writer.Close()

	file, err := os.Open(localPath)
	if err != nil {
		return errors.Wrap(err, "file open failed")
	}
	defer file.Close()

	_, err = io.Copy(writer, file)
	return errors.Wrap(err, "copy failed")
}

// CopyObjectFromWithCache copies a remote object to a local path (cached version).
func CopyObjectFromWithCache(ctx context.Context, remotePath, localPath string) error {
	// TODO(ochang): Cache.
	return CopyObjectFrom(ctx, remotePath, localPath)
}

// CopyObjectToWithCache copies a local object to a remote path (cached version).
func CopyObjectToWithCache(ctx context.Context, localPath, remotePath string) error {
	// TODO(ochang): Cache.
	return CopyObjectTo(ctx, localPath, remotePath)
}

// ReadObject returns an io.ReadCloser for the remote object.
func ReadObject(ctx context.Context, remotePath string) (io.ReadCloser, error) {
	provider, bucket, path, err := deconstructRemotePath(remotePath)
	if err != nil {
		return nil, err
	}

	return provider.ReadObject(ctx, bucket, path)
}

// ReadObjectBytes reads a remote object and returns the contents.
func ReadObjectBytes(ctx context.Context, remotePath string) ([]byte, error) {
	reader, err := ReadObject(ctx, remotePath)
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	data, err := ioutil.ReadAll(reader)
	return data, errors.Wrap(err, "read failed")
}

// WriteObject returns an io.WriteCloser for the remote object.
func WriteObject(ctx context.Context, remotePath string) (io.WriteCloser, error) {
	provider, bucket, path, err := deconstructRemotePath(remotePath)
	if err != nil {
		return nil, err
	}

	return provider.WriteObject(ctx, bucket, path)
}

// WriteObjectBytes writes a remote object with specified contents.
func WriteObjectBytes(ctx context.Context, remotePath string, data []byte) error {
	writer, err := WriteObject(ctx, remotePath)
	if err != nil {
		return err
	}

	_, err = writer.Write(data)
	if err != nil {
		return errors.Wrap(err, "wrap failed")
	}

	return writer.Close()
}

// StatObject returns information about the remote object.
func StatObject(ctx context.Context, remotePath string) (*ObjectInfo, error) {
	provider, bucket, path, err := deconstructRemotePath(remotePath)
	if err != nil {
		return nil, err
	}
	return provider.StatObject(ctx, bucket, path)
}

// ListObjects lists keys in the bucket.
func ListObjects(ctx context.Context, remotePath string, recursive bool) (ObjectIterator, error) {
	provider, bucket, path, err := deconstructRemotePath(remotePath)
	if err != nil {
		return nil, err
	}
	return provider.ListObjects(ctx, bucket, path, recursive)
}
