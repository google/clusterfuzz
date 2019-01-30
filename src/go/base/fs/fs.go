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

// Package fs implements various helpers for dealing with the filesystem.
package fs

import (
	"io/ioutil"
	"os"
	"path"
	"path/filepath"

	"github.com/pkg/errors"
)

// CreateDirectoryIfNeeded creates a directory if it does not exist already.
func CreateDirectoryIfNeeded(path string, createIntermediates bool) error {
	info, err := os.Stat(path)
	if err == nil {
		if info.IsDir() {
			return nil
		}

		return errors.Errorf("%s exists, but isn't a directory", path)
	}

	if os.IsNotExist(err) {
		if createIntermediates {
			return errors.Wrap(os.MkdirAll(path, 0755), "MkdirAll failed")
		}

		return errors.Wrap(os.Mkdir(path, 0755), "Mkdir failed")
	}

	return errors.Wrap(err, "stat failed")
}

// RemoveDirectory removes a directory, optionally recreating it.
func RemoveDirectory(path string, recreate bool) error {
	// TODO(ochang): Implement platform specific hacks.
	if err := os.RemoveAll(path); err != nil {
		return errors.Wrap(err, "RemoveAll failed")
	}

	if recreate {
		return errors.Wrap(os.Mkdir(path, 0755), "Mkdir failed")
	}
	return nil
}

// ClearDirectory clears a directory's contents.
func ClearDirectory(dirPath string) error {
	dir, err := os.Open(dirPath)
	if err != nil {
		return errors.Wrap(err, "Open failed")
	}
	defer dir.Close()

	items, err := dir.Readdirnames(-1)
	if err != nil {
		return errors.Wrap(err, "Readdirnames failed")
	}

	firstErr := error(nil)
	for _, item := range items {
		err = os.RemoveAll(path.Join(dirPath, item))
		if err != nil && firstErr == nil {
			firstErr = errors.Wrap(err, "RemoveAll failed")
		}
	}

	return firstErr
}

// ListFilesRecursive returns a list of files (not including directories) in
// the directory recursively.
func ListFilesRecursive(dirPath string) ([]string, error) {
	var filePaths []string

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			filePaths = append(filePaths, path)
		}

		return errors.Wrap(err, "walk failed")
	})
	return filePaths, errors.Wrap(err, "wail failed")
}

// ListFiles returns a list of files and directories in the directory
// (non-recursive).
func ListFiles(dirPath string) ([]string, error) {
	var filePaths []string

	infos, err := ioutil.ReadDir(dirPath)
	if err != nil {
		return nil, errors.Wrap(err, "ReadDir failed")
	}

	for _, info := range infos {
		filePaths = append(filePaths, path.Join(dirPath, info.Name()))
	}
	return filePaths, nil
}

// PathAccessible returns whether or not the given path exists and is
// accessible.
func PathAccessible(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
