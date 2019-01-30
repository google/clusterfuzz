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

// Package fuzzers implements builtin fuzzers and related helpers.
package fuzzers

import (
	"bufio"
	"bytes"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"clusterfuzz/go/base/fs"
)

var (
	allowedFuzzTargetExtensions = map[string]bool{
		"":     true,
		".exe": true,
	}
	fuzzTargetSearchBytes = []byte("LLVMFuzzerTestOneInput")
)

const (
	validFuzzTargetRegex = "^[a-zA-Z0-9_-]+$"
)

// fileContains returns whether or not the file at the given path contains the
// given string. Assumes that the file exists and can be read.
func fileContains(path string, search []byte) bool {
	// TODO(ochang): Don't read line by line, and move to a more general location.
	f, err := os.Open(path)
	if err != nil {
		log.Panic("Failed to open file:", path)
	}

	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		if bytes.Contains(scanner.Bytes(), search) {
			return true
		}
	}

	return false

}

// IsFuzzTarget returns whether or not the given path is a path to a
// libFuzzer-style fuzz target.
func IsFuzzTarget(path string) bool {
	filename := filepath.Base(path)
	ext := filepath.Ext(filename)
	basename := strings.TrimSuffix(filename, ext)

	matched, err := regexp.MatchString(validFuzzTargetRegex, basename)
	if !matched || err != nil {
		return false
	}

	if _, exists := allowedFuzzTargetExtensions[ext]; !exists {
		return false
	}

	if !fs.PathAccessible(path) {
		return false
	}

	if strings.HasSuffix(basename, "_fuzzer") {
		return true
	}

	return fileContains(path, fuzzTargetSearchBytes)

}

// GetFuzzTargets returns a list of paths to fuzz targets in the given
// directory.
func GetFuzzTargets(dir string) ([]string, error) {
	var targets []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && IsFuzzTarget(path) {
			targets = append(targets, path)
		}

		return err
	})
	return targets, err
}
