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

// Package persist implements a persistent cache.
package persist

import (
	"crypto/sha1"
	"encoding/hex"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"

	"github.com/pkg/errors"

	"clusterfuzz/go/base/environ"
	"clusterfuzz/go/base/fs"
	"clusterfuzz/go/base/logs"
)

const (
	persistFileExtension = ".persist"
)

// Initialize initializes the persistent cahce.
func Initialize() error {
	cacheDir := environ.GetValueStr("CACHE_DIR")
	if fs.PathAccessible(cacheDir) {
		return clearValues(cacheDir)
	}

	return fs.CreateDirectoryIfNeeded(cacheDir, true)
}

// clearValues clears the values in the persistent cache.
func clearValues(cacheDir string) error {
	return filepath.Walk(cacheDir, func(curPath string, info os.FileInfo, err error) error {
		if err != nil {
			return errors.Wrap(err, "Failed to walk")
		}

		if path.Ext(curPath) == persistFileExtension {
			return nil
		}

		persistFilePath := curPath + persistFileExtension
		if fs.PathAccessible(persistFilePath) {
			// Skip values which persist across reboots.
			return nil
		}

		return errors.Wrap(os.Remove(curPath), "Failed to remove")
	})
}

// valueFilePath returns the full file path to the value file for the given key.
func valueFilePath(key string) string {
	hashBytes := sha1.New().Sum([]byte(key))
	hexValue := hex.EncodeToString(hashBytes)

	cacheDir := environ.GetValueStr("CACHE_DIR")
	return path.Join(cacheDir, ".cache."+string(hexValue))
}

// HasValue whether or not the key exists.
func HasValue(key string) bool {
	valuePath := valueFilePath(key)
	return fs.PathAccessible(valuePath)
}

// GetValueStr returns the string value for the given key.
func GetValueStr(key string) string {
	valuePath := valueFilePath(key)
	result, err := ioutil.ReadFile(valuePath)

	if os.IsNotExist(err) {
		return ""
	}

	if err != nil {
		logs.Panicf("Failed to read persistent cache value for %s: %+v", valuePath, err)
	}

	return string(result)
}

// GetValueUint returns the uint64 value for the given key.
func GetValueUint(key string) uint64 {
	return environ.ParseUint(GetValueStr(key))
}

// GetValueInt returns the int64 value for the given key.
func GetValueInt(key string) int64 {
	return environ.ParseInt(GetValueStr(key))
}

// GetValueFloat returns the float64 value for the given key.
func GetValueFloat(key string) float64 {
	return environ.ParseFloat(GetValueStr(key))
}

// GetValueBool returns the bool value for the given key.
func GetValueBool(key string) bool {
	return environ.ParseBool(GetValueStr(key))
}

// SetValue sets a value in the persistent cache.
func SetValue(key string, value interface{}) {
	valuePath := valueFilePath(key)
	err := ioutil.WriteFile(valuePath, []byte(environ.ValueToStr(value)), 0644)
	if err != nil {
		logs.Panicf("Failed to set persistent cache value for %s: %+v", valuePath, err)
	}
}

// SetValuePersistsOnReboot sets a value in the persistent cache that persists
// even on reboots.
func SetValuePersistsOnReboot(key string, value interface{}) {
	SetValue(key, value)

	valuePath := valueFilePath(key)
	persistFilePath := valuePath + persistFileExtension

	err := ioutil.WriteFile(persistFilePath, []byte{}, 0644)
	if err != nil {
		logs.Panicf("Failed to write persistent file %s: %+v", persistFilePath, err)
	}
}

// DeleteValue deletes a value from the persistent cache.
func DeleteValue(key string) {
	if !HasValue(key) {
		return
	}

	valuePath := valueFilePath(key)
	err := os.Remove(valuePath)
	if err != nil {
		logs.Panicf("Failed to remove persistent cache value: %s: %+v", valuePath, err)
	}
}
