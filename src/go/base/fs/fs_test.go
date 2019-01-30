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

package fs

import (
	"io/ioutil"
	"log"
	"os"
	"path"
	"reflect"
	"sort"
	"testing"
)

var (
	tempDir string
)

func TestCreateDirectoryNew(t *testing.T) {
	dirPath := path.Join(tempDir, "TestCreateDirectoryNew")
	err := CreateDirectoryIfNeeded(dirPath, false)
	if err != nil {
		t.Errorf("CreateDirectoryIfNeeded got an error: %s", err)
	}

	info, err := os.Stat(dirPath)
	if err != nil {
		t.Errorf("Failed to stat %s: %s", dirPath, err)
	}

	if !info.IsDir() {
		t.Errorf("%s is not a directory", dirPath)
	}
}

func TestCreateDirectoryIntermediate(t *testing.T) {
	dirPath := path.Join(tempDir, "a", "b", "c", "CreateDirectoryIntermediate")
	err := CreateDirectoryIfNeeded(dirPath, false)
	if err == nil {
		t.Errorf("CreateDirectoryIfNeeded expected an error")
	}

	err = CreateDirectoryIfNeeded(dirPath, true)
	if err != nil {
		t.Errorf("CreateDirectoryIfNeeded got an error: %s", err)
	}

	info, err := os.Stat(dirPath)
	if err != nil {
		t.Errorf("Failed to stat %s: %s", dirPath, err)
	}

	if !info.IsDir() {
		t.Errorf("%s is not a directory", dirPath)
	}
}

func createTestDir(dirPath string) {
	os.Mkdir(dirPath, 0755)
	file1 := path.Join(dirPath, "1")
	file2 := path.Join(dirPath, "2")

	os.Mkdir(path.Join(dirPath, "sub"), 0755)

	file3 := path.Join(dirPath, "sub", "3")

	ioutil.WriteFile(file1, []byte("file1"), 0755)
	ioutil.WriteFile(file2, []byte("file2"), 0755)
	ioutil.WriteFile(file3, []byte("file3"), 0755)
}

func TestRemoveDirectory(t *testing.T) {
	dirPath := path.Join(tempDir, "TestRemoveDirectory")
	createTestDir(dirPath)

	err := RemoveDirectory(dirPath, false)
	if err != nil {
		t.Errorf("RemoveDirectory got an error: %s", err)
	}

	_, err = os.Stat(dirPath)
	if err == nil || !os.IsNotExist(err) {
		t.Errorf("Failed to remove directory")
	}

	createTestDir(dirPath)
	err = RemoveDirectory(dirPath, true)
	if err != nil {
		t.Errorf("RemoveDirectory got an error: %s", err)
	}

	files, err := ioutil.ReadDir(dirPath)
	if err != nil {
		t.Errorf("Failed to read recreated dir: %s", err)
	}

	if len(files) > 0 {
		t.Errorf("Recreated directory not empty")
	}
}

func TestListFiles(t *testing.T) {
	dirPath := path.Join(tempDir, "TestListFiles")
	createTestDir(dirPath)

	paths, err := ListFiles(dirPath)
	if err != nil {
		t.Errorf("ListFiles got an error: %s", err)
	}

	sort.Strings(paths)
	expected := []string{
		path.Join(dirPath, "1"),
		path.Join(dirPath, "2"),
		path.Join(dirPath, "sub"),
	}
	result := reflect.DeepEqual(paths, expected)

	if !result {
		t.Errorf("Wrong result from ListFiles: got %v, expected %v", paths, expected)
	}
}

func TestListFilesRecursive(t *testing.T) {
	dirPath := path.Join(tempDir, "TestListFilesRecursive")
	createTestDir(dirPath)

	paths, err := ListFilesRecursive(dirPath)
	if err != nil {
		t.Errorf("ListFilesRecursive got an error: %s", err)
	}

	sort.Strings(paths)
	expected := []string{
		path.Join(dirPath, "1"),
		path.Join(dirPath, "2"),
		path.Join(dirPath, "sub", "3"),
	}
	result := reflect.DeepEqual(paths, expected)

	if !result {
		t.Errorf("Wrong result from ListFilesRecursive: got %v, expected %v", paths, expected)
	}
}

func TestPathExists(t *testing.T) {
	dirPath := path.Join(tempDir, "TestListFilesRecursive")
	createTestDir(dirPath)

	testPath := path.Join(dirPath, "1")
	if !PathAccessible(testPath) {
		t.Errorf("Expected %s to exist", testPath)
	}

	testPath = path.Join(dirPath, "blah")
	if PathAccessible(testPath) {
		t.Errorf("Expected %s to not exist", testPath)
	}

}

func TestMain(m *testing.M) {
	tempDir, err := ioutil.TempDir("", "")
	if err != nil {
		log.Panicf("Failed to create temp dir: %s", err)
	}

	result := m.Run()
	os.RemoveAll(tempDir)

	os.Exit(result)
}
