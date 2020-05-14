// Copyright 2019 Google LLC
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

package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/pkg/errors"

	"clusterfuzz/go/base/environ"
)

const (
	// This directory contains purely test configs.
	testDataDir = "testdata"
)

var (
	cfg *Config

	// This is used to preserve path to config directory with valid test configs.
	cfgDirOverride string
)

func assertEqual(t *testing.T, expected, actual interface{}) {
	if expected != actual {
		// Create an error object to catch the stacktrace when logging a failure.
		err := errors.Errorf("Expected: %s\nActual: %s\n", expected, actual)
		t.Fatalf("%+v", err)
	}
}

func assertEqualMaps(t *testing.T, expected, actual map[string]interface{}) {
	if !reflect.DeepEqual(expected, actual) {
		// Create an error object to catch the stacktrace when logging a failure.
		err := errors.Errorf("Expected: %s\nActual: %s\n", expected, actual)
		t.Fatalf("%+v", err)
	}
}

func assertEqualNodes(t *testing.T, expected, actual *Node) {
	if expected != actual {
		// Create an error object to catch the stacktrace when logging a failure.
		err := errors.Errorf("Expected: %s\nActual: %s\n", expected, actual)
		t.Fatalf("%+v", err)
	}
}

func assertEqualSlices(t *testing.T, expected, actual []interface{}) {
	if !reflect.DeepEqual(expected, actual) {
		// Create an error object to catch the stacktrace when logging a failure.
		err := errors.Errorf("Expected: %s\nActual: %s\n", expected, actual)
		t.Fatalf("%+v", err)
	}
}

func assertErrorPrefix(t *testing.T, err error, prefix string) {
	if !strings.HasPrefix(err.Error(), prefix) {
		t.Fatalf("Expected error with '%s' prefix, got: %+v", prefix, err)
	}
}

func assertNoError(t *testing.T, err error) {
	if err != nil {
		t.Fatalf("Unexpected error: %+v", err)
	}
}

func assertPanic(t *testing.T, prefix string, fn func()) {
	defer func() {
		err := recover()
		if err != nil && !strings.HasPrefix(err.(string), prefix) {
			t.Fatalf("Expected panic with '%s' prefix, got: '%+v'", prefix, err)
		}
	}()

	fn()

	t.Fatalf("Expected panic with '%s' prefix, didn't panic at all", prefix)
}

func TestGetWithNonExistentConfigsDirectory(t *testing.T) {
	origConfigDir := environ.GetValueStr("CONFIG_DIR_OVERRIDE")
	environ.SetValue("CONFIG_DIR_OVERRIDE", "non-existent")
	assertPanic(t, "invalid config directory", func() {
		_ = New("")
	})

	environ.SetValue("CONFIG_DIR_OVERRIDE", origConfigDir)
}

func TestGetWithInvalidKeyName(t *testing.T) {
	_, err := cfg.getNode("")
	assertErrorPrefix(t, err, "invalid config key")
}

func TestGetWithBadYamlFile(t *testing.T) {
	_, err := cfg.getNode("bad")
	assertErrorPrefix(t, err, "failed to parse yaml config contents")
}

func TestGetWithRootYamlFile(t *testing.T) {
	actualMap := cfg.GetMap("a")
	expectedMap := map[string]interface{}{
		"b": map[interface{}]interface{}{
			"c": "d",
			"e": 1,
		},
	}
	assertEqualMaps(t, expectedMap, actualMap)

	actualMap = cfg.GetMap("a.b")
	expectedMap = map[string]interface{}{
		"c": "d",
		"e": 1,
	}
	assertEqualMaps(t, expectedMap, actualMap)

	actualString := cfg.GetString("a.b.c")
	assertEqual(t, "d", actualString)

	actualInt := cfg.GetInt("a.b.e")
	assertEqual(t, 1, actualInt)

	actualString = cfg.GetAbsPath("a.b.e")
	expectedString := filepath.Join(testDataDir, "1")
	assertEqual(t, expectedString, actualString)
}

func TestGetWithSubfolderYamlFile(t *testing.T) {
	// Use aa/bb/cc.yaml.
	actualMap := cfg.GetMap("aa.bb.cc")
	expectedMap := map[string]interface{}{
		"dd": "ee",
	}
	assertEqualMaps(t, expectedMap, actualMap)

	actualString := cfg.GetString("aa.bb.cc.dd")
	assertEqual(t, "ee", actualString)

	actualString = cfg.GetAbsPath("aa.bb.cc.dd")
	expectedString := filepath.Join(testDataDir, "aa", "bb", "ee")
	assertEqual(t, expectedString, actualString)

	_, err := cfg.getNode("ambiguous.a")
	assertErrorPrefix(t, err, "invalid config key")
}

func TestGetWithSubConfig(t *testing.T) {
	mainConfig := New("")
	subConfig := mainConfig.SubConfig("aa.bb.cc")
	actualString := subConfig.GetString("dd")
	assertEqual(t, "ee", actualString)
	actualMap := subConfig.GetMap("")
	expectedMap := map[string]interface{}{
		"dd": "ee",
	}
	assertEqualMaps(t, expectedMap, actualMap)

	mainConfig = New("aa")
	subConfig = mainConfig.SubConfig("bb.cc")
	actualString = subConfig.GetString("dd")
	assertEqual(t, "ee", actualString)
	actualMap = subConfig.GetMap("")
	expectedMap = map[string]interface{}{
		"dd": "ee",
	}
	assertEqualMaps(t, expectedMap, actualMap)

	mainConfig = New("aa.bb")
	subConfig = mainConfig.SubConfig("cc")
	actualString = subConfig.GetString("dd")
	assertEqual(t, "ee", actualString)
	actualMap = subConfig.GetMap("")
	expectedMap = map[string]interface{}{
		"dd": "ee",
	}
	assertEqualMaps(t, expectedMap, actualMap)
}

func TestGetWithInvalidKeys(t *testing.T) {
	// Invalid keys, these are actually values.
	assertPanic(t, "failed to convert yaml node to", func() {
		_ = cfg.GetString("aa.bb.cc.dd.ee")
	})
}

func TestHasValue(t *testing.T) {
	assertEqual(t, true, cfg.HasValue("aa.bb.cc"))
	assertEqual(t, false, cfg.HasValue("ambiguous.a"))
}

func TestRootValidation(t *testing.T) {
	_ = New("")
	_ = New("a")
	_ = New("aa")
	_ = New("aa.bb")
	_ = New("aa.bb.cc")
	_ = New("aa.bb.cc.dd")

	assertPanic(t, "bad config", func() {
		_ = New("aa.b")
	})

	assertPanic(t, "bad config", func() {
		_ = New("aa.bb.c")
	})

	assertPanic(t, "bad config", func() {
		_ = New("aa.bb.cc.d")
	})

	assertPanic(t, "failed to convert yaml node to", func() {
		_ = New("aa.bb.cc.dd.ee")
	})
}

func TestSetEnvironmentWithoutDefault(t *testing.T) {
	// Test that SetEnvironment initializes env variables specified in the config.
	restoreConfigDirOverride()

	err := os.Unsetenv("PROJECT_NAME")
	assertNoError(t, err)
	err = os.Unsetenv("APPLICATION_ID")
	assertNoError(t, err)

	projectConfig := NewProjectConfig()
	projectConfig.SetEnvironment()

	value := environ.GetValueStr("PROJECT_NAME")
	assertEqual(t, "test-project", value)

	value = environ.GetValueStr("APPLICATION_ID")
	assertEqual(t, "test-clusterfuzz", value)

	setConfigDirOverrideForTesting()
}

func TestSetEnvironmentWithDefault(t *testing.T) {
	// Test that SetEnvironment does not overwrite env variables that are set up.
	restoreConfigDirOverride()

	environ.SetValue("ISSUE_TRACKER", "test-issue-tracker-override")
	environ.SetValue("UPDATE_WEB_TESTS", true)

	// This config does not have "env" value specified.
	projectConfig := NewProjectConfig()
	projectConfig.SetEnvironment()

	value := environ.GetValueStr("PROJECT_NAME")
	assertEqual(t, "test-project", value)

	value = environ.GetValueStr("ISSUE_TRACKER")
	assertEqual(t, "test-issue-tracker-override", value)

	flag := environ.GetValueBool("UPDATE_WEB_TESTS")
	assertEqual(t, true, flag)

	setConfigDirOverrideForTesting()
}

func restoreConfigDirOverride() {
	environ.SetValue("CONFIG_DIR_OVERRIDE", cfgDirOverride)
}

func setConfigDirOverrideForTesting() {
	environ.SetValue("CONFIG_DIR_OVERRIDE", testDataDir)
}

func TestMain(m *testing.M) {
	cfgDirOverride = environ.GetValueStr("CONFIG_DIR_OVERRIDE")
	setConfigDirOverrideForTesting()
	cfg = New("")

	result := m.Run()
	os.Exit(result)
}
