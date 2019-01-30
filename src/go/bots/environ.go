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

// Package bots implements base functionality used by bots.
package bots

import (
	"io/ioutil"
	"os"
	"path"
	"strings"

	"clusterfuzz/go/base/environ"
	"clusterfuzz/go/base/logs"
)

// SetUpEnvironment sets up the bot environment variables.
func SetUpEnvironment() {
	if !environ.HasValue("BOT_NAME") {
		hostname, err := os.Hostname()
		if err != nil {
			logs.Panicf("Failed to get hostname: %+v\n", err)
		}

		environ.SetValue("BOT_NAME", strings.ToLower(hostname))
	}

	botDir := path.Join(RootDir(), "bot")
	inputsDir := path.Join(botDir, "inputs")
	logDir := path.Join(botDir, "logs")
	cacheDir := path.Join(botDir, "cache")

	environ.SetValue("CACHE_DIR", cacheDir)
	environ.SetValue("LOG_DIR", logDir)
	environ.SetValue("FUZZ_INPUTS", path.Join(inputsDir, "fuzzer-testcases"))
	environ.SetValue("FUZZ_INPUTS_DISK", path.Join(inputsDir, "fuzzer-testcases-disk"))
}

// RootDir returns the root directory of the bot.
func RootDir() string {
	return environ.GetValueStrOrPanic("ROOT_DIR")
}

// BotName returns the name of the bot.
func BotName() string {
	return environ.GetValueStrOrPanic("BOT_NAME")
}

// TaskPayload returns the current task payload.
func TaskPayload() string {
	return environ.GetValueStr("TASK_PAYLOAD")
}

// LogDir returns the current log directory.
func LogDir() string {
	return environ.GetValueStrOrPanic("LOG_DIR")
}

// CurrentSourceVersion returns the current source version."""
func CurrentSourceVersion() string {
	if environ.HasValue("SOURCE_VERSION_OVERRIDE") {
		return environ.GetValueStr("SOURCE_VERSION_OVERRIDE")
	}

	manifestPath := path.Join(RootDir(), "src", "appengine", "resources", "clusterfuzz-source.manifest")
	result, err := ioutil.ReadFile(manifestPath)

	if err != nil {
		logs.Panicf("Failed to get current source version: %v", err)
	}

	return string(result)
}
