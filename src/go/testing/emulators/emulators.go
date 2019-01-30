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

// Package emulators provides utilities for starting Google Cloud emulators.
package emulators

import (
	"bufio"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

const (
	emulatorTimeout = 10 * time.Second
)

var (
	readyIndicators = map[string]string{
		"datastore": "is now running",
		"pubsub":    "Server started",
	}

	defaultEmulatorArgs = map[string][]string{
		"datastore": []string{"--consistency=1.0"},
		"pubsub":    nil,
	}
)

// EmulatorState represents an instance of a running emulator.
type EmulatorState struct {
	dataDir string
	process *os.Process
}

func setOutputPipes(cmd *exec.Cmd) io.ReadCloser {
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Panicf("Failed to create pipe: %v", err)
	}
	cmd.Stderr = cmd.Stdout
	return stdout
}

func setEnv(emulator, tempDir string) {
	cmd := exec.Command("gcloud", "beta", "emulators", emulator, "env-init", "--data-dir="+tempDir)
	stdout := setOutputPipes(cmd)

	err := cmd.Start()
	if err != nil {
		log.Panicf("Failed to run env-init: %v\n", err)
	}

	reader := bufio.NewReader(stdout)
	exportPattern := regexp.MustCompile("export\\s*([^\\s]+)=([^\\s]+)")
	for {
		line, err := reader.ReadString('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Panicf("Failed to read from env-init: %v", err)
		}

		match := exportPattern.FindStringSubmatch(line)
		if match != nil && match[1] != "" {
			os.Setenv(match[1], match[2])
			log.Printf("setting %s %s\n", match[1], match[2])
		}
	}

	err = cmd.Wait()
	if err != nil {
		log.Panicf("env-init returned error: %v", err)
	}
}

// Start starts the specified emulator.
func Start(emulator string, args []string) *EmulatorState {
	tempDir, err := ioutil.TempDir("", "")
	if err != nil {
		log.Panicf("Failed to create temp dir: %v", err)
	}

	emulatorArgs := []string{
		"beta", "emulators", emulator, "start", "--data-dir=" + tempDir,
	}

	defaultArgs := defaultEmulatorArgs[emulator]
	if defaultArgs != nil {
		emulatorArgs = append(emulatorArgs, defaultArgs...)
	}

	if args != nil {
		emulatorArgs = append(emulatorArgs, args...)
	}

	cmd := exec.Command("gcloud", emulatorArgs...)
	stdout := setOutputPipes(cmd)

	err = cmd.Start()
	if err != nil {
		log.Panicf("Failed to start emulator process: %v", err)
	}

	ready := make(chan bool)
	go func() {
		reader := bufio.NewReader(stdout)
		for {
			line, err := reader.ReadString('\n')
			log.Print(line)
			if err == io.EOF {
				break
			}
			if err != nil {
				log.Panicf("Failed to read from emulator stdout: %v", err)
			}

			if strings.Contains(line, readyIndicators[emulator]) {
				ready <- true
				break
			}
		}

		stdout.Close()
	}()

	select {
	case <-ready:
	case <-time.After(emulatorTimeout):
		log.Panicf("Failed to start %s emulator in time.", emulator)
	}

	setEnv(emulator, tempDir)
	return &EmulatorState{
		dataDir: tempDir,
		process: cmd.Process,
	}
}

// Cleanup cleans up the emulator state.
func Cleanup(state *EmulatorState) {
	state.process.Kill()

	err := os.RemoveAll(state.dataDir)
	if err != nil {
		log.Panicf("Failed to remove emulator data dir: %v", err)
	}
}
