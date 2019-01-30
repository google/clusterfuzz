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

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/shirou/gopsutil/process"

	"clusterfuzz/go/base/logs"
	"clusterfuzz/go/base/persist"
	baseProc "clusterfuzz/go/base/process"
	"clusterfuzz/go/bots"
	"clusterfuzz/go/bots/tasks"
	"clusterfuzz/go/cloud/db"
	"clusterfuzz/go/cloud/db/types"
	"clusterfuzz/go/cloud/stackdriver"
)

const (
	heartbeatWaitInterval = 10 * time.Minute
	heartbeatUpdateKey    = "heartbeat_update"
)

// updateHeartbeat updates the heartbeat entity.
func updateHeartbeat() error {
	now := time.Now()

	// Check if heartbeat was recently updated and bail out if so.
	if persist.HasValue(heartbeatUpdateKey) {
		lastModTime := time.Unix(persist.GetValueInt(heartbeatUpdateKey), 0)
		if now.Before(lastModTime.Add(heartbeatWaitInterval)) {
			return nil
		}
	}

	key := datastore.NameKey("Heartbeat", bots.BotName(), nil)

	ctx := context.Background()
	var heartbeat types.Heartbeat

	err := db.Get(ctx, key, &heartbeat)
	if err != nil && !db.IsNoSuchEntityError(err) {
		return err
	}

	heartbeat.BotName = bots.BotName()
	heartbeat.TaskPayload = tasks.CurrentTaskPayload()
	heartbeat.TaskEndTime = tasks.CurrentTaskEndTime()
	heartbeat.LastBeatTime = now
	heartbeat.SourceVersion = bots.CurrentSourceVersion()

	_, err = db.Put(ctx, key, &heartbeat)
	if err != nil {
		return err
	}

	persist.SetValue(heartbeatUpdateKey, now.Unix())
	return nil
}

// killStuckTask kills the current bot instance if the task is stuck.
func killStuckTask() error {
	if !tasks.IsTaskRunning() {
		return nil
	}

	taskEndTime := tasks.CurrentTaskEndTime()
	if time.Now().Before(taskEndTime.Add(tasks.TaskCompletionBuffer)) {
		return nil
	}

	botFilePath := path.Join(bots.RootDir(), "src", "bot", "run_bot")
	procs, err := process.Processes()
	if err != nil {
		return err
	}

	for _, proc := range procs {
		cmdline, err := proc.Cmdline()
		if err != nil {
			logs.Warnf("Failed to get cmdline for process: %v", err)
			continue
		}

		if strings.Contains(cmdline, botFilePath) {
			logs.Logf("Killing stale bot (pid=%d, cmd=%s) which seems to be stuck.", proc.Pid, cmdline)
			err = baseProc.KillTree(proc.Pid)
			if err != nil {
				logs.Errorf("Failed to kill process %d: %+v", proc.Pid, err)
			}
		}
	}

	tasks.TrackTaskEnd()
	err = bots.ClearTempDirectories(true)
	if err != nil {
		return err
	}

	return bots.ClearTestcaseDirectories()
}

// beat does a heartbeat.
func beat(prevState int64, logFilename string) (int64, error) {
	logs.Logf("Beat for logging pipeline.")

	err := killStuckTask()
	if err != nil {
		return 0, err
	}

	logStat, err := os.Stat(logFilename)
	if err != nil {
		return 0, err
	}

	curState := logStat.ModTime().Unix()
	logs.Logf("Old state %d, new state %d.", prevState, curState)
	if curState != prevState {
		logs.Logf("State updated.")
		return curState, updateHeartbeat()
	}

	return curState, nil
}

func main() {
	flag.Parse()
	if flag.NArg() != 2 {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s prev_state log_path", os.Args[0])
		os.Exit(1)
	}

	bots.SetUpEnvironment()
	db.Init()

	logPath := path.Join(bots.LogDir(), "heartbeat_go.log")
	logger, err := stackdriver.Create(logPath)
	if err != nil {
		logs.Panicf("Failed to create logger: %+v", err)
	}
	logs.Init(logger)

	prevState, err := strconv.ParseInt(flag.Arg(0), 10, 64)
	if err != nil {
		logs.Panicf("Failed to parse previous state %s: %v.", flag.Arg(0), err)
	}

	logFilename := flag.Arg(1)
	result, err := beat(prevState, logFilename)

	if err != nil {
		logs.Errorf("Failed to beat: %+v.", err)
	} else {
		fmt.Printf("%d", result)
	}
	time.Sleep(heartbeatWaitInterval)
}
