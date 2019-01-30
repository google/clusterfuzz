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

// Package stackdriver implements logging using Stackdriver.
package stackdriver

import (
	"context"
	"fmt"
	"os"

	"cloud.google.com/go/compute/metadata"
	"cloud.google.com/go/logging"
	"google.golang.org/genproto/googleapis/api/monitoredres"

	"clusterfuzz/go/base/logs"
	"clusterfuzz/go/bots"
	"clusterfuzz/go/cloud"
)

// Logger is an implementation of a logs.Logger that sends logs to StackDriver.
type Logger struct {
	cloudLogger *logging.Logger
	baseLogger  logs.Logger
}

// Payload represents the log payload that we send.
type Payload struct {
	Message     string `json:"message"`
	BotName     string `json:"bot_name"`
	TaskPayload string `json:"task_payload"`
}

// Create creates a logger.
func Create(localPath string) (*Logger, error) {
	if metadata.OnGCE() {
		return createGCE(localPath)
	}

	return createGeneric(localPath)
}

// createCommon creates and returns a new logger.
func createCommon(localPath string, resource *monitoredres.MonitoredResource) (*Logger, error) {
	client, err := logging.NewClient(context.Background(), cloud.ProjectID())
	if err != nil {
		return nil, err
	}

	baseLogger, err := logs.CreateDefault(localPath)
	if err != nil {
		return nil, err
	}

	cloudLogger := client.Logger("bot", logging.CommonResource(resource))
	return &Logger{
		baseLogger:  baseLogger,
		cloudLogger: cloudLogger,
	}, nil
}

// createGCE creates a logger on a GCE machine.
func createGCE(localPath string) (*Logger, error) {
	instanceID, err := metadata.InstanceID()
	if err != nil {
		return nil, err
	}

	zone, err := metadata.Zone()
	if err != nil {
		return nil, err
	}

	resource := &monitoredres.MonitoredResource{
		Type: "gce_instance",
		Labels: map[string]string{
			"instance_id": instanceID,
			"zone":        zone,
		},
	}
	return createCommon(localPath, resource)
}

// createGeneric creates a logger on a nonGCE machine.
func createGeneric(localPath string) (*Logger, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return nil, err
	}

	resource := &monitoredres.MonitoredResource{
		Type: "gce_instance",
		Labels: map[string]string{
			"instance_id": hostname,
			"zone":        "non-gce",
		},
	}
	return createCommon(localPath, resource)
}

// logWithSeverity logs an entry with a specified severity.
func (l *Logger) logWithSeverity(severity logging.Severity, format string, v ...interface{}) {
	msg := fmt.Sprintf(format, v...)
	payload := Payload{
		Message:     msg,
		BotName:     bots.BotName(),
		TaskPayload: bots.TaskPayload(),
	}
	entry := logging.Entry{
		Payload:  payload,
		Severity: severity,
	}

	l.cloudLogger.Log(entry)
}

// Logf logs an entry.
func (l *Logger) Logf(fmt string, v ...interface{}) {
	l.logWithSeverity(logging.Default, fmt, v...)
	l.baseLogger.Logf(fmt, v...)
}

// Errorf logs an error entry.
func (l *Logger) Errorf(fmt string, v ...interface{}) {
	l.logWithSeverity(logging.Error, fmt, v...)
	l.baseLogger.Errorf(fmt, v...)
}

// Warnf logs an warning entry.
func (l *Logger) Warnf(fmt string, v ...interface{}) {
	l.logWithSeverity(logging.Warning, fmt, v...)
	l.baseLogger.Warnf(fmt, v...)
}

// Panicf logs an error entry and panics.
func (l *Logger) Panicf(fmt string, v ...interface{}) {
	l.logWithSeverity(logging.Error, fmt, v...)
	l.baseLogger.Panicf(fmt, v...)
}
