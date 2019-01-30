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

// Package logs implements logging helpers.
package logs

import (
	"log"
	"os"
)

// Logger is the interface for a logger.
type Logger interface {
	Logf(fmt string, v ...interface{})
	Errorf(fmt string, v ...interface{})
	Warnf(fmt string, v ...interface{})
	Panicf(fmt string, v ...interface{})
}

// DefaultLogger is the default implementation of a logger.
type DefaultLogger struct {
	logger *log.Logger
}

var (
	logger Logger
)

// Init initializes the loggers.
func Init(newLogger Logger) {
	logger = newLogger
}

// CreateDefault creates a default logger.
func CreateDefault(path string) (Logger, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}
	logger := log.New(f, "", log.Ldate|log.Ltime|log.Lshortfile)
	return &DefaultLogger{
		logger: logger,
	}, nil
}

// Logf logs an entry.
func (l *DefaultLogger) Logf(fmt string, v ...interface{}) {
	l.logger.Printf(fmt, v...)
}

// Errorf logs an error entry.
func (l *DefaultLogger) Errorf(fmt string, v ...interface{}) {
	l.logger.Printf("ERROR - "+fmt, v...)
}

// Warnf logs a warning entry.
func (l *DefaultLogger) Warnf(fmt string, v ...interface{}) {
	l.logger.Printf("WARN - "+fmt, v...)
}

// Panicf logs an error entry and panics.
func (l *DefaultLogger) Panicf(fmt string, v ...interface{}) {
	l.logger.Panicf("PANIC - "+fmt, v...)
}

// Logf logs an entry.
func Logf(fmt string, v ...interface{}) {
	if logger == nil {
		log.Printf(fmt, v...)
		return
	}
	logger.Logf(fmt, v...)
}

// Errorf logs an error entry.
func Errorf(fmt string, v ...interface{}) {
	if logger == nil {
		log.Printf(fmt, v...)
		return
	}
	logger.Errorf(fmt, v...)
}

// Warnf logs a warning entry.
func Warnf(fmt string, v ...interface{}) {
	if logger == nil {
		log.Printf(fmt, v...)
		return
	}
	logger.Warnf(fmt, v...)
}

// Panicf logs an error entry and panics.
func Panicf(fmt string, v ...interface{}) {
	if logger == nil {
		log.Panicf(fmt, v...)
		return
	}
	logger.Panicf(fmt, v...)
}
