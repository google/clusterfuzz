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

// Package environ implements helpers for extracting and setting environment
// variables.
package environ

import (
	"os"
	"reflect"
	"strconv"

	"clusterfuzz/go/base/logs"
)

// GetValueStrOrPanic returns the environment variable value, or panics if it
// does not exist.
func GetValueStrOrPanic(envVar string) string {
	if !HasValue(envVar) {
		logs.Panicf("%s must be set.", envVar)
	}

	return GetValueStr(envVar)
}

// HasValue returns whether or not the given environment variable exists.
func HasValue(key string) bool {
	_, exists := os.LookupEnv(key)
	return exists
}

// GetValueStr returns the string value for the given environment variable.
func GetValueStr(key string) string {
	return os.Getenv(key)
}

// GetValueInt returns the int64 value for the given environment variable.
func GetValueInt(key string) int64 {
	return ParseInt(os.Getenv(key))
}

// GetValueUint returns the uint64 value for the given environment variable.
func GetValueUint(key string) uint64 {
	return ParseUint(os.Getenv(key))
}

// GetValueFloat returns the float64 value for the given environment variable.
func GetValueFloat(key string) float64 {
	return ParseFloat(os.Getenv(key))
}

// GetValueBool returns the bool value for the given environment variable.
func GetValueBool(key string) bool {
	return ParseBool(os.Getenv(key))
}

// SetValue sets the given environment variable with the given value. The
// string value that is set is based on the given value's type.
func SetValue(key string, value interface{}) {
	err := os.Setenv(key, ValueToStr(value))
	if err != nil {
		logs.Panicf("Failed to set env.")
	}
}

// ParseInt parses an int value and panics on error.
func ParseInt(val string) int64 {
	intVal, err := strconv.ParseInt(val, 10, 64)
	if err != nil {
		logs.Panicf("Failed to parse int: %s", err)
	}

	return intVal
}

// ParseUint parses an uint value and panics on error.
func ParseUint(val string) uint64 {
	uintVal, err := strconv.ParseUint(val, 10, 64)
	if err != nil {
		logs.Panicf("Failed to parse uint: %s", err)
	}

	return uintVal
}

// ParseFloat parses a float value and panics on error.
func ParseFloat(val string) float64 {
	floatVal, err := strconv.ParseFloat(val, 64)
	if err != nil {
		logs.Panicf("Failed to parse float: %s", err)
	}

	return floatVal
}

// ParseBool parses a bool value and panics on error.
func ParseBool(val string) bool {
	switch val {
	case "True":
		return true
	case "False":
		return false
	default:
		logs.Panicf("Invalid boolean: %s", val)
	}

	return false
}

// ValueToStr converts a value to its string representation for storing in the
// environment.
func ValueToStr(value interface{}) string {
	reflectVal := reflect.ValueOf(value)

	switch reflect.TypeOf(value).Kind() {
	case reflect.String:
		return value.(string)

	case reflect.Bool:
		if reflectVal.Bool() {
			return "True"
		}
		return "False"

	case reflect.Float64:
		return strconv.FormatFloat(reflectVal.Float(), 'f', -1, 64)
	case reflect.Float32:
		return strconv.FormatFloat(reflectVal.Float(), 'f', -1, 32)

	case reflect.Uint64:
		fallthrough
	case reflect.Uint32:
		fallthrough
	case reflect.Uint16:
		fallthrough
	case reflect.Uint8:
		fallthrough
	case reflect.Uint:
		return strconv.FormatUint(reflectVal.Uint(), 10)

	case reflect.Int64:
		fallthrough
	case reflect.Int32:
		fallthrough
	case reflect.Int16:
		fallthrough
	case reflect.Int8:
		fallthrough
	case reflect.Int:
		return strconv.FormatInt(reflectVal.Int(), 10)

	default:
		logs.Panicf("Unhandled value type.")
	}

	return ""
}
