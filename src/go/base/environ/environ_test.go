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

package environ

import (
	"fmt"
	"os"
	"testing"
)

func ExampleGetValueInt() {
	SetValue("TEST_ENV", 42)
	fmt.Println(GetValueInt("TEST_ENV"))
	// Output: 42
}

func TestSetValueTrue(t *testing.T) {
	SetValue("TEST_ENV", true)

	expected := "True"
	valueStr := os.Getenv("TEST_ENV")

	if valueStr != expected {
		t.Errorf("Getenv should return %v, got %v", expected, valueStr)
	}
}

func TestSetValueFalse(t *testing.T) {
	SetValue("TEST_ENV", false)

	expected := "False"
	valueStr := os.Getenv("TEST_ENV")

	if valueStr != expected {
		t.Errorf("Getenv should return %v, got %v", expected, valueStr)
	}
}

func TestSetValueStr(t *testing.T) {
	SetValue("TEST_ENV", "abc")

	expected := "abc"
	valueStr := os.Getenv("TEST_ENV")

	if valueStr != expected {
		t.Errorf("Getenv should return %v, got %v", expected, valueStr)
	}
}

func TestSetValueInt(t *testing.T) {
	SetValue("TEST_ENV", 123)

	expected := "123"
	valueStr := os.Getenv("TEST_ENV")

	if valueStr != expected {
		t.Errorf("Getenv should return %v, got %v", expected, valueStr)
	}
}

func TestSetValueIntNegative(t *testing.T) {
	SetValue("TEST_ENV", -123)

	expected := "-123"
	valueStr := os.Getenv("TEST_ENV")

	if valueStr != expected {
		t.Errorf("Getenv should return %v, got %v", expected, valueStr)
	}
}

func TestSetValueFloat(t *testing.T) {
	SetValue("TEST_ENV", 0.5)

	expected := "0.5"
	valueStr := os.Getenv("TEST_ENV")

	if valueStr != expected {
		t.Errorf("Getenv should return %v, got %v", expected, valueStr)
	}
}

func TestGetValueStr(t *testing.T) {
	os.Setenv("TEST_ENV", "abc")

	expected := "abc"
	value := GetValueStr("TEST_ENV")

	if value != expected {
		t.Errorf("GetValueStr should return %v, got %v", expected, value)
	}
}

func TestGetValueInt(t *testing.T) {
	os.Setenv("TEST_ENV", "9223372036854775807")

	expected := int64(9223372036854775807)
	value := GetValueInt("TEST_ENV")

	if value != expected {
		t.Errorf("GetValueInt should return %v, got %v", expected, value)
	}
}

func TestGetValueIntNegative(t *testing.T) {
	os.Setenv("TEST_ENV", "-9223372036854775808")

	expected := int64(-9223372036854775808)
	value := GetValueInt("TEST_ENV")

	if value != expected {
		t.Errorf("GetValueInt should return %v, got %v", expected, value)
	}
}

func TestGetValueUint(t *testing.T) {
	os.Setenv("TEST_ENV", "18446744073709551615")

	expected := uint64(18446744073709551615)
	value := GetValueUint("TEST_ENV")

	if value != expected {
		t.Errorf("GetValueUint should return %v, got %v", expected, value)
	}
}
