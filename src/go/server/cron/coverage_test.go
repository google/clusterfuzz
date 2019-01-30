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

package cron

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"cloud.google.com/go/datastore"

	"clusterfuzz/go/cloud/db"
	"clusterfuzz/go/cloud/db/types"
	"clusterfuzz/go/testing/config"
)

func assertCoverageInformation(t *testing.T, expected types.CoverageInformation, actual types.CoverageInformation) {
	if formatDate(expected.Date) != formatDate(actual.Date) {
		t.Fatalf("Expected Date %v, got %v", expected.Date, actual.Date)
	}
	if expected.Fuzzer != actual.Fuzzer {
		t.Fatalf("Expected Fuzzer %s, got %s", expected.Fuzzer, actual.Fuzzer)
	}
	if expected.FunctionsCovered != actual.FunctionsCovered {
		t.Fatalf("Expected FunctionsCovered %d, got %d", expected.FunctionsCovered, actual.FunctionsCovered)
	}
	if expected.FunctionsTotal != actual.FunctionsTotal {
		t.Fatalf("Expected FunctionsTotal %d, got %d", expected.FunctionsTotal, actual.FunctionsTotal)
	}
	if expected.EdgesCovered != actual.EdgesCovered {
		t.Fatalf("Expected EdgesCovered %d, got %d", expected.EdgesCovered, actual.EdgesCovered)
	}
	if expected.EdgesTotal != actual.EdgesTotal {
		t.Fatalf("Expected EdgesTotal %d, got %d", expected.EdgesTotal, actual.EdgesTotal)
	}
	if expected.CorpusSizeUnits != actual.CorpusSizeUnits {
		t.Fatalf("Expected CorpusSizeUnits %d, got %d", expected.CorpusSizeUnits, actual.CorpusSizeUnits)
	}
	if expected.CorpusSizeBytes != actual.CorpusSizeBytes {
		t.Fatalf("Expected CorpusSizeBytes %d, got %d", expected.CorpusSizeBytes, actual.CorpusSizeBytes)
	}
	if expected.CorpusLocation != actual.CorpusLocation {
		t.Fatalf("Expected CorpusLocation '%s', got '%s'", expected.CorpusLocation, actual.CorpusLocation)
	}
	if expected.CorpusBackupLocation != actual.CorpusBackupLocation {
		t.Fatalf("Expected CorpusBackupLocation '%s', got '%s'", expected.CorpusBackupLocation, actual.CorpusBackupLocation)
	}
	if expected.QuarantineSizeUnits != actual.QuarantineSizeUnits {
		t.Fatalf("Expected QuarantineSizeUnits %d, got %d", expected.QuarantineSizeUnits, actual.QuarantineSizeUnits)
	}
	if expected.QuarantineSizeBytes != actual.QuarantineSizeBytes {
		t.Fatalf("Expected QuarantineSizeBytes %d, got %d", expected.QuarantineSizeBytes, actual.QuarantineSizeBytes)
	}
	if expected.QuarantineLocation != actual.QuarantineLocation {
		t.Fatalf("Expected QuarantineLocation '%s', got '%s'", expected.QuarantineLocation, actual.QuarantineLocation)
	}
	if expected.HTMLReportURL != actual.HTMLReportURL {
		t.Fatalf("Expected HTMLReportURL '%s', got '%s'", expected.HTMLReportURL, actual.HTMLReportURL)
	}
}

func parseDate(dateStr string) time.Time {
	date, _ := time.Parse(dateLayout, dateStr)
	return date
}

func formatDate(date time.Time) string {
	return date.Format(dateLayout)
}

func TestFuzzerCoverage(t *testing.T) {
	if !config.IntegrationTestsEnabled() {
		t.Log("Skipping TestFuzzerCoverage because integration tests are disabled.")
		return
	}

	// An old coverage information for a fuzzer that should NOT be overwritten.
	dateStr := "20180901"
	date := parseDate(dateStr)
	info0 := &types.CoverageInformation{
		Key:              datastore.NameKey("CoverageInformation", "boringssl_privkey-"+dateStr, nil),
		Date:             date,
		Fuzzer:           "boringssl_privkey",
		FunctionsCovered: 123,
		FunctionsTotal:   555,
		EdgesCovered:     1337,
		EdgesTotal:       31337,
		HTMLReportURL:    "https://storage.googleapis.com/oss-fuzz-coverage/boringssl/reports/20180905/linux/index.html",
	}

	// A recent coverage information for a fuzzer that should be overwritten.
	dateStr = "20180907"
	date = parseDate(dateStr)
	info1 := &types.CoverageInformation{
		Key:              datastore.NameKey("CoverageInformation", "base64_decode_fuzzer-"+dateStr, nil),
		Date:             date,
		Fuzzer:           "base64_decode_fuzzer",
		FunctionsCovered: 1,
		FunctionsTotal:   5,
		EdgesCovered:     3,
		EdgesTotal:       20,
		HTMLReportURL:    "intentionally junk URL that must be overwritten",
	}

	// A recent coverage information for a project that should be overwritten.
	dateStr = "20180907"
	date = parseDate(dateStr)
	info2 := &types.CoverageInformation{
		Key:              datastore.NameKey("CoverageInformation", "zlib-"+dateStr, nil),
		Date:             date,
		Fuzzer:           "zlib",
		FunctionsCovered: 1,
		FunctionsTotal:   2,
		EdgesCovered:     3,
		EdgesTotal:       4,
		HTMLReportURL:    "intentionally junk URL that must be overwritten",
	}

	db.Put(context.Background(), info0.Key, info0)
	db.Put(context.Background(), info1.Key, info1)
	db.Put(context.Background(), info2.Key, info2)

	req := httptest.NewRequest("", "/", nil)
	url := latestReportInfoDir(config.IntegrationTestBucketStatic())
	err := processGCSDir(req.Context(), url, processProject)
	if err != nil {
		t.Fatalf("Code coverage task (processGCSDir) failed unexpectedly: %+v", err)
	}

	query := datastore.NewQuery("CoverageInformation")
	it := db.RunQuery(context.Background(), query)

	// Extract all the entities into a map for further verification.
	entities := make(map[string]types.CoverageInformation)
	var info types.CoverageInformation
	for it.Next(&info) {
		entities[info.Key.Name] = info
	}

	if err := it.Err(); err != nil {
		t.Fatalf("Failed to run CoverageInformation query: %+v", err)
	}

	if len(entities) != 9 {
		t.Fatalf("Expected 9 entities, got %d.", len(entities))
	}

	// Assert and delete entities one by one to make sure we verify each of them.
	assertCoverageInformation(t, types.CoverageInformation{
		Date:             parseDate("20180905"),
		Fuzzer:           "boringssl_bn_div",
		FunctionsCovered: 82,
		FunctionsTotal:   1079,
		EdgesCovered:     1059,
		EdgesTotal:       12384,
		HTMLReportURL:    "https://storage.googleapis.com/oss-fuzz-coverage/boringssl/reports/20180905/linux/index.html",
	}, entities["boringssl_bn_div-20180905"])
	delete(entities, "boringssl_bn_div-20180905")

	assertCoverageInformation(t, types.CoverageInformation{
		Date:             parseDate("20180901"),
		Fuzzer:           "boringssl_privkey",
		FunctionsCovered: 123,
		FunctionsTotal:   555,
		EdgesCovered:     1337,
		EdgesTotal:       31337,
		HTMLReportURL:    "https://storage.googleapis.com/oss-fuzz-coverage/boringssl/reports/20180905/linux/index.html",
	}, entities["boringssl_privkey-20180901"])
	delete(entities, "boringssl_privkey-20180901")

	assertCoverageInformation(t, types.CoverageInformation{
		Date:             parseDate("20180905"),
		Fuzzer:           "boringssl_privkey",
		FunctionsCovered: 374,
		FunctionsTotal:   1510,
		EdgesCovered:     3535,
		EdgesTotal:       16926,
		HTMLReportURL:    "https://storage.googleapis.com/oss-fuzz-coverage/boringssl/reports/20180905/linux/index.html",
	}, entities["boringssl_privkey-20180905"])
	delete(entities, "boringssl_privkey-20180905")

	assertCoverageInformation(t, types.CoverageInformation{
		Date:             parseDate("20180905"),
		Fuzzer:           "boringssl",
		FunctionsCovered: 1872,
		FunctionsTotal:   4137,
		EdgesCovered:     21303,
		EdgesTotal:       51251,
		HTMLReportURL:    "https://storage.googleapis.com/oss-fuzz-coverage/boringssl/reports/20180905/linux/index.html",
	}, entities["boringssl-20180905"])
	delete(entities, "boringssl-20180905")

	assertCoverageInformation(t, types.CoverageInformation{
		Date:             parseDate("20180907"),
		Fuzzer:           "base64_decode_fuzzer",
		FunctionsCovered: 252,
		FunctionsTotal:   5646,
		EdgesCovered:     1111,
		EdgesTotal:       38748,
		HTMLReportURL:    "https://chromium-coverage.appspot.com/reports/589371_fuzzers_only/linux/index.html",
	}, entities["base64_decode_fuzzer-20180907"])
	delete(entities, "base64_decode_fuzzer-20180907")

	assertCoverageInformation(t, types.CoverageInformation{
		Date:             parseDate("20180907"),
		Fuzzer:           "zucchini_raw_gen_fuzzer",
		FunctionsCovered: 440,
		FunctionsTotal:   6439,
		EdgesCovered:     1791,
		EdgesTotal:       45121,
		HTMLReportURL:    "https://chromium-coverage.appspot.com/reports/589371_fuzzers_only/linux/index.html",
	}, entities["zucchini_raw_gen_fuzzer-20180907"])
	delete(entities, "zucchini_raw_gen_fuzzer-20180907")

	assertCoverageInformation(t, types.CoverageInformation{
		Date:             parseDate("20180907"),
		Fuzzer:           "chromium",
		FunctionsCovered: 79960,
		FunctionsTotal:   467023,
		EdgesCovered:     682323,
		EdgesTotal:       3953229,
		HTMLReportURL:    "https://chromium-coverage.appspot.com/reports/589371_fuzzers_only/linux/index.html",
	}, entities["chromium-20180907"])
	delete(entities, "chromium-20180907")

	assertCoverageInformation(t, types.CoverageInformation{
		Date:             parseDate("20180907"),
		Fuzzer:           "zlib_uncompress_fuzzer",
		FunctionsCovered: 19,
		FunctionsTotal:   47,
		EdgesCovered:     987,
		EdgesTotal:       1687,
		HTMLReportURL:    "https://storage.googleapis.com/oss-fuzz-coverage/zlib/reports/20180907/linux/index.html",
	}, entities["zlib_uncompress_fuzzer-20180907"])
	delete(entities, "zlib_uncompress_fuzzer-20180907")

	assertCoverageInformation(t, types.CoverageInformation{
		Date:             parseDate("20180907"),
		Fuzzer:           "zlib",
		FunctionsCovered: 19,
		FunctionsTotal:   47,
		EdgesCovered:     987,
		EdgesTotal:       1687,
		HTMLReportURL:    "https://storage.googleapis.com/oss-fuzz-coverage/zlib/reports/20180907/linux/index.html",
	}, entities["zlib-20180907"])
	delete(entities, "zlib-20180907")

	// Should not have any entities left unverified.
	if len(entities) != 0 {
		t.Fatalf("Expected 0 entities, got %d.", len(entities))
	}
}
