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
	"log"
	"net/http"

	"clusterfuzz/go/base/buckets"
	"clusterfuzz/go/cloud/db"
	"clusterfuzz/go/cloud/gcs"
	"clusterfuzz/go/server/appengine"
	"clusterfuzz/go/server/cron"
)

func main() {
	db.Init()
	buckets.RegisterProvider(gcs.Scheme, gcs.New())

	http.HandleFunc("/cron/fuzzer-coverage", appengine.VerifyCronRequest(cron.FuzzerCoverage))
	http.HandleFunc("/cron/oss-fuzz-generate-certs", appengine.VerifyCronRequest(cron.OSSFuzzGenerateCerts))
	log.Fatal(http.ListenAndServe(":8080", nil))
}
