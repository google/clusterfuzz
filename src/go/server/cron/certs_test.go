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
	"strings"
	"testing"

	"cloud.google.com/go/datastore"

	"clusterfuzz/go/cloud/db"
	"clusterfuzz/go/cloud/db/types"
)

func TestGenerateOSSFuzzCerts(t *testing.T) {
	project0 := &types.OssFuzzProject{
		Key:  datastore.NameKey("OssFuzzProject", "proj0", nil),
		Name: "proj0",
	}

	cert0 := &types.WorkerTlsCert{
		Key:          datastore.NameKey("WorkerTlsCert", "proj0", nil),
		ProjectName:  "proj0",
		CertContents: []byte("BEGIN CERTIFICATE ORIGINAL"),
		KeyContents:  []byte("BEGIN RSA PRIVATE KEY ORIGINAL"),
	}

	project1 := &types.OssFuzzProject{
		Key:  datastore.NameKey("OssFuzzProject", "proj1", nil),
		Name: "proj1",
	}

	db.Put(context.Background(), project0.Key, project0)
	db.Put(context.Background(), cert0.Key, cert0)
	db.Put(context.Background(), project1.Key, project1)

	req := httptest.NewRequest("", "/", nil)
	resp := httptest.NewRecorder()

	OSSFuzzGenerateCerts(resp, req)

	var cert types.WorkerTlsCert
	query := datastore.NewQuery("WorkerTlsCert")

	certs := make(map[string]bool)

	it := db.RunQuery(context.Background(), query)
	for it.Next(&cert) {
		if !strings.Contains(string(cert.KeyContents), "BEGIN RSA PRIVATE KEY") {
			t.Error("KeyContents does not contain a private key.")
		}

		if !strings.Contains(string(cert.CertContents), "BEGIN CERTIFICATE") {
			t.Error("CertContents does not contain a certificate.")
		}

		if cert.ProjectName == "proj0" {
			if !strings.Contains(string(cert.KeyContents), "ORIGINAL") ||
				!strings.Contains(string(cert.CertContents), "ORIGINAL") {
				t.Error("Certificate modified unexpectedly.")
			}
		}

		certs[cert.ProjectName] = true
	}
	if err := it.Err(); err != nil {
		t.Fatalf("Failed to run WorkerTlsCert query: %+v", err)
	}

	if len(certs) != 2 {
		t.Errorf("Expected 2 certs, got %d", len(certs))
	}

	_, ok := certs["proj0"]
	if !ok {
		t.Error("Could not find cert for proj0")
	}

	_, ok = certs["proj1"]
	if !ok {
		t.Error("Could not find cert for proj1")
	}
}
