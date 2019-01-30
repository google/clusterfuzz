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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/pkg/errors"

	"clusterfuzz/go/base/logs"
	"clusterfuzz/go/cloud"
	"clusterfuzz/go/cloud/db"
	"clusterfuzz/go/cloud/db/types"
)

func generateCert(project string) ([]byte, []byte, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to generate RSA key")
	}

	notBefore := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)

	subject := pkix.Name{
		Organization: []string{project},
		Country:      []string{"US"},
		CommonName:   fmt.Sprintf("*.c.%s.internal", cloud.ProjectID()),
	}

	template := x509.Certificate{
		Subject:      subject,
		SerialNumber: big.NewInt(9001),
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to create certificate")
	}

	certPem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})
	if certPem == nil {
		return nil, nil, errors.New("failed to encode certificate")
	}

	keyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})
	if keyPem == nil {
		return nil, nil, errors.New("failed to encode key")
	}

	return certPem, keyPem, nil
}

// OSSFuzzGenerateCerts generates self signed certs for OSS-Fuzz host/workers.
func OSSFuzzGenerateCerts(w http.ResponseWriter, r *http.Request) {
	var project types.OssFuzzProject
	query := datastore.NewQuery("OssFuzzProject")
	it := db.RunQuery(r.Context(), query)

	for it.Next(&project) {
		var tls types.WorkerTlsCert
		entityKey := datastore.Key{
			Kind: "WorkerTlsCert",
			Name: project.Name,
		}
		err := db.Get(r.Context(), &entityKey, &tls)
		if err == nil {
			continue
		}

		logs.Logf("Generating cert for %s.", project.Name)
		certPem, keyPem, err := generateCert(project.Name)
		if err != nil {
			logs.Errorf("Failed to generate cert for %s: %+v", project.Name, err)
			continue
		}

		tls.ProjectName = project.Name
		tls.CertContents = certPem
		tls.KeyContents = keyPem
		_, err = db.Put(r.Context(), &entityKey, &tls)
		if err != nil {
			logs.Errorf("Failed to put cert for %s: %+v", project.Name, err)
			continue
		}
	}

	if err := it.Err(); err != nil {
		logs.Errorf("Failed to query projects: %+v", err)
	}
}
