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

package appengine

import (
	"net/http"
)

// VerifyCronRequest wraps the given handler
func VerifyCronRequest(handler func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		// As per https://cloud.google.com/appengine/docs/standard/go/config/cron.
		if r.Header.Get("X-Appengine-Cron") != "true" {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		handler(w, r)
	}
}
