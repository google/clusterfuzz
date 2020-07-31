// Copyright 2019 Google LLC
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

// GCE Metadata server
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Token represents a service account token.
type Token struct {
	AccessToken string
	ExpiresAt   int64
	Info        *TokenInfo
}

// TokenInfo represents the response from https://www.googleapis.com/oauth2/v1/tokeninfo.
type TokenInfo struct {
	IssuedTo      string `json:"issued_to"`
	Audience      string `json:"audience"`
	UserID        string `json:"user_id"`
	Scope         string `json:"scope"`
	ExpiresIn     int64  `json:"expires_in"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	AccessType    string `json:"access_type"`
}

// TokenResult represents the response from service-accounts/.../token
type TokenResult struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

// LegacyToken represents the response from the legacy service-accounts/acquire metadata endpoint.
type LegacyToken struct {
	AccessToken string `json:"accessToken"`
	ExpiresAt   int64  `json:"expiresAt"`
	ExpiresIn   int64  `json:"expiresIn"`
}

// RecursiveAccount represents the response from the service-accounts/email/?recursive=true endpoint.
type RecursiveAccount struct {
	Aliases []string `json:"aliases"`
	Email   string   `json:"email"`
	Scopes  []string `json:"scopes"`
}

const (
	// Used by our ancient copy of oauth2client.
	legacyServiceAccountsPath = "/0.1/meta-data/service-accounts"
	serviceAccountsPath       = "/computeMetadata/v1/instance/service-accounts"
	defaultServiceAccPath     = serviceAccountsPath + "/default"

	projIDPath           = "/computeMetadata/v1/project/project-id"
	projNumPath          = "/computeMetadata/v1/project/numeric-project-id"
	deploymentBucketPath = "/computeMetadata/v1/project/attributes/deployment-bucket"
	zonePath             = "/computeMetadata/v1/instance/zone"
	hostnamePath         = "/computeMetadata/v1/instance/hostname"
	instanceIDPath       = "/computeMetadata/v1/instance/id"
)

var (
	// Configurable environment options.
	projID           string
	projNum          int
	deploymentBucket string
	zone             string
	hostname         string

	// IP:Port to listen on.
	ip   string
	port int

	// Cached token information.
	tokenLock sync.RWMutex
	token     Token
	email     string
)

// refreshTokenIfNeeded refreshes the access token if the current one is
// unavailable or expired.
func refreshTokenIfNeeded() error {
	tokenLock.RLock()
	if token.ExpiresAt != 0 && time.Now().Unix() < token.ExpiresAt {
		return nil
	}
	tokenLock.RUnlock()

	cmd := exec.Command("gcloud", "auth", "application-default", "print-access-token")
	output, err := cmd.Output()
	if err != nil {
		return err
	}

	accessToken := strings.TrimSpace(string(output))
	info, err := getTokenInfo(accessToken)
	if err != nil {
		return err
	}

	tokenLock.Lock()
	defer tokenLock.Unlock()

	token.AccessToken = accessToken
	token.Info = info
	token.ExpiresAt = time.Now().Unix() + info.ExpiresIn

	return nil
}

// getTokenInfo returns information about the token.
func getTokenInfo(accessToken string) (*TokenInfo, error) {
	resp, err := http.Get("https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=" + accessToken)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var info TokenInfo
	err = json.Unmarshal(body, &info)
	if err != nil {
		return nil, err
	}

	return &info, nil
}

// serviceAccountsHandler handles the /service-accounts/ request.
func serviceAccountsHandler(w http.ResponseWriter, r *http.Request) {
	handleCommon(w, r)
	if r.URL.Path != serviceAccountsPath+"/" {
		log.Printf("Unhandled service accounts path = %s, RawQuery = %s\n", r.URL.Path, r.URL.RawQuery)
		return
	}

	fmt.Fprintf(w, "%s/\ndefault/\n", email)
}

// aliasesHandler handles the /aliases request.
func aliasesHandler(w http.ResponseWriter, r *http.Request) {
	handleCommon(w, r)
	fmt.Fprintf(w, "default")
}

// aliasesHandler handles the /email request.
func emailHandler(w http.ResponseWriter, r *http.Request) {
	handleCommon(w, r)
	fmt.Fprintf(w, "%s", email)
}

// aliasesHandler handles the /scopes request.
func scopesHandler(w http.ResponseWriter, r *http.Request) {
	handleCommon(w, r)

	tokenLock.RLock()
	defer tokenLock.RUnlock()
	fmt.Fprintf(w, "%s\n", strings.Replace(token.Info.Scope, " ", "\n", -1))
}

// aliasesHandler handles the /token request.
func tokenHandler(w http.ResponseWriter, r *http.Request) {
	handleCommon(w, r)

	tokenLock.RLock()
	defer tokenLock.RUnlock()

	result := TokenResult{
		AccessToken: token.AccessToken,
		ExpiresIn:   token.ExpiresAt - time.Now().Unix(),
		TokenType:   "Bearer",
	}

	encoded, err := json.Marshal(result)
	if handleError(w, err) {
		return
	}

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, "%s", encoded)
}

// acquireHandler handles the legacy service account token request.
func acquireHandler(w http.ResponseWriter, r *http.Request) {
	handleCommon(w, r)

	tokenLock.RLock()
	defer tokenLock.RUnlock()

	result := LegacyToken{
		AccessToken: token.AccessToken,
		ExpiresAt:   token.ExpiresAt,
		ExpiresIn:   token.ExpiresAt - time.Now().Unix(),
	}

	encoded, err := json.Marshal(result)
	if handleError(w, err) {
		return
	}

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, "%s", encoded)
}

// projIDHandler handles proj ID requests.
func projIDHandler(w http.ResponseWriter, r *http.Request) {
	handleCommon(w, r)
	fmt.Fprintf(w, "%s", projID)
}

// projNumHandler handles proj numeric ID requests.
func projNumHandler(w http.ResponseWriter, r *http.Request) {
	handleCommon(w, r)
	fmt.Fprintf(w, "%d", projNum)
}

// zoneHandler handles zone requests.
func zoneHandler(w http.ResponseWriter, r *http.Request) {
	handleCommon(w, r)
	fmt.Fprintf(w, "%s", zone)
}

// hostnameHandler handles instance name requests.
func hostnameHandler(w http.ResponseWriter, r *http.Request) {
	handleCommon(w, r)
	fmt.Fprintf(w, "%s", hostname)
}

// deploymentBucketHandler handles deployment bucket name requests.
func deploymentBucketHandler(w http.ResponseWriter, r *http.Request) {
	handleCommon(w, r)
	fmt.Fprintf(w, "%s", deploymentBucket)
}

// unhandledHandler logs unhandled requests.
func unhandledHandler(w http.ResponseWriter, r *http.Request) {
	handleCommon(w, r)
	if r.URL.Path != "/" {
		log.Printf("Unhandled path = %s, RawQuery = %s\n", r.URL.Path, r.URL.RawQuery)
		w.WriteHeader(http.StatusNotFound)
	}
}

// accountPropertiesHandler handles service-accounts/email/ requests.
func accountPropertiesHandler(w http.ResponseWriter, r *http.Request) {
	handleCommon(w, r)

	if _, ok := r.URL.Query()["recursive"]; ok {
		tokenLock.RLock()
		defer tokenLock.RUnlock()

		result := RecursiveAccount{
			Aliases: []string{"default"},
			Email:   email,
			Scopes:  strings.Split(token.Info.Scope, " "),
		}

		encoded, err := json.Marshal(result)
		if handleError(w, err) {
			return
		}

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, "%s", encoded)
	} else {
		fmt.Fprintf(
			w,
			"aliases\n"+
				"email\n"+
				"identity\n"+
				"scopes\n"+
				"token\n")
	}
}

// handleCommon implements functionality common to all handlers.
func handleCommon(w http.ResponseWriter, r *http.Request) {
	err := refreshTokenIfNeeded()
	if err != nil {
		log.Panicf("Failed to refresh token: %s", err)
	}
	w.Header().Set("Metadata-Flavor", "Google")
	log.Printf("Requested = %s, RawQuery = %s\n", r.URL.Path, r.URL.RawQuery)
}

// handleError handles an error and returns whether if we should abort.
func handleError(w http.ResponseWriter, err error) bool {
	if err != nil {
		fmt.Fprintf(w, "ERROR: %s", err)
		return true
	}

	return false
}

func main() {
	flag.StringVar(&ip, "ip", "localhost", "IP to listen on.")
	flag.IntVar(&port, "port", 8080, "Port to listen on.")
	flag.StringVar(&projID, "project-id", "google.com:clusterfuzz", "Project ID")
	flag.IntVar(&projNum, "project-num", 246243303817, "Project numeric ID")
	flag.StringVar(&zone, "zone", "us-central1-f", "GCE zone")
	flag.StringVar(&hostname, "hostname", "test-bot", "Instance name")
	flag.StringVar(&deploymentBucket, "deployment-bucket", "clusterfuzz-deployment", "Deployment bucket name")

	flag.Parse()

	err := refreshTokenIfNeeded()
	if err != nil {
		log.Panicf("Failed to refresh token: %s", err)
	}

	// Not expected to change
	email = token.Info.Email

	http.HandleFunc(serviceAccountsPath+"/", serviceAccountsHandler)

	http.HandleFunc(defaultServiceAccPath+"/aliases", aliasesHandler)
	http.HandleFunc(defaultServiceAccPath+"/email", emailHandler)
	http.HandleFunc(defaultServiceAccPath+"/scopes", scopesHandler)
	http.HandleFunc(defaultServiceAccPath+"/token", tokenHandler)
	http.HandleFunc(defaultServiceAccPath+"/", accountPropertiesHandler)

	emailServiceAccPath := serviceAccountsPath + "/" + email
	http.HandleFunc(emailServiceAccPath+"/aliases", aliasesHandler)
	http.HandleFunc(emailServiceAccPath+"/email", emailHandler)
	http.HandleFunc(emailServiceAccPath+"/scopes", scopesHandler)
	http.HandleFunc(emailServiceAccPath+"/token", tokenHandler)
	http.HandleFunc(emailServiceAccPath+"/", accountPropertiesHandler)

	http.HandleFunc(legacyServiceAccountsPath+"/default/acquire", acquireHandler)

	http.HandleFunc(projIDPath, projIDHandler)
	http.HandleFunc(projNumPath, projNumHandler)
	http.HandleFunc(deploymentBucketPath, deploymentBucketHandler)
	http.HandleFunc(zonePath, zoneHandler)
	http.HandleFunc(hostnamePath, hostnameHandler)
	// Use the hostname for instance ID.
	http.HandleFunc(instanceIDPath, hostnameHandler)

	http.HandleFunc("/", unhandledHandler)

	http.ListenAndServe(fmt.Sprintf("%s:%d", ip, port), nil)
}
