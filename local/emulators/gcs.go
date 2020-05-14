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

// Implementation of a GCS server which only accepts PUT uploads and URL downloads.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
)

const (
	objectsDir           = "objects"
	metadataDir          = "metadata"
	metadataHeaderPrefix = "x-goog-meta-"
)

var (
	// Port to listen on.
	port int

	// Storage path.
	storagePath string

	// Error when the bucket does not exist.
	errBucketDoesNotExist = errors.New("bucket does not exist")

	// Error when bucket and key aren't set before the file contents.
	errInvalidParams = errors.New("bucket and key needs to be set before file")

	// Error when the path is invalid
	errInvalidPath = errors.New("invalid path")
)

// handlePost handles an object POST.
func handlePost(w http.ResponseWriter, r *http.Request) {
	reader, err := r.MultipartReader()
	if err != nil {
		handleError(w, err)
		return
	}

	var bucket string
	var key string
	metadata := make(map[string]string)

	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}

		switch name := part.FormName(); name {
		case "bucket":
			bucket, err = readFormDataString(part)
		case "key":
			key, err = readFormDataString(part)
		case "file":
			err = readFormFile(bucket, key, part)
		default:
			if strings.HasPrefix(name, metadataHeaderPrefix) {
				err = readMetadata(metadata, name, part)
			}
		}

		if err != nil {
			handleError(w, err)
			return
		}
	}

	err = writeMetadata(bucket, key, metadata)
	if err != nil {
		handleError(w, err)
		return
	}

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)
}

// handleGet handles an object GET request.
func handleGet(w http.ResponseWriter, r *http.Request) {
	// Parse /bucket/path/to/object
	parts := strings.SplitN(r.URL.Path, "/", 3)
	if len(parts) != 3 {
		handleError(w, errInvalidPath)
		return
	}

	bucket := parts[1]
	key := parts[2]

	fsPath, err := getFsPath(bucket, key, objectsDir)
	if err != nil {
		handleError(w, err)
		return
	}

	f, err := os.Open(fsPath)
	if err == os.ErrNotExist {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if err != nil {
		handleError(w, err)
		return
	}
	defer f.Close()

	// Use requested content disposition.
	contentDisp := r.URL.Query().Get("response-content-disposition")
	if contentDisp != "" {
		w.Header().Set("content-disposition", contentDisp)
	}

	w.Header().Set("Access-Control-Allow-Origin", "*")
	_, err = io.Copy(w, f)
	if err != nil {
		handleError(w, err)
	}
}

// handler is the root http request handler.
func handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "http://localhost:9000")
	switch r.Method {
	case http.MethodPost:
		handlePost(w, r)
	case http.MethodGet:
		handleGet(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// handleError prints an error to the response.
func handleError(w http.ResponseWriter, err error) {
	w.WriteHeader(http.StatusInternalServerError)
	fmt.Fprintf(w, "ERROR: %v.", err)
}

// readFormDataString reads the form data as a string.
func readFormDataString(r io.Reader) (string, error) {
	var buf [256]byte
	n, err := r.Read(buf[:])
	if err != nil && err != io.EOF {
		return "", err
	}

	return string(buf[:n]), nil
}

// getFsPath gets the file system path for the given bucket and key.
func getFsPath(bucket, key, pathType string) (string, error) {
	if bucket == "" || key == "" {
		return "", errInvalidParams
	}

	bucketFsPath := path.Join(storagePath, bucket)
	_, err := os.Stat(bucketFsPath)
	if err != nil {
		return "", errBucketDoesNotExist
	}

	return path.Join(bucketFsPath, pathType, key), nil
}

// readFormFile reads the uploaded file data.
func readFormFile(bucket, key string, r io.Reader) error {
	fsPath, err := getFsPath(bucket, key, objectsDir)
	if err != nil {
		return err
	}

	err = makeContainingDir(fsPath)
	if err != nil {
		return err
	}

	output, err := os.Create(fsPath)
	if err != nil {
		return err
	}
	defer output.Close()

	_, err = io.Copy(output, r)
	return err
}

// writeMetadata writes the requested metadata.
func writeMetadata(bucket, key string, metadata map[string]string) error {
	if bucket == "" || key == "" {
		return errInvalidParams
	}

	fsPath, err := getFsPath(bucket, key, metadataDir)
	if err != nil {
		return err
	}

	err = makeContainingDir(fsPath)
	if err != nil {
		return err
	}

	encoded, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(fsPath, encoded, 0600)
}

// readMetadata reads a metadata value from the form data.
func readMetadata(metadata map[string]string, name string, r io.Reader) error {
	value, err := readFormDataString(r)
	if err != nil {
		return err
	}

	key := name[len(metadataHeaderPrefix):]
	metadata[key] = value
	return nil
}

// makeContainingDir calls MkdirAll on the the containing directory of the given path.
func makeContainingDir(path string) error {
	return os.MkdirAll(filepath.Dir(path), 0700)
}

func main() {
	flag.IntVar(&port, "port", 9008, "Port to listen on.")
	flag.StringVar(&storagePath, "storage-path", "", "Local GCS storage path.")
	flag.Parse()

	http.HandleFunc("/", handler)
	http.ListenAndServe(fmt.Sprintf("localhost:%d", port), nil)
}
