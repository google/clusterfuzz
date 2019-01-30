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

// Package cron implements handlers for cron jobs.
package cron

import (
	"context"
	"encoding/json"
	"net/http"
	"path"
	"path/filepath"
	"strings"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/pkg/errors"

	"clusterfuzz/go/base/buckets"
	"clusterfuzz/go/base/config"
	"clusterfuzz/go/base/logs"
	"clusterfuzz/go/cloud/db"
	"clusterfuzz/go/cloud/db/types"
	"clusterfuzz/go/cloud/gcs"
)

const (
	dateLayout = "20060102"
)

type latestReportInfo struct {
	FuzzerStatsDir    string `json:"fuzzer_stats_dir"`
	HTMLReportURL     string `json:"html_report_url"`
	ReportDate        string `json:"report_date"`
	ReportSummaryPath string `json:"report_summary_path"`
}

// These structs are needed for parsing summary files exported by llvm-cov.
type reportInfo struct {
	Platform string `json:"platform"`
	Revision int    `json:"revision"`
	Root     string `json:"root"`
	Source   string `json:"source"`
}

type coverageInfo struct {
	Covered int `json:"covered"`
	Total   int `json:"count"`
}

type coverageTotals struct {
	ByFunction coverageInfo `json:"functions"`
	ByLine     coverageInfo `json:"lines"`
	ByRegion   coverageInfo `json:"regions"`
}

type coverageData struct {
	Totals coverageTotals `json:"totals"`
}

type coverageSummary struct {
	Data []coverageData `json:"data"`
}

func latestReportInfoDir(bucket string) string {
	return buckets.BuildURL(gcs.Scheme, bucket, "latest_report_info/")
}

func constructKey(fuzzer, date string) string {
	return fuzzer + "-" + date
}

// coverageInformation reads coverage summary file from GCS and constructs
// CoverageInformation entity out of it.
func coverageInformation(ctx context.Context, info latestReportInfo, summaryPath, name string) (*datastore.Key, *types.CoverageInformation, error) {
	var stats coverageSummary
	err := readJSON(ctx, summaryPath, &stats)
	if err != nil {
		return nil, nil, err
	}

	dateObj, err := time.Parse(dateLayout, info.ReportDate)
	if err != nil {
		logs.Errorf("Failed to parse date %s: %+v", info.ReportDate, err)
		return nil, nil, errors.Wrapf(err, "Incorrect date format: %s.", info.ReportDate)
	}

	var coverageInfo types.CoverageInformation
	key := &datastore.Key{
		Kind: "CoverageInformation",
		Name: constructKey(name, info.ReportDate),
	}

	// Ignore the error as we either get an existing entity or create a new one.
	_ = db.Get(ctx, key, &coverageInfo)
	coverageInfo.Fuzzer = name
	coverageInfo.Date = dateObj
	coverageInfo.FunctionsCovered = stats.Data[0].Totals.ByFunction.Covered
	coverageInfo.FunctionsTotal = stats.Data[0].Totals.ByFunction.Total
	coverageInfo.EdgesCovered = stats.Data[0].Totals.ByRegion.Covered
	coverageInfo.EdgesTotal = stats.Data[0].Totals.ByRegion.Total

	// Link to a per project report as long as we don't have per fuzzer reports.
	coverageInfo.HTMLReportURL = info.HTMLReportURL

	return key, &coverageInfo, nil
}

func basename(url string) string {
	base := path.Base(url)
	return strings.TrimSuffix(base, filepath.Ext(base))
}

func projectQualifiedFuzzerName(fuzzer, project string) string {
	// TODO(crbug.com/879288): use initialize env vars from local config.
	if project == "chromium" {
		return fuzzer
	}

	prefix := project + "_"
	if strings.HasPrefix(fuzzer, prefix) {
		return fuzzer
	}

	return prefix + fuzzer
}

// processFuzzerStats processes individual fuzzer stats file and constructs
// types.CoverageInformation object.
func processFuzzerStats(ctx context.Context, objectInfo buckets.ObjectInfo, info latestReportInfo, project string) (*datastore.Key, *types.CoverageInformation, error) {
	fuzzer := projectQualifiedFuzzerName(basename(objectInfo.Name), project)
	logs.Logf("Processing fuzzer stats for %s (%s)", fuzzer, objectInfo.FullPath())
	return coverageInformation(ctx, info, objectInfo.FullPath(), fuzzer)
}

func processGCSDir(ctx context.Context, url string, cb func(context.Context, buckets.ObjectInfo) error) error {
	it, err := buckets.ListObjects(ctx, url, false)
	if err != nil {
		return errors.Wrapf(err, "Failed to list %s.", url)
	}

	var info buckets.ObjectInfo
	for it.Next(&info) {
		err = cb(ctx, info)
		if err != nil {
			return err
		}
	}

	if err = it.Err(); err != nil {
		return errors.Wrapf(err, "Failed to iterate through %s.", url)
	}

	return nil
}

// processProjectStats processess total stats for a single project.
func processProjectStats(ctx context.Context, info latestReportInfo, project string) (*datastore.Key, *types.CoverageInformation, error) {
	logs.Logf("Processing total stats for %s project (%s)", project, info.ReportSummaryPath)

	// Using project name as a fuzzer_name should not cause any problems, as we
	// use project qualified names for fuzz targets and won't have any collisions.
	return coverageInformation(ctx, info, info.ReportSummaryPath, project)
}

// processProject processess latest report info for a single project.
func processProject(ctx context.Context, objectInfo buckets.ObjectInfo) error {
	project := basename(objectInfo.Name)
	logs.Logf("Processing coverage for %s project.", project)

	var info latestReportInfo
	err := readJSON(ctx, objectInfo.FullPath(), &info)
	if err != nil {
		return err
	}

	// Iterate through info.FuzzerStatsDir and prepare coverage information for
	// invididual fuzz targets.
	var keys []*datastore.Key
	var entities []*types.CoverageInformation
	processGCSDir(ctx, info.FuzzerStatsDir, func(ctx context.Context, objectInfo buckets.ObjectInfo) error {
		key, entity, err := processFuzzerStats(ctx, objectInfo, info, project)
		if err != nil {
			return err
		}

		keys = append(keys, key)
		entities = append(entities, entity)
		return nil
	})

	logs.Logf("Processed coverage for %d targets in %s project.", len(keys), project)

	key, entity, err := processProjectStats(ctx, info, project)
	if err != nil {
		logs.Errorf("Failed to processProjectStats for %s: %+v", project, err)
	} else {
		keys = append(keys, key)
		entities = append(entities, entity)
	}

	_, err = db.PutMulti(ctx, keys, entities)
	return err
}

func readJSON(ctx context.Context, url string, data interface{}) error {
	obj, err := buckets.ReadObject(ctx, url)
	if err != nil {
		return errors.Wrapf(err, "Failed to read %s into json.", url)
	}

	err = json.NewDecoder(obj).Decode(&data)
	if err != nil {
		return errors.Wrapf(err, "Failed to decode %s as json.", url)
	}

	return nil
}

// FuzzerCoverage gets the latest code coverage stats and links to reports.
func FuzzerCoverage(w http.ResponseWriter, r *http.Request) {
	cfg := config.NewProjectConfig()
	bucket := cfg.GetString("coverage.reports.bucket")
	url := latestReportInfoDir(bucket)
	err := processGCSDir(r.Context(), url, processProject)
	if err != nil {
		logs.Errorf("Failed to processProject in %s: %+v", url, err)
	} else {
		logs.Logf("FuzzerCoverage task finished successfully.")
	}
}
