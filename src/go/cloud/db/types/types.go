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

// Package types contains Datastore types (auto-generated from src/python/datastore/data_types.py).
// Please modify data_types.py and run `python butler.py generate_datastore_models` if you wish to modify a model.
package types

import (
	"time"

	"cloud.google.com/go/datastore"
)

// Admin is auto-generated from data_types.py.
type Admin struct {
	Key   *datastore.Key `datastore:"__key__"`
	Email string         `datastore:"email"`
}

// Blacklist is auto-generated from data_types.py.
type Blacklist struct {
	Key          *datastore.Key `datastore:"__key__"`
	FunctionName string         `datastore:"function_name"`
	ToolName     string         `datastore:"tool_name"`
	TestcaseID   int            `datastore:"testcase_id"`
}

// BuildCrashStatsJobHistory is auto-generated from data_types.py.
type BuildCrashStatsJobHistory struct {
	Key            *datastore.Key `datastore:"__key__"`
	EndTimeInHours int            `datastore:"end_time_in_hours"`
}

// BuildMetadata is auto-generated from data_types.py.
type BuildMetadata struct {
	Key           *datastore.Key `datastore:"__key__"`
	JobType       string         `datastore:"job_type"`
	Revision      int            `datastore:"revision"`
	BadBuild      bool           `datastore:"bad_build"`
	ConsoleOutput string         `datastore:"console_output,noindex"`
	BotName       string         `datastore:"bot_name"`
	Symbols       string         `datastore:"symbols"`
	Timestamp     time.Time      `datastore:"timestamp"`
}

// BundledArchiveMetadata is auto-generated from data_types.py.
type BundledArchiveMetadata struct {
	Key                  *datastore.Key `datastore:"__key__"`
	BlobstoreKey         string         `datastore:"blobstore_key"`
	Timeout              int            `datastore:"timeout"`
	JobQueue             string         `datastore:"job_queue"`
	JobType              string         `datastore:"job_type"`
	HTTPFlag             bool           `datastore:"http_flag"`
	ArchiveFilename      string         `datastore:"archive_filename"`
	UploaderEmail        string         `datastore:"uploader_email"`
	Gestures             []string       `datastore:"gestures"`
	CrashRevision        int            `datastore:"crash_revision"`
	AdditionalArguments  string         `datastore:"additional_arguments"`
	BugInformation       string         `datastore:"bug_information"`
	PlatformID           string         `datastore:"platform_id"`
	AppLaunchCommand     string         `datastore:"app_launch_command"`
	FuzzerName           string         `datastore:"fuzzer_name"`
	OverriddenFuzzerName string         `datastore:"overridden_fuzzer_name"`
	FuzzerBinaryName     string         `datastore:"fuzzer_binary_name"`
}

// CSRFToken is auto-generated from data_types.py.
type CSRFToken struct {
	Key            *datastore.Key `datastore:"__key__"`
	Value          string         `datastore:"value"`
	ExpirationTime time.Time      `datastore:"expiration_time"`
	UserEmail      string         `datastore:"user_email"`
}

// Config is auto-generated from data_types.py.
type Config struct {
	Key                                 *datastore.Key `datastore:"__key__"`
	PreviousHash                        string         `datastore:"previous_hash"`
	URL                                 string         `datastore:"url"`
	ClientCredentials                   string         `datastore:"client_credentials,noindex"`
	BuildApiaryServiceAccountEmail      string         `datastore:"build_apiary_service_account_email"`
	BuildApiaryServiceAccountPrivateKey string         `datastore:"build_apiary_service_account_private_key,noindex"`
	TestAccountEmail                    string         `datastore:"test_account_email"`
	TestAccountPassword                 string         `datastore:"test_account_password"`
	PrivilegedUsers                     string         `datastore:"privileged_users,noindex"`
	ContactString                       string         `datastore:"contact_string"`
	ComponentRepositoryMappings         string         `datastore:"component_repository_mappings,noindex"`
	ReproductionHelpURL                 string         `datastore:"reproduction_help_url"`
	DocumentationURL                    string         `datastore:"documentation_url"`
	BugReportURL                        string         `datastore:"bug_report_url"`
	PlatformGroupMappings               string         `datastore:"platform_group_mappings,noindex"`
	RelaxTestcaseRestrictions           bool           `datastore:"relax_testcase_restrictions"`
	RelaxSecurityBugRestrictions        bool           `datastore:"relax_security_bug_restrictions"`
	CoverageReportsBucket               string         `datastore:"coverage_reports_bucket"`
	GithubCredentials                   string         `datastore:"github_credentials"`
	ReproduceToolClientID               string         `datastore:"reproduce_tool_client_id"`
	ReproduceToolClientSecret           string         `datastore:"reproduce_tool_client_secret"`
	PredatorCrashTopic                  string         `datastore:"predator_crash_topic"`
	PredatorResultTopic                 string         `datastore:"predator_result_topic"`
	WifiSsid                            string         `datastore:"wifi_ssid"`
	WifiPassword                        string         `datastore:"wifi_password"`
	SendgridApiKey                      string         `datastore:"sendgrid_api_key"`
	SendgridSender                      string         `datastore:"sendgrid_sender"`
}

// CoverageInformation is auto-generated from data_types.py.
type CoverageInformation struct {
	Key                  *datastore.Key `datastore:"__key__"`
	Date                 time.Time      `datastore:"date"`
	Fuzzer               string         `datastore:"fuzzer"`
	FunctionsCovered     int            `datastore:"functions_covered"`
	FunctionsTotal       int            `datastore:"functions_total"`
	EdgesCovered         int            `datastore:"edges_covered"`
	EdgesTotal           int            `datastore:"edges_total"`
	CorpusSizeUnits      int            `datastore:"corpus_size_units"`
	CorpusSizeBytes      int            `datastore:"corpus_size_bytes"`
	CorpusLocation       string         `datastore:"corpus_location"`
	CorpusBackupLocation string         `datastore:"corpus_backup_location"`
	QuarantineSizeUnits  int            `datastore:"quarantine_size_units"`
	QuarantineSizeBytes  int            `datastore:"quarantine_size_bytes"`
	QuarantineLocation   string         `datastore:"quarantine_location"`
	HTMLReportURL        string         `datastore:"html_report_url"`
}

// DataBundle is auto-generated from data_types.py.
type DataBundle struct {
	Key          *datastore.Key `datastore:"__key__"`
	Name         string         `datastore:"name"`
	BucketName   string         `datastore:"bucket_name"`
	Source       string         `datastore:"source"`
	IsLocal      bool           `datastore:"is_local"`
	Timestamp    time.Time      `datastore:"timestamp"`
	SyncToWorker bool           `datastore:"sync_to_worker"`
}

// ExternalUserPermission is auto-generated from data_types.py.
type ExternalUserPermission struct {
	Key        *datastore.Key `datastore:"__key__"`
	Email      string         `datastore:"email"`
	EntityKind int            `datastore:"entity_kind"`
	EntityName string         `datastore:"entity_name"`
	IsPrefix   bool           `datastore:"is_prefix"`
	AutoCC     int            `datastore:"auto_cc"`
}

// FiledBug is auto-generated from data_types.py.
type FiledBug struct {
	Key            *datastore.Key `datastore:"__key__"`
	Timestamp      time.Time      `datastore:"timestamp"`
	TestcaseID     int            `datastore:"testcase_id"`
	BugInformation int            `datastore:"bug_information"`
	GroupID        int            `datastore:"group_id"`
	CrashType      string         `datastore:"crash_type"`
	CrashState     string         `datastore:"crash_state"`
	SecurityFlag   bool           `datastore:"security_flag"`
	PlatformID     string         `datastore:"platform_id"`
}

// FuzzStrategyProbability is auto-generated from data_types.py.
type FuzzStrategyProbability struct {
	Key          *datastore.Key `datastore:"__key__"`
	StrategyName string         `datastore:"strategy_name"`
	Probability  float64        `datastore:"probability"`
	Engine       string         `datastore:"engine"`
}

// FuzzTarget is auto-generated from data_types.py.
type FuzzTarget struct {
	Key     *datastore.Key `datastore:"__key__"`
	Engine  string         `datastore:"engine"`
	Project string         `datastore:"project"`
	Binary  string         `datastore:"binary"`
}

// FuzzTargetJob is auto-generated from data_types.py.
type FuzzTargetJob struct {
	Key            *datastore.Key `datastore:"__key__"`
	FuzzTargetName string         `datastore:"fuzz_target_name"`
	Job            string         `datastore:"job"`
	Engine         string         `datastore:"engine"`
	Weight         float64        `datastore:"weight"`
	LastRun        time.Time      `datastore:"last_run"`
}

// FuzzTargetsCount is auto-generated from data_types.py.
type FuzzTargetsCount struct {
	Key   *datastore.Key `datastore:"__key__"`
	Count int            `datastore:"count,noindex"`
}

// Fuzzer is auto-generated from data_types.py.
type Fuzzer struct {
	Key                         *datastore.Key `datastore:"__key__"`
	Timestamp                   time.Time      `datastore:"timestamp"`
	Name                        string         `datastore:"name"`
	Filename                    string         `datastore:"filename"`
	BlobstoreKey                string         `datastore:"blobstore_key"`
	FileSize                    string         `datastore:"file_size"`
	ExecutablePath              string         `datastore:"executable_path"`
	Revision                    int            `datastore:"revision"`
	Source                      string         `datastore:"source"`
	Timeout                     int            `datastore:"timeout"`
	SupportedPlatforms          string         `datastore:"supported_platforms"`
	LauncherScript              string         `datastore:"launcher_script"`
	Result                      string         `datastore:"result"`
	ResultTimestamp             time.Time      `datastore:"result_timestamp"`
	ConsoleOutput               string         `datastore:"console_output,noindex"`
	ReturnCode                  int            `datastore:"return_code"`
	SampleTestcase              string         `datastore:"sample_testcase"`
	Jobs                        []string       `datastore:"jobs"`
	ExternalContribution        bool           `datastore:"external_contribution"`
	MaxTestcases                int            `datastore:"max_testcases"`
	UntrustedContent            bool           `datastore:"untrusted_content"`
	DataBundleName              string         `datastore:"data_bundle_name"`
	AdditionalEnvironmentString string         `datastore:"additional_environment_string,noindex"`
	StatsColumns                string         `datastore:"stats_columns,noindex"`
	StatsColumnDescriptions     string         `datastore:"stats_column_descriptions,noindex"`
	Builtin                     bool           `datastore:"builtin,noindex"`
	Differential                bool           `datastore:"differential"`
}

// FuzzerJob is auto-generated from data_types.py.
type FuzzerJob struct {
	Key        *datastore.Key `datastore:"__key__"`
	Fuzzer     string         `datastore:"fuzzer"`
	Job        string         `datastore:"job"`
	Platform   string         `datastore:"platform"`
	Weight     float64        `datastore:"weight"`
	Multiplier float64        `datastore:"multiplier"`
}

// Heartbeat is auto-generated from data_types.py.
type Heartbeat struct {
	Key           *datastore.Key `datastore:"__key__"`
	BotName       string         `datastore:"bot_name"`
	LastBeatTime  time.Time      `datastore:"last_beat_time"`
	TaskPayload   string         `datastore:"task_payload"`
	TaskEndTime   time.Time      `datastore:"task_end_time"`
	SourceVersion string         `datastore:"source_version"`
}

// HostWorkerAssignment is auto-generated from data_types.py.
type HostWorkerAssignment struct {
	Key         *datastore.Key `datastore:"__key__"`
	HostName    string         `datastore:"host_name"`
	InstanceNum int            `datastore:"instance_num"`
	WorkerName  string         `datastore:"worker_name"`
	ProjectName string         `datastore:"project_name"`
}

// Job is auto-generated from data_types.py.
type Job struct {
	Key                  *datastore.Key `datastore:"__key__"`
	Name                 string         `datastore:"name"`
	EnvironmentString    string         `datastore:"environment_string,noindex"`
	Platform             string         `datastore:"platform"`
	CustomBinaryKey      string         `datastore:"custom_binary_key"`
	CustomBinaryFilename string         `datastore:"custom_binary_filename"`
	CustomBinaryRevision int            `datastore:"custom_binary_revision"`
	Description          string         `datastore:"description,noindex"`
	Templates            []string       `datastore:"templates"`
	Project              string         `datastore:"project"`
}

// JobTemplate is auto-generated from data_types.py.
type JobTemplate struct {
	Key               *datastore.Key `datastore:"__key__"`
	Name              string         `datastore:"name"`
	EnvironmentString string         `datastore:"environment_string,noindex"`
}

// Lock is auto-generated from data_types.py.
type Lock struct {
	Key            *datastore.Key `datastore:"__key__"`
	ExpirationTime time.Time      `datastore:"expiration_time"`
	Holder         string         `datastore:"holder"`
}

// Notification is auto-generated from data_types.py.
type Notification struct {
	Key        *datastore.Key `datastore:"__key__"`
	TestcaseID int            `datastore:"testcase_id"`
	UserEmail  string         `datastore:"user_email"`
}

// OssFuzzBuildFailure is auto-generated from data_types.py.
type OssFuzzBuildFailure struct {
	Key                  *datastore.Key `datastore:"__key__"`
	ProjectName          string         `datastore:"project_name"`
	IssueID              string         `datastore:"issue_id"`
	LastCheckedTimestamp time.Time      `datastore:"last_checked_timestamp"`
	ConsecutiveFailures  int            `datastore:"consecutive_failures"`
	BuildType            string         `datastore:"build_type"`
}

// OssFuzzProject is auto-generated from data_types.py.
type OssFuzzProject struct {
	Key            *datastore.Key `datastore:"__key__"`
	Name           string         `datastore:"name"`
	HighEnd        bool           `datastore:"high_end"`
	CPUWeight      float64        `datastore:"cpu_weight"`
	DiskSizeGb     int            `datastore:"disk_size_gb"`
	ServiceAccount string         `datastore:"service_account"`
	CCs            []string       `datastore:"ccs"`
}

// OssFuzzProjectInfo is auto-generated from data_types.py.
type OssFuzzProjectInfo struct {
	Key      *datastore.Key `datastore:"__key__"`
	Name     string         `datastore:"name"`
	Clusters []ClusterInfo  `datastore:"clusters"`
}

// ClusterInfo is auto-generated from data_types.py.
type ClusterInfo struct {
	Key      *datastore.Key `datastore:"__key__"`
	Cluster  string         `datastore:"cluster"`
	CPUCount int            `datastore:"cpu_count"`
	GCEZone  string         `datastore:"gce_zone"`
}

// ReportMetadata is auto-generated from data_types.py.
type ReportMetadata struct {
	Key                        *datastore.Key `datastore:"__key__"`
	JobType                    string         `datastore:"job_type"`
	CrashRevision              int            `datastore:"crash_revision"`
	IsUploaded                 bool           `datastore:"is_uploaded"`
	Product                    string         `datastore:"product"`
	Version                    string         `datastore:"version,noindex"`
	MinidumpKey                string         `datastore:"minidump_key,noindex"`
	SerializedCrashStackFrames []byte         `datastore:"serialized_crash_stack_frames,noindex"`
	TestcaseID                 string         `datastore:"testcase_id"`
	BotID                      string         `datastore:"bot_id,noindex"`
	OptionalParams             string         `datastore:"optional_params,noindex"`
	CrashReportID              string         `datastore:"crash_report_id"`
}

// TaskStatus is auto-generated from data_types.py.
type TaskStatus struct {
	Key     *datastore.Key `datastore:"__key__"`
	BotName string         `datastore:"bot_name"`
	Status  string         `datastore:"status"`
	Time    time.Time      `datastore:"time"`
}

// Testcase is auto-generated from data_types.py.
type Testcase struct {
	Key                        *datastore.Key `datastore:"__key__"`
	CrashType                  string         `datastore:"crash_type"`
	CrashAddress               string         `datastore:"crash_address,noindex"`
	CrashState                 string         `datastore:"crash_state"`
	CrashStacktrace            string         `datastore:"crash_stacktrace,noindex"`
	LastTestedCrashStacktrace  string         `datastore:"last_tested_crash_stacktrace,noindex"`
	FuzzedKeys                 string         `datastore:"fuzzed_keys,noindex"`
	MinimizedKeys              string         `datastore:"minimized_keys,noindex"`
	MinidumpKeys               string         `datastore:"minidump_keys,noindex"`
	BugInformation             string         `datastore:"bug_information"`
	Regression                 string         `datastore:"regression"`
	Fixed                      string         `datastore:"fixed"`
	SecurityFlag               bool           `datastore:"security_flag"`
	SecuritySeverity           int            `datastore:"security_severity,noindex"`
	OneTimeCrasherFlag         bool           `datastore:"one_time_crasher_flag"`
	Comments                   string         `datastore:"comments,noindex"`
	CrashRevision              int            `datastore:"crash_revision"`
	OriginalAbsolutePath       string         `datastore:"original_absolute_path,noindex"`
	AbsolutePath               string         `datastore:"absolute_path,noindex"`
	MinimizedArguments         string         `datastore:"minimized_arguments,noindex"`
	WindowArgument             string         `datastore:"window_argument,noindex"`
	JobType                    string         `datastore:"job_type"`
	Queue                      string         `datastore:"queue,noindex"`
	ArchiveState               int            `datastore:"archive_state,noindex"`
	ArchiveFilename            string         `datastore:"archive_filename,noindex"`
	BinaryFlag                 bool           `datastore:"binary_flag,noindex"`
	Timestamp                  time.Time      `datastore:"timestamp"`
	FlakyStack                 bool           `datastore:"flaky_stack,noindex"`
	HTTPFlag                   bool           `datastore:"http_flag,noindex"`
	FuzzerName                 string         `datastore:"fuzzer_name"`
	Status                     string         `datastore:"status"`
	DuplicateOf                int            `datastore:"duplicate_of,noindex"`
	Symbolized                 bool           `datastore:"symbolized,noindex"`
	GroupID                    int            `datastore:"group_id"`
	GroupBugInformation        int            `datastore:"group_bug_information"`
	Gestures                   []string       `datastore:"gestures,noindex"`
	Redzone                    int            `datastore:"redzone,noindex"`
	DisableUbsan               bool           `datastore:"disable_ubsan"`
	Open                       bool           `datastore:"open"`
	TimeoutMultiplier          float64        `datastore:"timeout_multiplier,noindex"`
	AdditionalMetadata         string         `datastore:"additional_metadata,noindex"`
	Triaged                    bool           `datastore:"triaged"`
	ProjectName                string         `datastore:"project_name"`
	Keywords                   []string       `datastore:"keywords"`
	HasBugFlag                 bool           `datastore:"has_bug_flag"`
	BugIndices                 []string       `datastore:"bug_indices"`
	OverriddenFuzzerName       string         `datastore:"overridden_fuzzer_name"`
	Platform                   string         `datastore:"platform"`
	PlatformID                 string         `datastore:"platform_id"`
	ImpactIndices              []string       `datastore:"impact_indices"`
	IsADuplicateFlag           bool           `datastore:"is_a_duplicate_flag"`
	IsLeader                   bool           `datastore:"is_leader"`
	FuzzerNameIndices          []string       `datastore:"fuzzer_name_indices"`
	ImpactVersionIndices       []string       `datastore:"impact_version_indices"`
	ImpactStableVersion        string         `datastore:"impact_stable_version"`
	ImpactStableVersionIndices []string       `datastore:"impact_stable_version_indices"`
	ImpactStableVersionLikely  bool           `datastore:"impact_stable_version_likely"`
	ImpactBetaVersion          string         `datastore:"impact_beta_version"`
	ImpactBetaVersionIndices   []string       `datastore:"impact_beta_version_indices"`
	ImpactBetaVersionLikely    bool           `datastore:"impact_beta_version_likely"`
	IsImpactSetFlag            bool           `datastore:"is_impact_set_flag"`
	UploaderEmail              string         `datastore:"uploader_email"`
}

// TestcaseGroup is auto-generated from data_types.py.
type TestcaseGroup struct {
	Key *datastore.Key `datastore:"__key__"`
}

// TestcaseUploadMetadata is auto-generated from data_types.py.
type TestcaseUploadMetadata struct {
	Key                      *datastore.Key `datastore:"__key__"`
	Timestamp                time.Time      `datastore:"timestamp"`
	Filename                 string         `datastore:"filename"`
	Status                   string         `datastore:"status"`
	UploaderEmail            string         `datastore:"uploader_email"`
	BotName                  string         `datastore:"bot_name"`
	TestcaseID               int            `datastore:"testcase_id"`
	DuplicateOf              int            `datastore:"duplicate_of"`
	BlobstoreKey             string         `datastore:"blobstore_key"`
	Timeout                  int            `datastore:"timeout"`
	Bundled                  bool           `datastore:"bundled"`
	PathInArchive            string         `datastore:"path_in_archive,noindex"`
	OriginalBlobstoreKey     string         `datastore:"original_blobstore_key"`
	SecurityFlag             bool           `datastore:"security_flag"`
	Retries                  int            `datastore:"retries"`
	BugSummaryUpdateFlag     bool           `datastore:"bug_summary_update_flag"`
	QuietFlag                bool           `datastore:"quiet_flag"`
	AdditionalMetadataString string         `datastore:"additional_metadata_string,noindex"`
}

// TestcaseVariant is auto-generated from data_types.py.
type TestcaseVariant struct {
	Key           *datastore.Key `datastore:"__key__"`
	TestcaseID    int            `datastore:"testcase_id"`
	Status        int            `datastore:"status"`
	JobType       string         `datastore:"job_type"`
	Revision      int            `datastore:"revision"`
	CrashType     string         `datastore:"crash_type"`
	CrashState    string         `datastore:"crash_state"`
	SecurityFlag  bool           `datastore:"security_flag"`
	IsSimilar     bool           `datastore:"is_similar"`
	ReproducerKey string         `datastore:"reproducer_key"`
}

// Trial is auto-generated from data_types.py.
type Trial struct {
	Key         *datastore.Key `datastore:"__key__"`
	AppName     string         `datastore:"app_name"`
	Probability float64        `datastore:"probability"`
	AppArgs     string         `datastore:"app_args,noindex"`
}

// WorkerTlsCert is auto-generated from data_types.py.
type WorkerTlsCert struct {
	Key          *datastore.Key `datastore:"__key__"`
	ProjectName  string         `datastore:"project_name"`
	CertContents []byte         `datastore:"cert_contents,noindex"`
	KeyContents  []byte         `datastore:"key_contents,noindex"`
}
