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

package worker

import (
	"context"
	"os"
	"time"

	"github.com/golang/protobuf/proto"

	"clusterfuzz/go/base/environ"
	"clusterfuzz/go/fuzzers"
	pb "clusterfuzz/protos/untrusted_runner"
)

// HeartbeatServer implements the heartbeat gRPC interface.
type HeartbeatServer struct{}

// UntrustedRunnerServer implements the untrusted_runner gRPC interface.
type UntrustedRunnerServer struct {
	StartTime time.Time
}

// Beat responds to a heartbeat request.
func (s *HeartbeatServer) Beat(ctx context.Context, r *pb.HeartbeatRequest) (*pb.HeartbeatResponse, error) {
	return &pb.HeartbeatResponse{}, nil
}

// GetStatus gets information about the worker.
func (s *UntrustedRunnerServer) GetStatus(context.Context, *pb.GetStatusRequest) (*pb.GetStatusResponse, error) {
	return &pb.GetStatusResponse{
		Revision:  proto.String("VERSION"), // TODO(ochang): Get actual revision.
		StartTime: proto.Uint64(uint64(s.StartTime.Unix())),
		BotName:   proto.String(environ.GetValueStr("BOT_NAME")),
	}, nil
}

// SetupRegularBuild sets up a regular build.
func (s *UntrustedRunnerServer) SetupRegularBuild(context.Context, *pb.SetupRegularBuildRequest) (*pb.SetupBuildResponse, error) {
	return nil, nil
}

// SetupSymbolizedBuild sets up a symbolized build.
func (s *UntrustedRunnerServer) SetupSymbolizedBuild(context.Context, *pb.SetupSymbolizedBuildRequest) (*pb.SetupBuildResponse, error) {
	return nil, nil
}

// SetupProductionBuild sets up a production build.
func (s *UntrustedRunnerServer) SetupProductionBuild(context.Context, *pb.SetupProductionBuildRequest) (*pb.SetupBuildResponse, error) {
	return nil, nil
}

// RunProcess runs a process using an interface similar to process_handler.runProcess (python).
func (s *UntrustedRunnerServer) RunProcess(context.Context, *pb.RunProcessRequest) (*pb.RunProcessResponse, error) {
	return nil, nil
}

// RunAndWait runs a process using an interface similar to new_process.ProcessRunner.run_and_wait (python).
func (s *UntrustedRunnerServer) RunAndWait(context.Context, *pb.RunAndWaitRequest) (*pb.RunAndWaitResponse, error) {
	return nil, nil
}

// UpdateEnvironment updates the environment variables on the worker.
func (s *UntrustedRunnerServer) UpdateEnvironment(ctx context.Context, req *pb.UpdateEnvironmentRequest) (*pb.UpdateEnvironmentResponse, error) {
	for key, val := range req.Env {
		if err := os.Setenv(key, val); err != nil {
			return nil, err
		}
	}

	return &pb.UpdateEnvironmentResponse{}, nil
}

// ResetEnvironment resets the environment variables on the worker.
func (s *UntrustedRunnerServer) ResetEnvironment(ctx context.Context, req *pb.ResetEnvironmentRequest) (*pb.ResetEnvironmentResponse, error) {
	// TODO(ochang): implement this.
	return &pb.ResetEnvironmentResponse{}, nil
}

// UpdateSource causes the worker to exit and update its source.
func (s *UntrustedRunnerServer) UpdateSource(context.Context, *pb.UpdateSourceRequest) (*pb.UpdateSourceResponse, error) {
	return nil, nil
}

// SymbolizeStacktrace symbolizes a stacktrace.
func (s *UntrustedRunnerServer) SymbolizeStacktrace(context.Context, *pb.SymbolizeStacktraceRequest) (*pb.SymbolizeStacktraceResponse, error) {
	return nil, nil
}

// TerminateStaleApplicationInstances terminates stale instances on the worker.
func (s *UntrustedRunnerServer) TerminateStaleApplicationInstances(context.Context, *pb.TerminateStaleApplicationInstancesRequest) (*pb.TerminateStaleApplicationInstancesResponse, error) {
	return nil, nil
}

// GetFuzzTargets is a libFuzzer/AFL specific function to return a list of fuzz targets in a directory.
func (s *UntrustedRunnerServer) GetFuzzTargets(ctx context.Context, req *pb.GetFuzzTargetsRequest) (*pb.GetFuzzTargetsResponse, error) {
	targets, err := fuzzers.GetFuzzTargets(*req.Path)
	if err != nil {
		return nil, err
	}

	return &pb.GetFuzzTargetsResponse{
		FuzzTargetPaths: targets,
	}, nil
}

// PruneCorpus is a libFuzzer specific function to run the corpus pruning task.
func (s *UntrustedRunnerServer) PruneCorpus(context.Context, *pb.PruneCorpusRequest) (*pb.PruneCorpusResponse, error) {
	return nil, nil
}

// GetTLSCertAndKey returns the TLS cert and key paths for the gRPC server.
func GetTLSCertAndKey() (string, string, error) {
	localCert := environ.GetValueStr("UNTRUSTED_TLS_CERT_FOR_TESTING")
	localKey := environ.GetValueStr("UNTRUSTED_TLS_KEY_FOR_TESTING")

	// TODO(ochang): Read from metadata.
	return localCert, localKey, nil
}
