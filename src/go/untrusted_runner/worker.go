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

// Untrusted worker process.
package main

import (
	"math"
	"net"
	"path"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"

	"clusterfuzz/go/base/logs"
	"clusterfuzz/go/bots"
	"clusterfuzz/go/cloud/stackdriver"
	"clusterfuzz/go/untrusted_runner/worker"
	pb "clusterfuzz/protos/untrusted_runner"
)

// Init initializes the worker environment.
func Init() {
	bots.SetUpEnvironment()
	logPath := path.Join(bots.LogDir(), "worker_go.log")
	logger, err := stackdriver.Create(logPath)
	if err != nil {
		logs.Panicf("Failed to create logger: %s", err)
	}
	logs.Init(logger)
}

func main() {
	Init()

	certFile, keyFile, err := worker.GetTLSCertAndKey()
	if err != nil {
		logs.Panicf("Failed to get tls cert and key: %s", err)
	}

	creds, err := credentials.NewServerTLSFromFile(certFile, keyFile)
	if err != nil {
		logs.Panicf("Failed to generate credentials: %s", err)
	}

	lis, err := net.Listen("tcp", ":9001")
	if err != nil {
		logs.Panicf("failed to listen:", err)
	}

	srv := grpc.NewServer(
		grpc.Creds(creds),
		grpc.MaxRecvMsgSize(math.MaxInt32),
		grpc.MaxSendMsgSize(math.MaxInt32),
	)

	pb.RegisterHeartbeatServer(srv, &worker.HeartbeatServer{})
	pb.RegisterUntrustedRunnerServer(srv, &worker.UntrustedRunnerServer{time.Now()})
	reflection.Register(srv)

	logs.Logf("Server starting.")
	if err := srv.Serve(lis); err != nil {
		logs.Panicf("Failed to serve: %s", err)
	}
}
