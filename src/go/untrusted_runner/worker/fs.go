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
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/golang/protobuf/proto"
	"google.golang.org/grpc/metadata"

	"clusterfuzz/go/base/fs"
	pb "clusterfuzz/protos/untrusted_runner"
)

const (
	fileChunkSize = 4096
)

// CreateDirectory creates a directory.
func (s *UntrustedRunnerServer) CreateDirectory(ctx context.Context, req *pb.CreateDirectoryRequest) (*pb.CreateDirectoryResponse, error) {
	result := true
	if err := fs.CreateDirectoryIfNeeded(*req.Path, *req.CreateIntermediates); err != nil {
		result = false
	}

	return &pb.CreateDirectoryResponse{
		Result: proto.Bool(result),
	}, nil
}

// RemoveDirectory removes a directory.
func (s *UntrustedRunnerServer) RemoveDirectory(ctx context.Context, req *pb.RemoveDirectoryRequest) (*pb.RemoveDirectoryResponse, error) {
	result := true
	if err := fs.RemoveDirectory(*req.Path, *req.Recreate); err != nil {
		result = false
	}

	return &pb.RemoveDirectoryResponse{
		Result: proto.Bool(result),
	}, nil
}

// ListFiles lists files in a directory.
func (s *UntrustedRunnerServer) ListFiles(ctx context.Context, req *pb.ListFilesRequest) (*pb.ListFilesResponse, error) {
	var filePaths []string
	var err error

	if *req.Recursive {
		filePaths, err = fs.ListFilesRecursive(*req.Path)
	} else {
		filePaths, err = fs.ListFiles(*req.Path)
	}

	if err != nil {
		return nil, err
	}

	return &pb.ListFilesResponse{
		FilePaths: filePaths,
	}, nil
}

// CopyFileTo copies a file to the worker.
func (s *UntrustedRunnerServer) CopyFileTo(stream pb.UntrustedRunner_CopyFileToServer) error {
	md, ok := metadata.FromIncomingContext(stream.Context())
	if !ok {
		return errors.New("no metadata")
	}

	path := md["path-bin"][0]
	dir := filepath.Dir(path)

	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}

	defer f.Close()
	for {
		chunk, err := stream.Recv()
		if err == io.EOF {
			return stream.SendAndClose(&pb.CopyFileToResponse{
				Result: proto.Bool(true),
			})
		}
		if err != nil {
			return err
		}

		_, err = f.Write(chunk.Data)
		if err != nil {
			return err
		}
	}
}

// CopyFileFrom copies a file from the worker.
func (s *UntrustedRunnerServer) CopyFileFrom(req *pb.CopyFileFromRequest, stream pb.UntrustedRunner_CopyFileFromServer) error {
	if stat, err := os.Stat(*req.Path); err != nil || stat.IsDir() {
		trailer := metadata.Pairs("result", "invalid-path")
		stream.SetTrailer(trailer)
		return nil
	}

	f, err := os.Open(*req.Path)
	if err != nil {
		return err
	}

	defer f.Close()
	data := make([]byte, fileChunkSize)
	for {
		n, err := f.Read(data)
		if err == io.EOF {
			trailer := metadata.Pairs("result", "ok")
			stream.SetTrailer(trailer)
			return nil
		}

		if err != nil {
			return err
		}

		chunk := &pb.FileChunk{
			Data: data[0:n],
		}

		if err = stream.Send(chunk); err != nil {
			return err
		}
	}

	return nil
}

// Stat runs stat() on a file on the worker.
func (s *UntrustedRunnerServer) Stat(ctx context.Context, req *pb.StatRequest) (*pb.StatResponse, error) {
	stat, err := os.Stat(*req.Path)
	if err != nil {
		return &pb.StatResponse{
			Result: proto.Bool(false),
		}, err
	}

	return &pb.StatResponse{
		Result: proto.Bool(true),
		StMode: proto.Uint32(uint32(stat.Mode())),
		StSize: proto.Uint64(uint64(stat.Size())),
		// TODO(ochang): Add remaining fields (platform specific).
	}, nil
}
