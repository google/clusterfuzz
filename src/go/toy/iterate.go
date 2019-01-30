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

// Simple toy example to iterate through all open testcases.
package main

import (
	"context"
	"fmt"
	"log"

	"clusterfuzz/go/cloud/db"
	"clusterfuzz/go/cloud/db/types"
)

func main() {
	db.Init()

	q := db.GetOpenTestcasesQuery()
	var t types.Testcase
	it := db.RunQuery(context.Background(), q)

	for it.Next(&t) {
		fmt.Printf("%d\n", t.Key.ID)
	}
	if err := it.Err(); err != nil {
		log.Fatalf("Failed to retrieve testcases: %+v", err)
	}

}
