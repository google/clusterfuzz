# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Exports Jobs, Fuzzer, DataBundles and their JobTemplates to GCS, 
    in order to mirror the workloads on testing environments."""

import os
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.bot.tasks.utasks import uworker_io


target_entities = [
    (data_types.Fuzzer, ['blobstore_key']),
    (data_types.Job, ['custom_binary_key']),
    (data_types.DataBundle, []),
    (data_types.JobTemplate, []),
]
export_bucket = os.getenv('EXPORT_BUCKET', None)
operation_mode = os.getenv('OPERATION_MODE', None)


class EntityMigrator:
    def __init__(self, target_type, blobstore_keys):
        self.target_type = target_type
        self.blobstore_keys = blobstore_keys

    def export_entities(self):
        pass

    def import_entities(self):
        pass

def process_entities(operation_mode: str):
    for (entity, blobstore_keys) in target_entities:
        migrator = EntityMigrator(entity, blobstore_keys)
        if operation_mode == 'export':
            migrator.export_entities()
        else:
            migrator.import_entities()

def main():
    "Exports datastore entities and respective blobs"

    assert export_bucket
    assert operation_mode in ['import', 'export']

    process_entities(operation_mode)
