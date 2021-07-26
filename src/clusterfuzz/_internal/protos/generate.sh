#!/bin/bash
#
# Copyright 2020 Google LLC
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

SCRIPT_DIR=$( readlink -f $( dirname ${BASH_SOURCE[0]} ) )
PARENT_DIR=$( dirname $( dirname $( dirname ${SCRIPT_DIR} ) ) )

python -m grpc_tools.protoc --proto_path=$PARENT_DIR --python_out=$PARENT_DIR --grpc_python_out=$PARENT_DIR $SCRIPT_DIR/*.proto

read -r -d '' COPYRIGHT_HEADER <<EOF
# Copyright 2020 Google LLC
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
EOF

for generated in $SCRIPT_DIR/*pb2*.py; do
  echo -e "$COPYRIGHT_HEADER\n" > /tmp/cf_pb2_temp
  cat "$generated" >> /tmp/cf_pb2_temp
  mv /tmp/cf_pb2_temp "$generated"
done
