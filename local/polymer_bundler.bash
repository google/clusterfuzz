#!/bin/bash
# Copyright 2019 Google LLC
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

build_one_file() {
  local source_file=$1
  local source_directory=$2
  local deployment_directory=$3
  local deployment_file="${source_file/$source_directory/$deployment_directory}"
  mkdir -p `dirname $deployment_file`
  polymer-bundler --inline-scripts --inline-css --strip-comments --out-file=$deployment_file $source_file &
}

cd $( dirname ${BASH_SOURCE[0]} )/../src/appengine
rm -r templates > /dev/null 2>&1

echo "Building templates for App Engine..."

for source_file in `find private/templates -iname '*.html'`; do
  build_one_file $source_file private/templates templates
done;

while wait -n; do
  sleep 1
done;

if [[ $(find private/templates -size +0 | wc -l) != $(find templates -size +0 | wc -l) ]]; then
  echo "Polymer Bundler build failed. Difference between unbuilt and built files:"
  diff <(find private/templates -size +0 -type f -printf "%f\n" | sort) <(find templates -size +0 -type f -printf "%f\n" | sort)
  exit 1
fi

echo "Finished building templates"
