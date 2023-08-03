# Copyright 2019 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
FROM gcr.io/clusterfuzz-images/oss-fuzz/base

COPY start_host.py /data
RUN chmod 644 /data/start_host.py

ENV NUM_WORKERS_PER_HOST 16
ENV DISABLE_MOUNTS True
ENV TRUSTED_HOST True

ENV RUN_CMD "python3.7 /data/start_host.py"
