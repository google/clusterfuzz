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
FROM gcr.io/clusterfuzz-images/base

COPY start_gvisor.sh /data/start.sh
COPY setup_gcloud.sh /data/setup_gcloud.sh
RUN cp /bin/true /bin/mount
RUN cp /bin/true /bin/chown

CMD ["bash", "-ex", "/data/start.sh"]
