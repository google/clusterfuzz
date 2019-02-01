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
FROM gcr.io/clusterfuzz-images/chromium/base

WORKDIR /data

# Note that CUDA Toolkit version might work with only a particular version of
# NVidia drivers, e.g. cuda 9.2 needs drivers 396.37 and cuda 9.0 needs 384.130.
# Drivers are installed in
# clusterfuzz/configs/gce/linux-init-internal-ml-with-gpu.yaml.
# cuDNN packages installed later in this script must match the CUDA version too.

# From https://developer.nvidia.com/cuda-downloads?target_os=Linux&target_arch=x86_64&target_distro=Ubuntu&target_version=1604&target_type=deblocal
RUN wget https://developer.nvidia.com/compute/cuda/9.0/Prod/local_installers/cuda-repo-ubuntu1604-9-0-local_9.0.176-1_amd64-deb -O cuda.deb && \
    dpkg -i cuda.deb && \
    apt-key add /var/cuda-repo-9-0-local/7fa2af80.pub && \
    apt-get update && \
    apt-get install -y cuda

# From (requires registration) https://docs.nvidia.com/deeplearning/sdk/cudnn-install/#installlinux-deb
RUN wget https://storage.googleapis.com/clusterfuzz-data/cudnn/7.1.4_cuda9.0/libcudnn7_7.1.4.18-1%2Bcuda9.0_amd64.deb && \
    wget https://storage.googleapis.com/clusterfuzz-data/cudnn/7.1.4_cuda9.0/libcudnn7-dev_7.1.4.18-1%2Bcuda9.0_amd64.deb && \
    wget https://storage.googleapis.com/clusterfuzz-data/cudnn/7.1.4_cuda9.0/libcudnn7-doc_7.1.4.18-1%2Bcuda9.0_amd64.deb && \
    dpkg -i libcudnn7_*.deb && \
    dpkg -i libcudnn7-dev_*.deb && \
    dpkg -i libcudnn7-doc_*.deb

# Replace TensorFlow CPU version with GPU version. Also the version number
# needs to match cuda and cuDNN version above.
RUN pip uninstall tensorflow -y && \
    pip uninstall tensorboard -y && \
    pip install tensorflow-gpu==1.8.0

WORKDIR $INSTALL_DIRECTORY

# Used by the bots to decide whether the ML task queue should be used.
ENV ML True
