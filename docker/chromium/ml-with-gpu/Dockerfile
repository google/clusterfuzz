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

# The dependencies installation commands below follow
# https://www.tensorflow.org/install/gpu#ubuntu_1604_cuda_101.
#
# Add NVIDIA package repositories.
# Add HTTPS support for apt-key.
RUN apt-get install -y gnupg-curl && \
    wget https://developer.download.nvidia.com/compute/cuda/repos/ubuntu1604/x86_64/cuda-repo-ubuntu1604_10.1.243-1_amd64.deb && \
    apt-key adv --fetch-keys https://developer.download.nvidia.com/compute/cuda/repos/ubuntu1604/x86_64/7fa2af80.pub && \
    dpkg -i cuda-repo-ubuntu1604_10.1.243-1_amd64.deb && \
    apt-get update && \
    wget https://developer.download.nvidia.com/compute/machine-learning/repos/ubuntu1604/x86_64/nvidia-machine-learning-repo-ubuntu1604_1.0.0-1_amd64.deb && \
    apt install -y ./nvidia-machine-learning-repo-ubuntu1604_1.0.0-1_amd64.deb && \
    apt-get update && \
    rm -f cuda-repo-* nvidia-machine-learning-repo-*

# Install development and runtime libraries (~4GB).
RUN apt-get install -y --no-install-recommends \
    cuda-10-1 \
    libcudnn7=7.6.4.38-1+cuda10.1  \
    libcudnn7-dev=7.6.4.38-1+cuda10.1

# Install TensorRT. Requires that libcudnn7 is installed above.
RUN apt-get install -y --no-install-recommends \
    libnvinfer6=6.0.1-1+cuda10.1 \
    libnvinfer-dev=6.0.1-1+cuda10.1 \
    libnvinfer-plugin6=6.0.1-1+cuda10.1

# Replace TensorFlow CPU version with GPU version. Also the version number
# needs to match cuda and cuDNN version above.
RUN python3 -m pip uninstall tensorflow -y && \
    python3 -m pip uninstall tensorboard -y && \
    python3 -m pip install mock==2.0.0 && \
    python3 -m pip install tensorflow-gpu==2.3.0

WORKDIR $INSTALL_DIRECTORY

# Used by the bots to decide whether the ML task queue should be used.
ENV ML True
