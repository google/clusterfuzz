# Copyright 2026 Google LLC
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

# Install python 3.11.9 from source
wget https://www.python.org/ftp/python/3.11.9/Python-3.11.9.tgz
tar xzf Python-3.11.9.tgz
cd Python-3.11.9
./configure --enable-optimizations --enable-loadable-sqlite-extensions --prefix=$HOME/.localpython --without-ensurepip
make -j$(nproc)
make install
curl -O https://bootstrap.pypa.io/get-pip.py
$HOME/.localpython/bin/python3 get-pip.py
$HOME/.localpython/bin/python3.11 -m pip install pipenv

# Copy distutils to this new install
git clone --branch v3.11.9 https://github.com/python/cpython.git	
cd cpython
cp -r Lib/distutils $HOME/.localpython/lib/python3.11/
