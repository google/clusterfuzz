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
"""setup.py for libClusterFuzz."""
import setuptools

with open('README.md', 'r') as fh:
  long_description = fh.read()

setuptools.setup(
    name='clusterfuzz',
    version='2.5.4.post3',
    author='ClusterFuzz authors',
    author_email='clusterfuzz-dev@googlegroups.com',
    description='ClusterFuzz',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/google/clusterfuzz',
    packages=setuptools.find_packages(),
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: OS Independent',
    ],
    install_requires=[
        # TODO(ochang): Minimize dependencies.
        'google-api-python-client',
        'google-auth>=1.22.1',
        'google-auth-oauthlib',
        'google-cloud-core',
        'google-cloud-datastore==1.12.0',
        'google-cloud-logging',
        'google-cloud-monitoring',
        'google-cloud-ndb',
        'google-cloud-storage',
        'grpcio',
        'httplib2',
        'mozprocess',
        'oauth2client',
        'protobuf',
        'psutil',
        'pytz',
        'PyYAML',
        'requests',
        'six',
    ],
    package_data={
        'clusterfuzz': ['lib-config/*', 'lib-config/**/*'],
    },
    python_requires='>=3.7',
    zip_safe=False,
)
