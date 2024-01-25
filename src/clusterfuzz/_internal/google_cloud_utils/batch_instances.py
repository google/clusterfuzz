# Copyright 2024 Google LLC
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
"""Cloud Batch helpers."""
from googleapiclient import discovery

from clusterfuzz._internal.metrics import logs

project = 'google.com:clusterfuzz'
zone = 'us-west1-a'

compute = discovery.build('compute', 'beta')


MAX_RUN_DURATION_SECONDS = 60 * .5



instance_body = {
  'name': 'jon-vm',
  'machineType': 'zones/us-west1-a/machineTypes/n1-standard-1',
  'disks': [{
      'boot': True,
      'autoDelete': True,
      'initializeParams': {
          'sourceImage': 'projects/cos-cloud/global/images/family/cos-stable'
      }
  }],
  'networkInterfaces': [{
      'network': 'global/networks/default',
      'accessConfigs': [{
          'type': 'ONE_TO_ONE_NAT',
          'name': 'External NAT'
      }]
  }],
  'serviceAccounts': [{
      'email': 'default',
      'scopes': ['https://www.googleapis.com/auth/cloud-platform']
  }],
  'scheduling': {
      'maxRunDuration': {
          'seconds': MAX_RUN_DURATION_SECONDS,
      },
      'instanceTerminationAction': 'DELETE',
      'provisioningModel': 'SPOT',
  }
}

def create(name):
  body = instance_body.copy()
  body['name'] = name
  request = compute.instances().insert(project=project, zone=zone, body=body)
  response = request.execute()
  return response


def delete(name):
  try:
    req = compute.instances().delete(project=project, zone=zone, instance=name)
    req.execute()
  except Exception as e:
    print(e)


def test():
  # x=create('jon-vm-3')
  pool = multiprocessing.Pool(int(multiprocessing.cpu_count() * 2))
  x=pool.map(create, [f'jons2-{s}' for s in range(10000)])
  import pdb; pdb.set_trace()

if __name__ == '__main__':
  import multiprocessing
  multiprocessing.set_start_method('spawn')
  test()
