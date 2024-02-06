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
import random

from clusterfuzz._internal.metrics import logs
import time

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
          'network': 'projects/google.com:clusterfuzz/global/networks/batch',
          'subnetwork': 'projects/google.com:clusterfuzz/regions/us-west1/subnetworks/us-west1a',
      }],
  # 'networkInterfaces': [{
  #     'network': 'global/networks/default',
  #     'accessConfigs': [{
  #         'type': 'ONE_TO_ONE_NAT',
  #         'name': 'External NAT'
  #     }]
  # }],
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
  },
  'metadata': {
      'items': [{'key': 'mykey', 'value': 'myvalue'}]
  },
}


bulk_body = {
  'namePattern': 'jonbulk-######',
  'instanceProperties': {
      'disks': [{
          'boot': True,
          'autoDelete': True,
          'initializeParams': {
              'sourceImage': 'projects/cos-cloud/global/images/family/cos-stable'
          }
      }],
      'machineType': 'n1-standard-1',
      'networkInterfaces': [{
          'network': 'projects/google.com:clusterfuzz/global/networks/batch',
          'subnetwork': 'projects/google.com:clusterfuzz/regions/us-west1/subnetworks/us-west1a',
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
}

zone_bulk2_body = {
  'namePattern': 'jonbulk-######',
  'instanceProperties': {
      'disks': [{
          'boot': True,
          'autoDelete': True,
          'initializeParams': {
              'sourceImage': 'projects/cos-cloud/global/images/family/cos-stable'
          }
      }],
      'machineType': 'n1-standard-1',
      # 'networkInterfaces': [{
      #     'network': 'projects/google.com:clusterfuzz/global/networks/batch',
      #     'subnetwork': 'projects/google.com:clusterfuzz/regions/us-west1/subnetworks/us-west1a',
      # }],
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
}

zone_bulk_body = {
  # 'namePattern': 'jonbulk-######',
  'instanceProperties': {
      'disks': [{
          'boot': True,
          'autoDelete': True,
          'initializeParams': {
              'sourceImage': 'projects/cos-cloud/global/images/family/cos-stable'
          }
      }],
      'machineType': 'n1-standard-1',
      'networkInterfaces': [{
          'network': 'projects/google.com:clusterfuzz/global/networks/batch',
          'subnetwork': 'projects/google.com:clusterfuzz/regions/us-west1/subnetworks/us-west1a',
      }],
  #     'networkInterfaces': [{
  #     'network': 'global/networks/default',
  #     'accessConfigs': [{
  #         'type': 'ONE_TO_ONE_NAT',
  #         'name': 'External NAT'
  #     }]
  # }],
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
}

def create(name):
  body = instance_body.copy()
  body['name'] = name
  try:
    request = compute.instances().insert(project=project, zone=zone, body=body)
    response = request.execute()
  except Exception as e:
    print(e)
    return
  return response


def create_bulk(count):
  body = bulk_body.copy()
  body['count'] = count
  request = compute.regionInstances().bulkInsert(project=project, region='us-west1', body=body)
  response = request.execute()
  return response


def create_zone_bulk(count):
  body = zone_bulk_body.copy()
  body['count'] = count
  per_instance_properties = {
      f'jonbulki2222-{idx}' : {
        'metadata': {
          'items': [{'key': 'mykey', 'value': f'{idx}'}]
        }
      }
      for idx in range(count)}
  body['perInstanceProperties'] = per_instance_properties
  print(body)
  zones = [# 'us-west1-b', 'us-west1-c',
           'us-west1-a']
  zone = random.choice(zones)
  print(zone)
  request = compute.instances().bulkInsert(project=project, zone=zone, body=body)
  response = request.execute()
  print(response)
  return response


def create_zone_bulk2(count):
  body = zone_bulk2_body.copy()
  body['count'] = count
  zones = [# 'us-west1-b', 'us-west1-c',
           'us-west2-a']
  zone = random.choice(zones)
  print(zone)
  request = compute.instances().bulkInsert(project=project, zone=zone, body=body)
  response = request.execute()
  print(response)
  return response



def delete(name):
  try:
    req = compute.instances().delete(project=project, zone=zone, instance=name)
    req.execute()
  except Exception as e:
    print(e)


def test():
  # x=create('jon-vm-3')
  start = time.time()
  pool = multiprocessing.Pool(int(multiprocessing.cpu_count() * 10))
  total = 15000
  # for _ in range(10):
  #   start = time.time()
  #   create(f'jons228z{_}')
  #   # print(create)
  #   end = time.time()
  #   print(end-start)

  for idx in range(3):
    x=pool.map(create, [f'jons2a28zu{idx}-{s}' for s in range(5000)])
    print('done')
    time.sleep(20)
  end = time.time()
  print('total', end-start)
  # Seems to be about 60 seconds between regional bulk inserts.
  # create_zone_bulk(5000)
  # create_zone_bulk(2)
  # create('jonbulkij')
  # import time
  # for _ in range(3):
  #   print('start')
  #   # time.sleep(60)
  #   create_zone_bulk(5000)
  #   print('done')
  # import pdb; pdb.set_trace()

if __name__ == '__main__':
  import multiprocessing
  multiprocessing.set_start_method('spawn')
  test()
