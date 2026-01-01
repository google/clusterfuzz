# Copyright 2025 Google LLC
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
"clean_jobs.py cleans up pending kubernetes jobs."

import datetime

from local.butler import common


def execute(args):
  """Run the clean_jobs command."""
  # Currently config_dir is unused but required by the argument parser for consistency.
  del args

  namespace = 'default'

  while True:
    print(f'Listing pending jobs in namespace \'{namespace}\'...')

    # Get list of pending jobs by checking for pending pods.
    # We filter pods with status.phase=Pending and get their owner Job name.
    pending_cmd = (
        "kubectl get pods -n {namespace} "
        "--field-selector=status.phase=Pending "
        "-o jsonpath='{{range .items[*]}}{{.metadata.ownerReferences[?(@.kind==\"Job\")].name}}{{\"\\n\"}}{{end}}'"
    ).format(namespace=namespace)

    return_code, output = common.execute(pending_cmd, print_output=False)
    if return_code != 0:
      print('Failed to list pending pods. Ensure kubectl is configured.')
      return return_code

    jobs = output.decode('utf-8').strip()
    job_list = []
    if jobs:
      # Filter empty strings and deduplicate
      job_list = list(set([j.strip() for j in jobs.split('\n') if j.strip()]))

    # Get running pods older than 6 hours
    print(f'Listing running jobs older than 6 hours in namespace \'{namespace}\'...')
    running_cmd = (
        "kubectl get pods -n {namespace} "
        "--field-selector=status.phase=Running "
        "-o jsonpath='{{range .items[*]}}{{.metadata.creationTimestamp}},{{.metadata.ownerReferences[?(@.kind==\"Job\")].name}}{{\"\\n\"}}{{end}}'"
    ).format(namespace=namespace)

    return_code, output = common.execute(running_cmd, print_output=False)
    if return_code != 0:
      print('Failed to list running pods. Ensure kubectl is configured.')
      return return_code

    running_pods = output.decode('utf-8').strip()
    if running_pods:
      now = datetime.datetime.utcnow()
      cutoff_time = now - datetime.timedelta(hours=6)
      
      for line in running_pods.split('\n'):
        if not line.strip():
          continue
        
        parts = line.strip().split(',')
        if len(parts) != 2:
          continue

        creation_timestamp_str, job_name = parts
        # Format from kubernetes: 2023-10-27T10:00:00Z
        try:
            creation_time = datetime.datetime.strptime(creation_timestamp_str, "%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            print(f"Error parsing date: {creation_timestamp_str}")
            continue

        if creation_time < cutoff_time:
             if job_name:
                job_list.append(job_name)

    # Deduplicate combined list
    job_list = list(set(job_list))
    job_count = len(job_list)
    print(f'Found {job_count} jobs to delete (pending + old running).')

    if job_count < 500:
      print('Job count is under 500. Exiting.')
      break

    # Process in batches
    batch_size = 500
    for i in range(0, job_count, batch_size):
      batch = job_list[i:i + batch_size]
      print(f'Deleting batch of {len(batch)} jobs...')

      # We join with spaces for the command
      delete_cmd = f'kubectl delete jobs -n {namespace} ' + ' '.join(batch)

      # Use execute but we need to handle potential line length issues.
      # common.execute uses shell=True.
      # If the command is too long, it will fail.
      # 500 jobs * 50 chars avg = 25000 chars.
      # Linux ARG_MAX is usually huge (2MB), so 25KB is fine.

      common.execute(delete_cmd)

  print('Finished deleting jobs.')
  return 0
