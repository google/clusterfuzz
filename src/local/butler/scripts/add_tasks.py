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
"""Add tasks to a queue."""
from clusterfuzz._internal.base import tasks
from clusterfuzz._internal.datastore import data_handler


def execute(args):
  """Adds task to queue. Ignores |args|."""
  del args

  testcase_ids = [
      6370177092354048,
      4744808593555456,
      5227780266459136,
      6574395942174720,
      5244277185511424,
      6510914580709376,
      5775142323945472,
      6011445988753408,
      4906124947947520,
      6530929128308736,
      5352929858879488,
      4822064720445440,
      6196499218104320,
      5648685870284800,
      5743771882815488,
      6572216783142912,
      6312222733041664,
      4645517271171072,
      4563799747002368,
      4938153525706752,
      6726867197296640,
      5648258588147712,
      6071687468482560,
      6341729695236096,
      5161211645591552,
      5737435933638656,
      5841772634636288,
      6063675576090624,
      6283270358499328,
      4920378535116800,
      6026859015766016,
      4797038180892672,
      6469710677737472,
      6733155834724352,
      6217441478639616,
      5871576352227328,
  ]
  for testcase_id in testcase_ids:
    testcase = data_handler.get_testcase_by_id(testcase_id)
    print(f'Restarted {testcase_id}.')
    queue = tasks.default_queue()
    tasks.add_task('analyze', str(testcase_id), testcase.job_type, queue)
