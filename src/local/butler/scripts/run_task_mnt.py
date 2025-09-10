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
"""Run a task locally."""

import os
import inspect
import sys
import json
import datetime
from collections import defaultdict
from clusterfuzz._internal.bot.fuzzers import init
from clusterfuzz._internal.bot.tasks import commands
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.metrics import events
from clusterfuzz._internal.config import local_config
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.protos import uworker_msg_pb2
from clusterfuzz._internal.datastore import ndb_utils
from clusterfuzz._internal.base import tasks
from clusterfuzz._internal.base import utils
from clusterfuzz._internal.base import errors
from clusterfuzz._internal.issue_management import issue_tracker_utils
from clusterfuzz._internal.cron import grouper

# def execute(args):
#   """Build keywords."""
#   del args
#   environment.set_bot_environment()
#   logs.configure('run_bot')

#   high_end_topic = 'high-end-jobs-linux'
#   high_end_testcases = []

#   # This query is the same used to schedule progression tasks.
#   for status in ['Processed', 'Duplicate']:
#     for testcase in data_types.Testcase.query(
#         ndb_utils.is_true(data_types.Testcase.open),
#         ndb_utils.is_false(data_types.Testcase.one_time_crasher_flag),
#         data_types.Testcase.status == status):
#       testcase_id = testcase.key.id()
#       queue = tasks.queue_for_testcase(testcase)
#       if str(queue) == high_end_topic:
#         high_end_testcases.append(testcase_id)
#         testcase.queue = None
#         new_queue = tasks.queue_for_testcase(testcase)
#         testcase.put()
#         logs.info(f'Updated Testcase {testcase_id} queue. From: {queue} -> To: {new_queue}')

#   logs.info(f'Moved {len(high_end_testcases)} Testcases from topic {high_end_topic}: {high_end_testcases}')
#   print('Finished!')




def _job_to_dict(job):
  """Return a dict of job items along with associated fuzzers."""
  result = job.to_dict()
  result['id'] = job.key.id()
  # Adding all associated fuzzers with each job.
  fuzzers = data_types.Fuzzer.query()
  result['fuzzers'] = [
      fuzzer.name for fuzzer in fuzzers if job.name in fuzzer.jobs

  ]
  return result

def execute(args):
  """Build keywords."""
  environment.set_bot_environment()

  os.environ["LOG_TO_CONSOLE"] = "TRUE"
  os.environ["LOG_TO_GCP"] = ''
  # os.environ["LOCAL_DEVELOPMENT"] = "TRUE"
  logs.configure('run_bot')

  print(f'Starting!\n')

  event_type_count = {}
  for attr, event_type in events.EventTypes.__dict__.items():
    if attr.startswith('_'):
      continue
    print(f'Counting for event={event_type}')
    event_type_count[event_type] = data_types.TestcaseLifecycleEvent.query(
        data_types.TestcaseLifecycleEvent.event_type == event_type
    ).count()

  task_names = [
    'analyze',
    'blame',
    'corpus_pruning',
    'fuzz',
    'impact',
    'minimize',
    'progression',
    'regression',
    'symbolize',
    'variant',
  ]
  task_event_count = {}
  print('\nTask Events:')
  for task_name in task_names:
    print(f'Count task events for {task_name}')
    task_event_count[task_name] = data_types.TestcaseLifecycleEvent.query(
        data_types.TestcaseLifecycleEvent.event_type == 'task_execution',
        data_types.TestcaseLifecycleEvent.task_name == task_name
    ).count()

  print()
  print(event_type_count)
  print(task_event_count)


  filename = 'count_event.txt'
  with open(filename, 'w') as f:
    for event_type, ct in event_type_count.items():
      f.write(f'{event_type} = {ct}\n')
    f.write('\n')
    for task_name, ct in task_event_count.items():
      f.write(f'{task_name} = {ct}\n')

  print('\nDone!')

  # testcase_entity = data_handler.get_testcase_by_id(4860495613853696)
  # testcase_2 = grouper.TestcaseAttributes(testcase_entity.key.id())
  # for attr_name in grouper.FORWARDED_ATTRIBUTES:
  #   setattr(testcase_2, attr_name, getattr(testcase_entity, attr_name))

  # logs.info(f'Grouping testcase {testcase.id} ({grouper._get_testcase_log_info(testcase, False)}) '
  #           f'and testcase {testcase_2.id} ({grouper._get_testcase_log_info(testcase_2, False)}). Reason: similar_crash')

  # logs.info(
  #     'Grouping testcase %s '
  #     '(crash_type=%s, crash_state=%s, security_flag=%s, group=%s) '
  #     'and testcase %s '
  #     '(crash_type=%s, crash_state=%s, security_flag=%s, group=%s). Reason: %s'
  #     % (testcase_1testcase.id, testcase.crash_type, testcase.crash_state,
  #        testcase.security_flag, testcase.group_id, testcase_2.id,
  #        testcase_2.crash_type, testcase_2.crash_state,
  #        testcase_2.security_flag, testcase_2.group_id, 'similar_crash'))


  # rejection_events = ndb_utils.get_all_from_query(data_types.TestcaseLifecycleEvent.query(
  #     data_types.TestcaseLifecycleEvent.rejection_reason == events.RejectionReason.GROUPER_OVERFLOW
  # ))

  # lowest_timestamp = datetime.datetime(2026, 1, 1)
  # for re in rejection_events:
  #   if re.timestamp <= lowest_timestamp:
  #     lowest_timestamp = re.timestamp
  
  # print(lowest_timestamp)


  # dt_format = '%Y/%m/%d %H:%M:%S'
  # time_lower = datetime.datetime.strptime('2025/07/08 18:00:00', dt_format)
  # time_upper = datetime.datetime.strptime('2025/07/09 19:00:00', dt_format)
  # pending_critical_testcases = []
  # pending_progression = []
  # count = 0
  # for testcase in data_types.Testcase.query(
  #     ndb_utils.is_true(data_types.Testcase.open),
  #     data_types.Testcase.timestamp >= time_lower,
  #     data_types.Testcase.timestamp <= time_upper):

  #   count += 1
  #   if not data_handler.critical_tasks_completed(testcase):
  #     testcase_id = testcase.key.id()
  #     pending_critical_testcases.append(testcase_id)
  #   if testcase.get_metadata('progression_pending'):
  #     testcase_id = testcase.key.id()
  #     pending_progression.append(testcase_id)

  # with open('pending_testcases_ossfuzz.txt', 'w') as f:
  #   f.write(f'Pending Critical Tasks ({len(pending_critical_testcases)}):\n')
  #   for tc in pending_critical_testcases:
  #     f.write(f'\tTC: {tc}\n')
  #   f.write(f'Pending Progression ({len(pending_progression)}):\n')
  #   for tc in pending_progression:
  #     f.write(f'\tTC: {tc}\n')

  # print()
  # print(f'Total: {count}')
  # print(f'Pending Critical: {len(pending_critical_testcases)}')
  # print(f'Pending Progression: {len(pending_progression)}')

  # init.run()
  # task = 'progression'
  # testcase_id = '4823144033288192'
  # testcase = data_handler.get_testcase_by_id(testcase_id)
  # job_type = testcase.job_type
  # tasks.add_task(task, testcase_id, job_type, queue=None)
  # commands.process_command_impl('progression', '4807557586223104', 'x86_libfuzzer_chrome_asan',
  #                               True, True)

  # all_jobs = ndb_utils.get_all_from_model(data_types.Job)
  # custom_bin_jobs = set()
  # for job in all_jobs:
  #   job_environment = job.get_environment()
  #   # Skip custom binary jobs.
  #   if utils.string_is_true(job_environment.get('CUSTOM_BINARY')):
  #     custom_bin_jobs.add(job.name)
  
  # print(f'# Custom Bin Jobs: {len(custom_bin_jobs)}')
  # print(f'Custom Bin jobs:{custom_bin_jobs}')

  # custom_bin_jobs = {
  #     'libfuzzer_webp_asan', 'libfuzzer_gradientfuzz_test', 'linux_asan_dart_x64', 'linux_asan_spirv',
  #     'centipede_v8_asan_dbg_custom', 'libfuzzer_asan_bookholt_cmdbuf_lpm', 'linux_msan_chrome_ipc',
  #     'linux_d8_dbg_cm', 'libfuzzer_asan_linux_opensslNVD', 'linux_asan_firefox'}

  # for job_name in custombin_jobs:
  #   print(f'## Job: {job_name}')
  #   job = data_types.Job.query(data_types.Job.name == job_name).get()
  #   job_defintion = _job_to_dict(job)
  #   print(job_defintion)
  #   print()
  #   with open(f'{job_name}.json', 'w') as f:
  #     json.dump(job_defintion, f, indent=4)


  # # job_to_open_testcases = defaultdict(list)
  # for job_name in custom_bin_jobs:
  #   print(f'Job {job_name}:')
  #   for testcase in data_types.Testcase.query(
  #       ndb_utils.is_false(data_types.Testcase.open),
  #       data_types.Testcase.fixed == 'NA',
  #       ndb_utils.is_false(data_types.Testcase.one_time_crasher_flag),
  #       data_types.Testcase.job_type == job_name):
  #     if testcase.get_metadata('progression_pending'):
  #       testcase_id = testcase.key.id()
  #       print(f'\tClearing progression pending for TC: {testcase_id}')
  #       data_handler.clear_progression_pending(testcase)
  #       testcase.put()

  # with open('custom_job_to_testcase.txt', 'w') as f:
  #   for j in job_to_open_testcases:
  #     f.write(f'Job {j}\n')
  #     for tc in job_to_open_testcases[j]:
  #       f.write(f'\tTC: {tc}\n')

  # unique_queues = set()
  # q_to_tc = defaultdict(list)
  # default_queue = str(tasks.default_queue())

  # for status in ['Processed', 'Duplicate']:
  #   for testcase in data_types.Testcase.query(
  #       ndb_utils.is_true(data_types.Testcase.open),
  #       ndb_utils.is_false(data_types.Testcase.one_time_crasher_flag),
  #       data_types.Testcase.status == status):
  #     testcase_id = testcase.key.id()
  #     queue = str(tasks.queue_for_testcase(testcase))

  #     unique_queues.add(str(queue))
  #     if queue != default_queue:
  #       q_to_tc[queue].append(testcase_id)

  # print(f'Unique queues: {unique_queues}')

  # with open('queue_to_testcase.txt', 'w') as f:
  #   for q in q_to_tc:
  #     f.write(f'Queue {q}\n')
  #     for tc in q_to_tc[q]:
  #       f.write(f'\tTC: {tc}\n')


  # Testcases with fixed not null and progression_pending
  # testcases_pending = {}
  # print(f'Testcases with pending progression and fixed:')
  # for testcase_id in data_handler.get_open_testcase_id_iterator():
  #   try:
  #     testcase = data_handler.get_testcase_by_id(testcase_id)
  #   except errors.InvalidTestcaseError:
  #     continue

  #   if testcase.get_metadata('progression_pending'):
  #     testcases_pending[testcase_id] = testcase.fixed
  #     print(f'TC: {testcase_id}, Fixed: {testcase.fixed}')

  # with open('pending_progression_tcs.txt', 'w') as f:
  #   for t in testcases_pending:
  #     f.write(f'TC {t}, Fixed: {testcases_pending[t]}\n')


  # testcases_pending = {}
  # status = 'Processed'
  # print(f'Testcases with pending progression and fixed:')
  # for testcase in data_types.Testcase.query(
  #     ndb_utils.is_true(data_types.Testcase.open),
  #     # ndb_utils.is_false(data_types.Testcase.one_time_crasher_flag),
  #     data_types.Testcase.status == status):
  #   if testcase.fixed and testcase.get_metadata('progression_pending'):
  #     testcase_id = testcase.key.id()
  #     testcases_pending[testcase_id] = testcase.fixed
  #     print(f'TC: {testcase_id}, Fixed: {testcase.fixed}')


  # with open('pending_progression_tcs.txt', 'w') as f:
  #   for t in testcases_pending:
  #     f.write(f'TC {t}, Fixed: {testcases_pending[t]}\n')

  # testcase = data_handler.get_testcase_by_id(5150734693629952)
  # issue_tracker = issue_tracker_utils.get_issue_tracker_for_testcase(testcase)
  # if not issue_tracker:
  #   return
  # same_crash_params_query = data_types.Testcase.query(
  #     data_types.Testcase.crash_type == testcase.crash_type,
  #     data_types.Testcase.crash_state == testcase.crash_state,
  #     data_types.Testcase.security_flag == testcase.security_flag,
  #     data_types.Testcase.project_name == testcase.project_name,
  #     data_types.Testcase.status == 'Processed')
  # for similar_testcase in ndb_utils.get_all_from_query(same_crash_params_query):
  #   # Exclude ourself from comparison.
  #   if similar_testcase.key.id() == testcase.key.id():
  #     continue

  #   # Exclude similar testcases without bug information.
  #   if not similar_testcase.bug_information:
  #     continue


  #   # Get the issue object given its ID.
  #   issue = issue_tracker.get_issue(similar_testcase.bug_information)
  #   if not issue:
  #     continue

  #   print(similar_testcase.key.id())

  #   # If the reproducible issue is not verified yet, bug is still valid and
  #   # might be caused by non-availability of latest builds. In that case,
  #   # don't file a new bug yet.
  #   if similar_testcase.open and not similar_testcase.one_time_crasher_flag:
  #     print('Open + Not ONE TIME: Return True')

  #   # If the issue is still open, no need to file a duplicate bug.
  #   if issue.is_open:
  #     print('Issue OPEN: Return True')
 

  # print('Finished')

  # task = 'progression'
  # testcase = data_handler.get_testcase_by_id(5858659032498176)
  # testcase_id = testcase.key.id()
  # try:
  #   tasks.add_task(
  #       task,
  #       testcase_id,
  #       testcase.job_type,
  #       queue=tasks.queue_for_testcase(testcase))
  # except Exception:
  #   logs.error(f'Failed to create task for {testcase_id}')

  # commands.process_command_impl('minimize', '5596768725041152', 'libfuzzer_chrome_asan_debug',
  #                               True, True)

  # commands.process_command_impl('blame', 4611343386607616, 'v8_libfuzzer_asan_linux_arm_sim',
  #                               False, False)
  # testcase = 5744698551369728
  # job = 'v8_libfuzzer_asan_linux_arm64_sim'
  # tasks.add_task('blame', testcase, job)
  # jsonPayload.extras.task_name="blame" OR jsonPayload.extras.task_name="impact"
  # logs.info('Testing PR')
  # environment.set_value('CF_TASK_ID', 'f61826c3-ca9a-4b97-9c1e-9e6f4e4f8868')
  # environment.set_value('CF_TASK_NAME', 'analyze')

  # testcase = data_types.Testcase()
  # testcase.bug_information = '426517098'
  # testcase.job_type = 'afl_asan_test'
  # testcase.fuzzer_name = 'test_string_fuzzer'
  # testcase.crash_revision = 1
  # testcase.status = 'Unreproducible'
  # testcase.minimized_keys = 'NA'
  # testcase.regression = 'NA'
  # testcase.set_impacts_as_na()
  # testcase.fixed = 'NA'
  # testcase.triaged = True
  # testcase.put()
  # print(f'## Testcase ID: {testcase.key.id()}')

  # try:
  #   testcase_id = 5594504941731840
  #   testcase = data_handler.get_testcase_by_id(testcase_id)
  #   same_crash_params_query = data_types.Testcase.query(
  #     data_types.Testcase.crash_type == testcase.crash_type,
  #     data_types.Testcase.crash_state == testcase.crash_state,
  #     data_types.Testcase.security_flag == testcase.security_flag,
  #     data_types.Testcase.project_name == testcase.project_name,
  #     data_types.Testcase.status == 'Processed')

  #   similar_testcases_from_query = ndb_utils.get_all_from_query(
  #       same_crash_params_query,
  #       batch_size=data_types.TESTCASE_ENTITY_QUERY_LIMIT // 2)
  #   for sim_tc in similar_testcases_from_query:
  #     if not sim_tc.bug_information:
  #       continue
  #     tc_id = sim_tc.key.id()
  #     print(tc_id, sim_tc.bug_information)


  # except Exception as e:
  #   print(f'Failed - {e}')
  
    # event = events.TestcaseCreationEvent(
    #   testcase=testcase, creation_origin=events.TestcaseOrigin.MANUAL_UPLOAD,
    #   uploader='vtcosta@google.com', source_frame=sys._getframe(0)
    # )
    # print(event)

    # event = events.Event(event_type='test', source_frame=sys._getframe(0))
    # print(event)
    # utask_return_code = uworker_msg_pb2.ErrorType.Name(uworker_msg_pb2.ErrorType.REGRESSION_BAD_BUILD_ERROR)
    # print()
    # print(type(utask_return_code))
    # print(utask_return_code)

    # utask_return_code = uworker_msg_pb2.ErrorType.Name(uworker_msg_pb2.ErrorType.REGRESSION_BAD_BUILD_ERROR)
    # print()
    # print(type(utask_return_code))
    # print(utask_return_code)
    # print()

    # utask_return_code = uworker_msg_pb2.ErrorType.Name(None)
    # print()
    # print(type(utask_return_code))
    # print(utask_return_code)
    # print()

    # testcase = data_types.Testcase(id=123456, job_type='blabers')
    # print(testcase.key.id())
    # print(testcase.job_type)
    # print(testcase.fuzzer_name)
    # print(testcase.crash_revision)

  #   event_data = {'task_job_type': 'blabla', 'testcase_id': 124}
  #   event_task_exec = events.TaskExecutionEvent(**event_data, task_stage=events.TaskStage.PREPROCESS, task_status=events.TaskStatus.STARTED)
  #   print(event_task_exec)
  # except Exception as e:
  #   print(f'Failed - {e}')

  # testcase.key.delete()

