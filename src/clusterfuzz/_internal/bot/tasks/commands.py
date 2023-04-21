# Copyright 2019 Google LLC
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
"""Run command based on the current task."""

import base64
import datetime
import functools
import json
import os
import sys
import tempfile
import time

from google.cloud import ndb
import requests

from clusterfuzz._internal.base import errors
from clusterfuzz._internal.base import tasks
from clusterfuzz._internal.base import utils
from clusterfuzz._internal.bot.tasks import blame_task
from clusterfuzz._internal.bot.tasks import corpus_pruning_task
from clusterfuzz._internal.bot.tasks import fuzz_task
from clusterfuzz._internal.bot.tasks import impact_task
from clusterfuzz._internal.bot.tasks import minimize_task
from clusterfuzz._internal.bot.tasks import progression_task
from clusterfuzz._internal.bot.tasks import regression_task
from clusterfuzz._internal.bot.tasks import symbolize_task
from clusterfuzz._internal.bot.tasks import unpack_task
from clusterfuzz._internal.bot.tasks import upload_reports_task
from clusterfuzz._internal.bot.tasks import variant_task
from clusterfuzz._internal.bot.tasks.untrusted import analyze_task
from clusterfuzz._internal.bot.webserver import http_server
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.google_cloud_utils import blobs
from clusterfuzz._internal.google_cloud_utils import storage
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.system import process_handler
from clusterfuzz._internal.system import shell


class BaseTask:

  def __init__(self, module):
    self.module = module

  def execute(self, task_argument, job_type, uworker_env):
    # !!! undo api change
    raise NotImplementedError('Child class must implement.')


class TrustedTask(BaseTask):

  def execute(self, task_argument, job_type, _):
    self.module.execute_task(task_argument, job_type, None)


# def convert_untrusted_result(untrusted_result):
#   for entity_name, entities in untrusted_result.entity_changes.items():
#     # entity_cls = getattr(data_types, entity_name)
#     # entities = json.loads(entities)
#     for key, changed_values in entities.items():
#       key = ndb.Key(serialized=bytes(key, 'utf-8'))
#       entity = key.get()
#       for attr, val in changed_values.items():
#         # !!! Enforce some type safety
#         getattr(entity, attr)
#         setattr(entity, attr, val)
#       untrusted_result.entities[entity_name].append(entity)


def get_uworker_io_gcs_path():
  # inspired by write_blob
  io_bucket = storage.uworker_io_bucket()
  io_file_name = blobs.generate_new_blob_name()
  if storage.get(storage.get_cloud_storage_file_path(io_bucket, io_file_name)):
    raise RuntimeError(f'UUID collision found: {io_file_name}.')  # !!!
  return f'/{io_bucket}/{io_file_name}'


def get_uworker_output_upload_urls():
  gcs_path = get_uworker_io_gcs_path()
  return storage.get_signed_upload_url(gcs_path), gcs_path


def get_uworker_input_urls():
  # !!! Are both needed? Can we make a dl url before uploading to it?
  gcs_path = get_uworker_io_gcs_path()
  return gcs_path, storage.get_signed_download_url(gcs_path)


def upload_uworker_input(uworker_input):
  """Uploads input for the untrusted portion of a task."""
  gcs_path, signed_download_url = get_uworker_input_urls()

  with tempfile.TemporaryDirectory() as tmp_dir:
    uworker_input_filename = os.path.join(tmp_dir, 'uworker_input')
    with open(uworker_input_filename, 'w') as fp:
      fp.write(uworker_input)
      if not storage.copy_file_to(uworker_input_filename, gcs_path):
        raise RuntimeError('Failed to upload uworker_input.')
  return signed_download_url


def make_ndb_entity_input_obj_serializable(obj):
  # !!! consider urlsafe.
  obj_dict = obj.to_dict()
  # !!! We can't handle datetimes.
  for key in list(obj_dict.keys()):
    value = obj_dict[key]
    if isinstance(value, datetime.datetime):
      del obj_dict[key]
  return {
      'key': base64.b64encode(obj.key.serialized()).decode(),
      # 'model': type(ndb_entity).__name__,
      'properties': obj_dict,
  }


def get_entity_with_changed_properties(ndb_key: ndb.Key,
                                       properties) -> ndb.Model:
  """Returns the entity pointed to by ndb_key and changes properties.."""
  model_name = ndb_key.kind()
  model_cls = getattr(data_types, model_name)
  entity = model_cls()
  entity.key = ndb_key
  for ndb_property, value in properties.items():
    fail_msg = f'{entity} doesn\'t have {ndb_property}'
    assert hasattr(entity, ndb_property), fail_msg
    setattr(entity, ndb_property, value)
  return entity


def deserialize_uworker_input(serialized_uworker_input):
  """Deserializes input for the untrusted part of a task."""
  serialized_uworker_input = json.loads(serialized_uworker_input)
  uworker_input = serialized_uworker_input['serializable']
  for name, entity_dict in serialized_uworker_input['entities'].items():
    entity_key = entity_dict['key']
    serialized_key = base64.b64decode(bytes(entity_key, 'utf-8'))
    ndb_key = ndb.Key(serialized=serialized_key)
    # !!! make entity in uworker
    entity = get_entity_with_changed_properties(ndb_key,
                                                entity_dict['properties'])
    uworker_input[name] = analyze_task.UworkerEntityWrapper(entity)
  return uworker_input


def serialize_uworker_input(uworker_input):
  serializable = {}
  ndb_entities = {}
  for key, value in uworker_input.items():
    if not isinstance(value, ndb.Model):
      serializable[key] = value
      continue
    ndb_entities[key] = make_ndb_entity_input_obj_serializable(value)

  return json.dumps({'serializable': serializable, 'entities': ndb_entities})
  # !!! pickle is scary, replace
  # return base64.b64encode(pickle.dumps(uworker_input))


def serialize_and_upload_uworker_input(uworker_input, job_type,
                                       uworker_output_upload_url) -> str:
  """Serializes input for the untrusted portion of a task."""
  # Add remaining fields.

  assert 'job_type' not in uworker_input
  uworker_input['job_type'] = job_type
  assert 'uworker_output_upload_url' not in uworker_input
  uworker_input['uworker_output_upload_url'] = uworker_output_upload_url

  uworker_input = serialize_uworker_input(uworker_input)
  uworker_input_download_url = upload_uworker_input(uworker_input)
  return uworker_input_download_url


def download_and_deserialize_uworker_input(uworker_input_download_url) -> str:
  req = requests.get(uworker_input_download_url)
  return deserialize_uworker_input(req.content)


def serialize_uworker_output(uworker_output):
  """Serializes uworker's output for deserializing by deserialize_uworker_output
  and consumption by postprocess_task."""
  entities = {}
  serializable = {}

  for name, value in uworker_output.items():
    if not isinstance(value, analyze_task.UworkerEntityWrapper):
      serializable[name] = value
      continue
    entities[name] = {
        # Not same as dict key !!!
        'key': base64.b64encode(value.key.serialized()).decode(),
        'changed': value._wrapped_changed_attributes,  # pylint: disable=protected-access
    }
  # from remote_pdb import RemotePdb
  # RemotePdb('127.0.0.1', 4444).set_trace()
  return json.dumps({'serializable': serializable, 'entities': entities})


def serialize_and_upload_uworker_output(uworker_output, upload_url) -> str:
  uworker_output = serialize_uworker_output(uworker_output)
  storage.upload_signed_url(upload_url, uworker_output)


def deserialize_uworker_output(uworker_output):
  """Deserializes uworker's execute output for postprocessing. Returns a dict
  that can be passed as kwargs to postprocess. changes made db entities that
  were modified during the untrusted portion of the task will be done to those
  entities here."""
  uworker_output = json.loads(uworker_output)
  deserialized_output = uworker_output['serializable']
  for name, entity_dict in uworker_output['entities'].items():
    key = entity_dict['key']
    ndb_key = ndb.Key(serialized=base64.b64decode(key))
    entity = ndb_key.get()
    deserialized_output[name] = entity
    for attr, new_value in entity_dict['changed'].items():
      # !!! insecure
      setattr(entity, attr, new_value)
  return deserialized_output


def download_url(url):
  req = requests.get(url)
  # !!! check errors.
  return req.content


def download_and_deserialize_uworker_output(output_url) -> str:
  with tempfile.TemporaryDirectory() as temp_dir:
    uworker_output_local_path = os.path.join(temp_dir, 'temp')
    storage.copy_file_from(output_url, uworker_output_local_path)
    with open(uworker_output_local_path) as uworker_output_file_handle:
      uworker_output = uworker_output_file_handle.read()
  return deserialize_uworker_output(uworker_output)


class UntrustedTask(BaseTask):
  """Represents an untrusted task. Executes it entirely locally."""

  def execute(self, task_argument, job_type, uworker_env):
    # !!! Done on preworker
    uworker_input = self.module.preprocess_task(task_argument, job_type,
                                                uworker_env)
    if not uworker_input:
      return False

    uworker_output_upload_url, uworker_output_download_url = (
        get_uworker_output_upload_urls())
    uworker_input_download_url = serialize_and_upload_uworker_input(
        uworker_input, job_type, uworker_output_upload_url)

    # !!! Done on uworker
    uworker_input = download_and_deserialize_uworker_input(
        uworker_input_download_url)
    uworker_output = self.module.uworker_execute(**uworker_input)
    serialize_and_upload_uworker_output(uworker_output,
                                        uworker_output_upload_url)

    # !!! Done on postworker
    uworker_output = download_and_deserialize_uworker_output(
        uworker_output_download_url)
    return self.module.postprocess_task(**uworker_output)


COMMAND_MAP = {
    'analyze': UntrustedTask(analyze_task),
    'blame': TrustedTask(blame_task),
    'corpus_pruning': TrustedTask(corpus_pruning_task),
    'fuzz': TrustedTask(fuzz_task),
    'impact': TrustedTask(impact_task),
    'minimize': TrustedTask(minimize_task),
    'progression': TrustedTask(progression_task),
    'regression': TrustedTask(regression_task),
    'symbolize': TrustedTask(symbolize_task),
    'unpack': TrustedTask(unpack_task),
    'upload_reports': TrustedTask(upload_reports_task),
    'variant': TrustedTask(variant_task),
}

TASK_RETRY_WAIT_LIMIT = 5 * 60  # 5 minutes.


class Error(Exception):
  """Base commands exceptions."""


class AlreadyRunningError(Error):
  """Exception raised for a task that is already running on another bot."""


def cleanup_task_state():
  """Cleans state before and after a task is executed."""
  # Cleanup stale processes.
  process_handler.cleanup_stale_processes()

  # Clear build urls, temp and testcase directories.
  shell.clear_build_urls_directory()
  shell.clear_crash_stacktraces_directory()
  shell.clear_testcase_directories()
  shell.clear_temp_directory()
  shell.clear_system_temp_directory()
  shell.clear_device_temp_directories()

  # Reset memory tool environment variables.
  environment.reset_current_memory_tool_options()

  # Call python's garbage collector.
  utils.python_gc()


def is_supported_cpu_arch_for_job():
  """Return true if the current cpu architecture can run this job."""
  cpu_arch = environment.get_cpu_arch()
  if not cpu_arch:
    # No cpu architecture check is defined for this platform, bail out.
    return True

  supported_cpu_arch = environment.get_value('CPU_ARCH')
  if not supported_cpu_arch:
    # No specific cpu architecture requirement specified in job, bail out.
    return True

  # Convert to list just in case anyone specifies value as a single string.
  supported_cpu_arch_list = list(supported_cpu_arch)

  return cpu_arch in supported_cpu_arch_list


def update_environment_for_job(environment_string):
  """Process the environment variable string included with a job."""
  # Now parse the job's environment definition.
  env = environment.parse_environment_definition(environment_string)
  uworker_env = env.copy()
  for key, value in env.items():
    environment.set_value(key, value)

  # If we share the build with another job type, force us to be a custom binary
  # job type.
  if environment.get_value('SHARE_BUILD_WITH_JOB_TYPE'):
    environment.set_value('CUSTOM_BINARY', True)
    uworker_env['CUSTOM_BINARY'] = 'True'

  # Allow the default FUZZ_TEST_TIMEOUT and MAX_TESTCASES to be overridden on
  # machines that are preempted more often.
  fuzz_test_timeout_override = environment.get_value(
      'FUZZ_TEST_TIMEOUT_OVERRIDE')
  if fuzz_test_timeout_override:
    environment.set_value('FUZZ_TEST_TIMEOUT', fuzz_test_timeout_override)
    uworker_env['FUZZ_TEST_TIMEOUT'] = fuzz_test_timeout_override

  max_testcases_override = environment.get_value('MAX_TESTCASES_OVERRIDE')
  if max_testcases_override:
    environment.set_value('MAX_TESTCASES', max_testcases_override)
    uworker_env['MAX_TESTCASES'] = max_testcases_override

  if environment.is_trusted_host():
    env['JOB_NAME'] = environment.get_value('JOB_NAME')
    from clusterfuzz._internal.bot.untrusted_runner import \
        environment as worker_environment
    worker_environment.update_environment(env)
  return uworker_env


def set_task_payload(func):
  """Set TASK_PAYLOAD and unset TASK_PAYLOAD."""

  @functools.wraps(func)
  def wrapper(task):
    """Wrapper."""
    environment.set_value('TASK_PAYLOAD', task.payload())
    try:
      return func(task)
    except:  # Truly catch *all* exceptions.
      e = sys.exc_info()[1]
      e.extras = {'task_payload': environment.get_value('TASK_PAYLOAD')}
      raise
    finally:
      environment.remove_key('TASK_PAYLOAD')

  return wrapper


def should_update_task_status(task_name):
  """Whether the task status should be automatically handled."""
  return task_name not in [
      # Multiple fuzz tasks are expected to run in parallel.
      'fuzz',

      # The task payload can't be used as-is for de-duplication purposes as it
      # includes revision. corpus_pruning_task calls update_task_status itself
      # to handle this.
      # TODO(ochang): This will be cleaned up as part of migration to Pub/Sub.
      'corpus_pruning',
  ]


def start_web_server_if_needed():
  """Start web server for blackbox fuzzer jobs (non-engine fuzzer jobs)."""
  if environment.is_engine_fuzzer_job():
    return

  try:
    http_server.start()
  except Exception:
    logs.log_error('Failed to start web server, skipping.')


def run_command(task_name, task_argument, job_name, uworker_env):
  """Run the command."""
  if task_name not in COMMAND_MAP:
    logs.log_error("Unknown command '%s'" % task_name)
    return

  task = COMMAND_MAP[task_name]

  # If applicable, ensure this is the only instance of the task running.
  task_state_name = ' '.join([task_name, task_argument, job_name])
  # !!! development needed to rerun analyze if it fails
  # if should_update_task_status(task_name):
  #   if not data_handler.update_task_status(task_state_name,
  #                                          data_types.TaskState.STARTED):
  #     logs.log('Another instance of "{}" already '
  #              'running, exiting.'.format(task_state_name))
  #     raise AlreadyRunningError

  try:
    task.execute(task_argument, job_name, uworker_env)
  except errors.InvalidTestcaseError:
    # It is difficult to try to handle the case where a test case is deleted
    # during processing. Rather than trying to catch by checking every point
    # where a test case is reloaded from the datastore, just abort the task.
    logs.log_warn('Test case %s no longer exists.' % task_argument)
  except BaseException:
    # On any other exceptions, update state to reflect error and re-raise.
    if should_update_task_status(task_name):
      data_handler.update_task_status(task_state_name,
                                      data_types.TaskState.ERROR)

    raise

  # Task completed successfully.
  if should_update_task_status(task_name):
    data_handler.update_task_status(task_state_name,
                                    data_types.TaskState.FINISHED)


# pylint: disable=too-many-nested-blocks
# TODO(mbarbella): Rewrite this function to avoid nesting issues.
@set_task_payload
def process_command(task):
  """Figures out what to do with the given task and executes the command."""
  logs.log("Executing command '%s'" % task.payload())
  if not task.payload().strip():
    logs.log_error('Empty task received.')
    return

  # Parse task payload.
  task_name = task.command
  task_argument = task.argument
  job_name = task.job

  environment.set_value('TASK_NAME', task_name)
  environment.set_value('TASK_ARGUMENT', task_argument)
  environment.set_value('JOB_NAME', job_name)
  if job_name != 'none':
    job = data_types.Job.query(data_types.Job.name == job_name).get()
    # Job might be removed. In that case, we don't want an exception
    # raised and causing this task to be retried by another bot.
    if not job:
      logs.log_error("Job '%s' not found." % job_name)
      return

    if not job.platform:
      error_string = "No platform set for job '%s'" % job_name
      logs.log_error(error_string)
      raise errors.BadStateError(error_string)

    # A misconfiguration led to this point. Clean up the job if necessary.
    job_queue_suffix = tasks.queue_suffix_for_platform(job.platform)
    bot_queue_suffix = tasks.default_queue_suffix()

    if job_queue_suffix != bot_queue_suffix:
      # This happens rarely, store this as a hard exception.
      logs.log_error(
          'Wrong platform for job %s: job queue [%s], bot queue [%s].' %
          (job_name, job_queue_suffix, bot_queue_suffix))

      # Try to recreate the job in the correct task queue.
      new_queue = (
          tasks.high_end_queue() if task.high_end else tasks.regular_queue())
      new_queue += job_queue_suffix

      # Command override is continuously run by a bot. If we keep failing
      # and recreating the task, it will just DoS the entire task queue.
      # So, we don't create any new tasks in that case since it needs
      # manual intervention to fix the override anyway.
      if not task.is_command_override:
        try:
          tasks.add_task(task_name, task_argument, job_name, new_queue)
        except Exception:
          # This can happen on trying to publish on a non-existent topic, e.g.
          # a topic for a high-end bot on another platform. In this case, just
          # give up.
          logs.log_error('Failed to fix platform and re-add task.')

      # Add a wait interval to avoid overflowing task creation.
      failure_wait_interval = environment.get_value('FAIL_WAIT')
      time.sleep(failure_wait_interval)
      return

    if task_name != 'fuzz':
      # Make sure that our platform id matches that of the testcase (for
      # non-fuzz tasks).
      testcase = data_handler.get_entity_by_type_and_id(data_types.Testcase,
                                                        task_argument)
      if testcase:
        current_platform_id = environment.get_platform_id()
        testcase_platform_id = testcase.platform_id

        # This indicates we are trying to run this job on the wrong platform.
        # This can happen when you have different type of devices (e.g
        # android) on the same platform group. In this case, we just recreate
        # the task.
        if (task_name != 'variant' and testcase_platform_id and
            not utils.fields_match(testcase_platform_id, current_platform_id)):
          logs.log(
              'Testcase %d platform (%s) does not match with ours (%s), exiting'
              % (testcase.key.id(), testcase_platform_id, current_platform_id))
          tasks.add_task(
              task_name,
              task_argument,
              job_name,
              wait_time=utils.random_number(1, TASK_RETRY_WAIT_LIMIT))
          return

    # Some fuzzers contain additional environment variables that should be
    # set for them. Append these for tests generated by these fuzzers and for
    # the fuzz command itself.
    fuzzer_name = None
    if task_name == 'fuzz':
      fuzzer_name = task_argument
    elif testcase:
      fuzzer_name = testcase.fuzzer_name

    # Get job's environment string.
    environment_string = job.get_environment_string()

    if task_name == 'minimize':
      # Let jobs specify a different job and fuzzer to minimize with.
      job_environment = job.get_environment()
      minimize_job_override = job_environment.get('MINIMIZE_JOB_OVERRIDE')
      if minimize_job_override:
        minimize_job = data_types.Job.query(
            data_types.Job.name == minimize_job_override).get()
        if minimize_job:
          environment.set_value('JOB_NAME', minimize_job_override)
          environment_string = minimize_job.get_environment_string()
          environment_string += '\nORIGINAL_JOB_NAME = %s\n' % job_name
          job_name = minimize_job_override
        else:
          logs.log_error(
              'Job for minimization not found: %s.' % minimize_job_override)
          # Fallback to using own job for minimization.

      minimize_fuzzer_override = job_environment.get('MINIMIZE_FUZZER_OVERRIDE')
      fuzzer_name = minimize_fuzzer_override or fuzzer_name

    if fuzzer_name and not environment.is_engine_fuzzer_job(job_name):
      fuzzer = data_types.Fuzzer.query(
          data_types.Fuzzer.name == fuzzer_name).get()
      additional_default_variables = ''
      additional_variables_for_job = ''
      if (fuzzer and hasattr(fuzzer, 'additional_environment_string') and
          fuzzer.additional_environment_string):
        for line in fuzzer.additional_environment_string.splitlines():
          # Job specific values may be defined in fuzzer additional
          # environment variable name strings in the form
          # job_name:VAR_NAME = VALUE.
          if '=' in line and ':' in line.split('=', 1)[0]:
            fuzzer_job_name, environment_definition = line.split(':', 1)
            if fuzzer_job_name == job_name:
              additional_variables_for_job += '\n%s' % environment_definition
            continue

          additional_default_variables += '\n%s' % line

      environment_string += additional_default_variables
      environment_string += additional_variables_for_job

    # Update environment for the job.
    uworker_env = update_environment_for_job(environment_string)

  # Match the cpu architecture with the ones required in the job definition.
  # If they don't match, then bail out and recreate task.
  if not is_supported_cpu_arch_for_job():
    logs.log(
        'Unsupported cpu architecture specified in job definition, exiting.')
    tasks.add_task(
        task_name,
        task_argument,
        job_name,
        wait_time=utils.random_number(1, TASK_RETRY_WAIT_LIMIT))
    return

  # Initial cleanup.
  cleanup_task_state()

  start_web_server_if_needed()

  try:
    run_command(task_name, task_argument, job_name, uworker_env)
  finally:
    # Final clean up.
    cleanup_task_state()
