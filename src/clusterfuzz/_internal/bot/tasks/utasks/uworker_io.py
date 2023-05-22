# Copyright 2023 Google LLC
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
"""Module for dealing with input and output (I/O) to a uworker."""

import base64
import datetime
import json
import tempfile
import uuid

from google.cloud import ndb

from clusterfuzz._internal.bot.tasks.utasks import uworker_errors
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.google_cloud_utils import storage
from clusterfuzz._internal.metrics import logs


def generate_new_input_file_name():
  """Generates a new I/O file name."""
  return str(uuid.uuid4()).lower()


def get_uworker_input_gcs_path():
  """Returns a GCS path for uworker I/O."""
  # Inspired by blobs.write_blob.
  io_bucket = storage.uworker_io_bucket()
  io_file_name = generate_new_input_file_name()
  if storage.get(storage.get_cloud_storage_file_path(io_bucket, io_file_name)):
    raise RuntimeError(f'UUID collision found: {io_file_name}.')
  return f'/{io_bucket}/{io_file_name}'


def get_uworker_output_urls(input_gcs_path):
  """Returns a signed download URL for the uworker to upload the output and a
  GCS url for the tworker to download the output. Make sure we can infer the
  actual input since the output is not trusted."""
  gcs_path = input_gcs_path + '.output'
  # Note that the signed upload URL can't be directly downloaded from.
  return storage.get_signed_upload_url(gcs_path), gcs_path


def get_uworker_input_urls():
  """Returns a signed download URL for the uworker to download the input and a
  GCS url for the tworker to upload it (this happens first)."""
  gcs_path = get_uworker_input_gcs_path()
  return storage.get_signed_download_url(gcs_path), gcs_path


def upload_uworker_input(uworker_input, gcs_path):
  """Uploads input for the untrusted portion of a task."""

  with tempfile.NamedTemporaryFile() as uworker_input_file:
    with open(uworker_input_file.name, 'w') as fp:
      fp.write(uworker_input)
    if not storage.copy_file_to(uworker_input_file.name, gcs_path):
      raise RuntimeError('Failed to upload uworker_input.')


def make_ndb_entity_input_obj_serializable(obj):
  """Returns a dictionary that can be JSON serialized representing an NDB
  entity. Does not include datetime fields."""
  obj_dict = obj.to_dict()
  # TOOD(metzman): Handle datetimes.
  for key in list(obj_dict.keys()):
    value = obj_dict[key]
    if isinstance(value, datetime.datetime):
      del obj_dict[key]
  return {
      'key': base64.b64encode(obj.key.serialized()).decode(),
      'properties': obj_dict,
  }


def get_entity_with_properties(ndb_key: ndb.Key, properties) -> ndb.Model:
  """Returns the entity pointed to by ndb_key and sets the properties on the
  entity as the |properties| dictionary specifies."""
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
    entity = get_entity_with_properties(ndb_key, entity_dict['properties'])
    uworker_input[name] = UworkerEntityWrapper(entity)
  return uworker_input


def serialize_uworker_input(uworker_input):
  """Serializes and returns |uworker_input| as JSON. Can handle ndb entities."""
  serializable = {}
  ndb_entities = {}
  for key, value in uworker_input.items():
    if not isinstance(value, ndb.Model):
      serializable[key] = value
      continue
    ndb_entities[key] = make_ndb_entity_input_obj_serializable(value)

  return json.dumps({'serializable': serializable, 'entities': ndb_entities})


def serialize_and_upload_uworker_input(uworker_input, job_type) -> str:
  """Serializes input for the untrusted portion of a task."""
  # Add remaining fields to the input.
  assert 'job_type' not in uworker_input
  uworker_input['job_type'] = job_type

  signed_input_download_url, input_gcs_url = get_uworker_input_urls()
  # Get URLs for the uworker'ps output. We need a signed upload URL so it can
  # write its output. Also get a download URL in case the caller wants to read
  # the output.
  signed_output_upload_url, output_gcs_url = get_uworker_output_urls(
      input_gcs_url)

  assert 'uworker_output_upload_url' not in uworker_input
  uworker_input['uworker_output_upload_url'] = signed_output_upload_url

  uworker_input = serialize_uworker_input(uworker_input)
  upload_uworker_input(uworker_input, input_gcs_url)

  return signed_input_download_url, output_gcs_url


def download_and_deserialize_uworker_input(uworker_input_download_url):
  """Downloads and deserializes the input to the uworker from the signed
  download URL."""
  data = storage.download_signed_url(uworker_input_download_url)
  return deserialize_uworker_input(data)


def serialize_uworker_output(uworker_output_obj):
  """Serializes uworker's output for deserializing by deserialize_uworker_output
  and consumption by postprocess_task."""
  uworker_output = uworker_output_obj.to_dict()
  entities = {}
  serializable = {}
  error = uworker_output.pop('error', None)
  if error is not None:
    error = error.value

  for name, value in uworker_output.items():
    if not isinstance(value, UworkerEntityWrapper):
      serializable[name] = value
      continue
    entities[name] = {
        'key': base64.b64encode(value.key.serialized()).decode(),
        'changed': value._wrapped_changed_attributes,  # pylint: disable=protected-access
    }
  output = {'serializable': serializable, 'entities': entities, 'error': error}
  return json.dumps(output)


def serialize_and_upload_uworker_output(uworker_output, upload_url):
  """Serializes |uworker_output| and uploads it to |upload_url."""
  uworker_output = serialize_uworker_output(uworker_output)
  storage.upload_signed_url(uworker_output, upload_url)


def _download_uworker_io_from_gcs(gcs_url):
  with tempfile.NamedTemporaryFile() as local_path:
    if not storage.copy_file_from(gcs_url, local_path.name):
      logs.log_error('Could not download uworker I/O file from %s' % gcs_url)
      return None
    with open(local_path.name) as file_handle:
      return file_handle.read()


def _download_uworker_input_from_gcs(gcs_url):
  return _download_uworker_io_from_gcs(gcs_url)


def download_and_deserialize_uworker_output(output_url: str):
  """Downloads and deserializes uworker output."""
  serialized_uworker_output = _download_uworker_io_from_gcs(output_url)
  uworker_output = deserialize_uworker_output(serialized_uworker_output)

  # Now download the input, which is stored securely so that the uworker cannot
  # tamper with it.
  # Get the portion that does not contain ".output".
  input_url = output_url.split('.output')[0]
  serialized_uworker_input = _download_uworker_input_from_gcs(input_url)
  uworker_input = deserialize_uworker_input(serialized_uworker_input)
  uworker_output.uworker_env = uworker_input['uworker_env']
  uworker_output.uworker_input = uworker_input
  return uworker_output


def deserialize_uworker_output(uworker_output):
  """Deserializes uworker's execute output for postprocessing. Returns a dict
  that can be passed as kwargs to postprocess. Changes made db entities that
  were modified during the untrusted portion of the task will be done to those
  entities here."""
  uworker_output = json.loads(uworker_output)
  deserialized_output = uworker_output['serializable']
  error = uworker_output.pop('error')
  if error is not None:
    deserialized_output['error'] = uworker_errors.Type(error)
  else:
    deserialized_output['error'] = None
  for name, entity_dict in uworker_output['entities'].items():
    key = entity_dict['key']
    ndb_key = ndb.Key(serialized=base64.b64decode(key))
    entity = ndb_key.get()
    deserialized_output[name] = entity
    for attr, new_value in entity_dict['changed'].items():
      # TODO(metzman): Don't allow setting all fields on every entity since this
      # might have some security problems.
      setattr(entity, attr, new_value)
  return uworker_output_from_dict(deserialized_output)


class UworkerEntityWrapper:
  """Wrapper for db entities on the uworker. This wrapper functions the same as
  the entity but also tracks changes made to the entity. This is useful for
  uworkers, since they can't directly save any changes to db entities. This
  makes for easier results processing by trusted workers (who now don't need to
  clobber the entire entity when writing to the db, but can instead update just
  the modified fields)."""

  def __init__(self, entity):
    # Everything set here, must be in the list in __setattr__
    self._entity = entity
    # TODO(https://github.com/google/clusterfuzz/issues/3008): Deal with key
    # which won't be possible to set on a model when there's no datastore
    # connection.
    self._wrapped_changed_attributes = {}

  def __getattr__(self, attribute):
    if attribute in ['_entity', '_wrapped_changed_attributes']:
      # Allow setting and changing _entity and _wrapped_changed_attributes.
      # Stack overflow in __init__ otherwise.
      return super().__getattr__(attribute)  # pylint: disable=no-member
    return getattr(self._entity, attribute)

  def __setattr__(self, attribute, value):
    if attribute in ['_entity', '_wrapped_changed_attributes']:
      # Allow setting and changing _entity. Stack overflow in __init__
      # otherwise.
      super().__setattr__(attribute, value)
      return
    # Record the attribute change.
    self._wrapped_changed_attributes[attribute] = value
    # Make the attribute change.
    setattr(self._entity, attribute, value)


class UworkerOutput:
  """Convenience class for results from uworker_main. This is useful for
  ensuring we are returning values for fields expected by utask_postprocess."""

  def __init__(self, testcase=None, error=None, **kwargs):
    self.testcase = testcase
    self.error = error
    for key, value in kwargs.items():
      setattr(self, key, value)

  def to_dict(self):
    # Make a copy so calls to pop don't modify the object.
    return self.__dict__.copy()


def uworker_output_from_dict(output_dict):
  return UworkerOutput(**output_dict)
