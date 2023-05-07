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
import os
import tempfile
import uuid

from google.cloud import ndb

from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.google_cloud_utils import storage


def generate_new_io_file_name():
  """Generates a new I/O file name."""
  return str(uuid.uuid4()).lower()


def get_uworker_io_gcs_path():
  """Returns a GCS path for uworker I/O."""
  # Inspired by blobs.write_blob.
  io_bucket = storage.uworker_io_bucket()
  io_file_name = generate_new_io_file_name()
  if storage.get(storage.get_cloud_storage_file_path(io_bucket, io_file_name)):
    raise RuntimeError(f'UUID collision found: {io_file_name}.')  # !!!
  return f'/{io_bucket}/{io_file_name}'


def get_uworker_output_upload_urls():
  """Returns a GCS path for the tworker/preprocess to upload the input to and a
  signed download URL for the uworker to download the input."""
  gcs_path = get_uworker_io_gcs_path()
  # Note that the signed upload URL can't automatically be downloaded from.
  return storage.get_signed_upload_url(gcs_path), gcs_path


def get_uworker_input_urls():
  """Returns a GCS path for the tworker/preprocess to upload the input to and a
  signed download URL for the uworker to download the input."""
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
    uworker_input[name] = UworkerEntityWrapper(entity)
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
  data = storage.download_signed_url(uworker_input_download_url)
  return deserialize_uworker_input(data)


def serialize_uworker_output(uworker_output):
  """Serializes uworker's output for deserializing by deserialize_uworker_output
  and consumption by postprocess_task."""
  entities = {}
  serializable = {}

  for name, value in uworker_output.items():
    if not isinstance(value, UworkerEntityWrapper):
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
  storage.upload_signed_url(uworker_output, upload_url)


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


# def get_utask_upload_url(entity):
#   return _get_utask_optional_field(entity, 'signed_upload_url')

# def get_utask_download_url(entity):
#   return _get_utask_optional_field(entity, 'signed_download_url')

# def get_utask_optional_field(entity, fieldname):
#   return getattr(entity, fieldname, None)


class UworkerEntityWrapper:
  """Wrapper for db entities on the uworker. This wrapper functions the same as
  the entity but also tracks changes made to the entity. This makes for easier
  results processing by trusted workers (who now don't need to clobber the
  entire entity when writing to the db, but can instead update just the modified
  fields."""

  def __init__(self, entity, signed_download_url=None, signed_upload_url=None):
    # Everything set here, must be in the list in __setattr__
    self._entity = entity

  def __getattr__(self, attribute):
    return getattr(self._entity, attribute)

  def __setattr__(self, attribute, value):
    if attribute in ['_entity']:
      # Allow setting and changing _entity. Stack overflow in __init__
      # otherwise.
      super().__setattr__(attribute, value)
      return
    if getattr(self._entity, '_wrapped_changed_attributes', None) is None:
      # Ensure we can track changes.
      setattr(self._entity, '_wrapped_changed_attributes', {})
    # Record the attribute change.
    getattr(self._entity, '_wrapped_changed_attributes')[attribute] = value
    # Make the attribute change.
    setattr(self._entity, attribute, value)


def download_and_deserialize_uworker_output(output_url) -> str:
  with tempfile.TemporaryDirectory() as temp_dir:
    uworker_output_local_path = os.path.join(temp_dir, 'temp')
    storage.copy_file_from(output_url, uworker_output_local_path)
    with open(uworker_output_local_path) as uworker_output_file_handle:
      uworker_output = uworker_output_file_handle.read()
  return deserialize_uworker_output(uworker_output)
