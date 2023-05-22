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
from typing import Optional
import uuid

from google.cloud import ndb
from google.cloud.datastore_v1.proto import entity_pb2
from google.cloud.ndb import model

from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.google_cloud_utils import storage
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.protos import uworker_msg_pb2


def generate_new_io_file_name():
  """Generates a new I/O file name."""
  return str(uuid.uuid4()).lower()


def get_uworker_io_gcs_path():
  """Returns a GCS path for uworker I/O."""
  # Inspired by blobs.write_blob.
  io_bucket = storage.uworker_io_bucket()
  io_file_name = generate_new_io_file_name()
  if storage.get(storage.get_cloud_storage_file_path(io_bucket, io_file_name)):
    raise RuntimeError(f'UUID collision found: {io_file_name}.')
  return f'/{io_bucket}/{io_file_name}'


def get_uworker_output_urls():
  """Returns a signed download URL for the uworker to upload the output and a
  GCS url for the tworker to download the output."""
  gcs_path = get_uworker_io_gcs_path()
  # Note that the signed upload URL can't be directly downloaded from.
  return storage.get_signed_upload_url(gcs_path), gcs_path


def get_uworker_input_urls():
  """Returns a signed download URL for the uworker to download the input and a
  GCS url for the tworker to upload it (this happens first)."""
  gcs_path = get_uworker_io_gcs_path()
  return storage.get_signed_download_url(gcs_path), gcs_path


def upload_uworker_input(uworker_input):
  """Uploads input for the untrusted portion of a task."""
  signed_download_url, gcs_path = get_uworker_input_urls()

  with tempfile.NamedTemporaryFile() as uworker_input_file:
    with open(uworker_input_file.name, 'wb') as fp:
      fp.write(uworker_input)
    if not storage.copy_file_to(uworker_input_file.name, gcs_path):
      raise RuntimeError('Failed to upload uworker_input.')
  return signed_download_url


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
  uworker_input_proto = uworker_msg_pb2.Input()
  uworker_input_proto.ParseFromString(serialized_uworker_input)
  input_dict = {}
  for descriptor, field in uworker_input_proto.ListFields():
    if isinstance(field, entity_pb2.Entity):
      input_dict[descriptor.name] = model._entity_from_protobuf(field)  # pylint: disable=protected-access
    elif isinstance(field, uworker_msg_pb2.Json):
      input_dict[descriptor.name] = json.loads(field.serialized)
    else:
      input_dict[descriptor.name] = field
  return input_dict


def serialize_uworker_input(uworker_input):
  """Serializes and returns |uworker_input| as JSON. Can handle ndb entities."""
  uworker_input = uworker_input.copy()
  for key, value in uworker_input.items():
    if isinstance(value, ndb.Model):
      uworker_input[key] = model._entity_to_protobuf(value)  # pylint: disable=protected-access
    elif isinstance(value, dict):
      value = json.dumps(value)
      uworker_input[key] = uworker_msg_pb2.Json(serialized=value)

  uworker_input = uworker_msg_pb2.Input(**uworker_input)
  return uworker_input.SerializeToString()


def serialize_and_upload_uworker_input(uworker_input, job_type,
                                       uworker_output_upload_url) -> str:
  """Serializes input for the untrusted portion of a task."""
  # Add remaining fields to the input.
  assert 'job_type' not in uworker_input
  uworker_input['job_type'] = job_type
  assert 'uworker_output_upload_url' not in uworker_input
  uworker_input['uworker_output_upload_url'] = uworker_output_upload_url

  uworker_input = serialize_uworker_input(uworker_input)
  uworker_input_download_url = upload_uworker_input(uworker_input)
  return uworker_input_download_url


def download_and_deserialize_uworker_input(uworker_input_download_url):
  """Downloads and deserializes the input to the uworker from the signed
  download URL."""
  data = storage.download_signed_url(uworker_input_download_url)
  return deserialize_uworker_input(data)


def serialize_uworker_output(uworker_output_obj):
  """Serializes uworker's output for deserializing by deserialize_uworker_output
  and consumption by postprocess_task."""
  uworker_output = uworker_output_obj.to_dict()
  # Delete entities from uworker_input, they are annoying to serialize and
  # unnecessary since the only reason they would be passed as input is if they
  # are modified and will be output.
  uworker_input = uworker_output['uworker_input']
  for key in list(uworker_input.keys()):
    if isinstance(uworker_input[key], UworkerEntityWrapper):
      del uworker_input[key]
      continue
  entities = {}
  serializable = {}
  error = uworker_output.pop('error', None)
  if error is not None:
    error = error.value

  proto_output = uworker_msg_pb2.Output()
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


def download_and_deserialize_uworker_output(output_url) -> Optional[str]:
  """Downloads and deserializes uworker output."""
  with tempfile.NamedTemporaryFile() as uworker_output_local_path:
    if not storage.copy_file_from(output_url, uworker_output_local_path.name):
      logs.log_error('Could not download uworker output from %s' % output_url)
      return None
    with open(uworker_output_local_path.name) as uworker_output_file_handle:
      uworker_output = uworker_output_file_handle.read()
  return deserialize_uworker_output(uworker_output)


def deserialize_uworker_output(uworker_output):
  """Deserializes uworker's execute output for postprocessing. Returns a dict
  that can be passed as kwargs to postprocess. Changes made db entities that
  were modified during the untrusted portion of the task will be done to those
  entities here."""
  uworker_output = json.loads(uworker_output)
  deserialized_output = uworker_output['serializable']
  error = uworker_output.pop('error')
  if error is not None:
    # !!!
    deserialized_output['error'] = uworker_msg_pb2.ErrorType(error)
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
  return deserialized_output


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
