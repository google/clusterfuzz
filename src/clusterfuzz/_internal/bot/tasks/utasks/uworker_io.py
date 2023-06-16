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

import json
import os
import uuid

from google.cloud import ndb
from google.cloud.datastore_v1.proto import entity_pb2
from google.cloud.ndb import model

from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.google_cloud_utils import storage
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.protos import uworker_msg_pb2
from clusterfuzz._internal.system import environment


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
  uworker_input_filename = _get_tmp_file_for_io()
  with open(uworker_input_filename, 'wb') as uworker_input_file:
    uworker_input_file.write(uworker_input)
  if not storage.copy_file_to(uworker_input_filename, gcs_path):
    raise RuntimeError('Failed to upload uworker_input.')


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
  uworker_input = DeserializedUworkerMsg()
  for descriptor, field in uworker_input_proto.ListFields():
    if isinstance(field, entity_pb2.Entity):
      entity_wrapper = UworkerEntityWrapper(model._entity_from_protobuf(field))  # pylint: disable=protected-access
      setattr(uworker_input, descriptor.name, entity_wrapper)
    elif isinstance(field, uworker_msg_pb2.Json):
      setattr(uworker_input, descriptor.name, json.loads(field.serialized))
    else:
      setattr(uworker_input, descriptor.name, field)
  return uworker_input


def serialize_uworker_input(uworker_input):
  """Serializes and returns |uworker_input| as JSON. Can handle ndb entities."""
  return uworker_input.serialize()


def serialize_and_upload_uworker_input(uworker_input, job_type) -> str:
  """Serializes input for the untrusted portion of a task."""
  # Add remaining fields to the input.

  assert getattr(uworker_input, 'job_type', None) is None
  uworker_input.job_type = job_type

  signed_input_download_url, input_gcs_url = get_uworker_input_urls()
  # Get URLs for the uworker'ps output. We need a signed upload URL so it can
  # write its output. Also get a download URL in case the caller wants to read
  # the output.
  signed_output_upload_url, output_gcs_url = get_uworker_output_urls(
      input_gcs_url)

  assert getattr(uworker_input, 'uworker_output_upload_url', None) is None
  uworker_input.uworker_output_upload_url = signed_output_upload_url

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
  return uworker_output_obj.serialize()


def serialize_wrapped_entity(wrapped_entity):
  entity_proto = model._entity_to_protobuf(wrapped_entity._entity)  # pylint: disable=protected-access
  changed = json.dumps(list(wrapped_entity._wrapped_changed_attributes.keys()))  # pylint: disable=protected-access
  changed = uworker_msg_pb2.Json(serialized=changed)
  wrapped_entity_proto = uworker_msg_pb2.UworkerEntityWrapper(
      entity=entity_proto, changed=changed)
  return wrapped_entity_proto


def serialize_and_upload_uworker_output(uworker_output, upload_url):
  """Serializes |uworker_output| and uploads it to |upload_url."""
  uworker_output = serialize_uworker_output(uworker_output)
  storage.upload_signed_url(uworker_output, upload_url)


def _get_tmp_file_for_io():
  tmp_dir = environment.get_value('BOT_TMPDIR')
  # Don't use tempfile because of permissions issues on Windows. See
  # https://github.com/google/clusterfuzz/issues/3158.
  tmp_file_for_storage = os.path.join(tmp_dir, 'uworker-io-storage')
  return tmp_file_for_storage


def _download_uworker_io_from_gcs(gcs_url):
  tmp_file_for_storage = _get_tmp_file_for_io()
  if not storage.copy_file_from(gcs_url, tmp_file_for_storage):
    logs.log_error('Could not download uworker I/O file from %s' % gcs_url)
    return None
  with open(tmp_file_for_storage, 'rb') as file_handle:
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
  uworker_output.uworker_env = uworker_input.uworker_env  # pylint: disable=no-member
  uworker_output.uworker_input = uworker_input
  return uworker_output


def deserialize_wrapped_entity(wrapped_entity_proto):
  """Deserializes a proto representing a db entity."""
  # TODO(metzman): Add verification to ensure only the correct object is
  # retreived.
  changed_entity = model._entity_from_protobuf(wrapped_entity_proto.entity)  # pylint: disable=protected-access
  changes = json.loads(wrapped_entity_proto.changed.serialized)
  original_entity = changed_entity.key.get()
  if original_entity is None:  # Object is new.
    return changed_entity
  for changed_attr_name in changes:
    changed_attr_value = getattr(changed_entity, changed_attr_name)
    setattr(original_entity, changed_attr_name, changed_attr_value)
  return original_entity


def deserialize_uworker_output(uworker_output_str):
  """Deserializes uworker's execute output for postprocessing. Returns a dict
  that can be passed as kwargs to postprocess. Changes made db entities that
  were modified during the untrusted portion of the task will be done to those
  entities here."""
  # Deserialize the proto.
  uworker_output_proto = uworker_msg_pb2.Output()
  uworker_output_proto.ParseFromString(uworker_output_str)

  # Convert the proto to a Python object that can contain real ndb models and
  # other python objects, instead of only the python serialized versions.
  uworker_output = DeserializedUworkerMsg()
  for field_descriptor, field in uworker_output_proto.ListFields():
    if isinstance(field, uworker_msg_pb2.UworkerEntityWrapper):
      field = deserialize_wrapped_entity(field)
    setattr(uworker_output, field_descriptor.name, field)
  return uworker_output


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


class UworkerMsg:
  """Convenience class for results utask_function. This is useful for ensuring
  we are returning values for fields expected by main or postprocess."""

  # Child must implement.
  PROTO_CLS = None

  def __init__(self, **kwargs):
    self.proto = self.PROTO_CLS()  # pylint: disable=not-callable
    for key, value in kwargs.items():
      setattr(self, key, value)

  def __getattr__(self, attribute):
    if attribute in ['proto']:
      # Allow setting and changing proto. Stack overflow in __init__ otherwise.
      return super().__getattr__(attribute)  # pylint: disable=no-member
    return getattr(self.proto, attribute)

  def __setattr__(self, attribute, value):
    super().__setattr__(attribute, value)
    if attribute in ['proto']:
      # Allow setting and changing proto. Stack overflow in __init__
      # otherwise.
      return

    field_descriptor = self.proto.DESCRIPTOR.fields_by_name[attribute]
    if field_descriptor.message_type is None:
      setattr(self.proto, attribute, value)
      return

    if value is None:
      return

    self.save_rich_type(attribute, value)

  def save_rich_type(self, attribute, value):
    raise NotImplementedError('Child must implement.')

  def serialize(self):
    return self.proto.SerializeToString()


def save_json_field(field, value):
  serialized_json = uworker_msg_pb2.Json(serialized=json.dumps(value))
  field.CopyFrom(serialized_json)


class UworkerOutput(UworkerMsg):
  """Class representing an unserialized UworkerOutput message from
  utask_main."""
  PROTO_CLS = uworker_msg_pb2.Output

  def save_rich_type(self, attribute, value):
    field = getattr(self.proto, attribute)
    if isinstance(value, dict):
      save_json_field(field, value)
      return

    if not isinstance(value, UworkerEntityWrapper):
      raise ValueError(f'{value} is of type {type(value)}. Can\'t serialize.')

    wrapped_entity_proto = serialize_wrapped_entity(value)
    field.CopyFrom(wrapped_entity_proto)


class UworkerInput(UworkerMsg):
  """Class representing an unserialized UworkerInput message from
  utask_preprocess."""
  PROTO_CLS = uworker_msg_pb2.Input

  def save_rich_type(self, attribute, value):
    field = getattr(self.proto, attribute)
    if isinstance(value, dict):
      save_json_field(field, value)
      return

    if not isinstance(value, ndb.Model):
      raise ValueError(f'{value} is of type {type(value)}. Can\'t serialize.')

    entity_proto = model._entity_to_protobuf(value)  # pylint: disable=protected-access
    field.CopyFrom(entity_proto)


class DeserializedUworkerMsg:

  def __init__(self, testcase=None, error=None, **kwargs):
    self.testcase = testcase
    self.error = error
    for key, value in kwargs.items():
      setattr(self, key, value)
