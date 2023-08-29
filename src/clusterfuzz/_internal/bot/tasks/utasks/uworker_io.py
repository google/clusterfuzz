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

import collections
import json
import uuid

from google.cloud import ndb
from google.cloud.datastore_v1.proto import entity_pb2
from google.cloud.ndb import model
from google.protobuf import message

from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.google_cloud_utils import storage
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.protos import uworker_msg_pb2


def generate_new_input_file_name():
  """Generates a new input file name."""
  return str(uuid.uuid4()).lower()


def get_uworker_input_gcs_path():
  """Returns a GCS path for uworker I/O."""
  # Inspired by blobs.write_blob.
  io_bucket = storage.uworker_input_bucket()
  io_file_name = generate_new_input_file_name()
  if storage.get(storage.get_cloud_storage_file_path(io_bucket, io_file_name)):
    raise RuntimeError(f'UUID collision found: {io_file_name}.')
  return f'/{io_bucket}/{io_file_name}'


def get_uworker_output_urls(input_gcs_path):
  """Returns a signed download URL for the uworker to upload the output and a
  GCS url for the tworker to download the output. Make sure we can infer the
  actual input since the output is not trusted."""
  gcs_path = uworker_input_path_to_output_path(input_gcs_path)
  # Note that the signed upload URL can't be directly downloaded from.
  return storage.get_signed_upload_url(gcs_path), gcs_path


def uworker_input_path_to_output_path(input_gcs_path):
  return input_gcs_path.replace(storage.uworker_input_bucket(),
                                storage.uworker_output_bucket())


def uworker_output_path_to_input_path(output_gcs_path):
  return output_gcs_path.replace(storage.uworker_output_bucket(),
                                 storage.uworker_input_bucket())


def get_uworker_input_urls():
  """Returns a signed download URL for the uworker to download the input and a
  GCS url for the tworker to upload it (this happens first)."""
  gcs_path = get_uworker_input_gcs_path()
  return storage.get_signed_download_url(gcs_path), gcs_path


def upload_uworker_input(uworker_input, gcs_path):
  """Uploads input for the untrusted portion of a task."""
  storage.write_data(uworker_input, gcs_path)


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


def get_proto_fields(proto):
  """Returns a generator containing tuples of (field_name, field_value) for each
  field in the proto messsage. None is used for fields that are not set. This is
  a little different than the behavior of protobuf which sets the value to a
  Falsey version of the same type e.g. string fields are empty strings, int
  fields are 0."""
  for descriptor in proto.DESCRIPTOR.fields:
    field_name = descriptor.name
    try:
      has_field = proto.HasField(field_name)
    except AttributeError as error:
      # This probably occurs after a deploy.
      logs.log_error(f'Error getting proto fields {error}.')
      has_field = False
    except ValueError:
      field_value = getattr(proto, field_name, [])
      yield field_name, field_value, descriptor
      continue
    if has_field:
      field_value = getattr(proto, field_name)
    else:
      field_value = None
    yield field_name, field_value, descriptor


def deserialize_proto_field(field_value, field_descriptor, is_input):
  """Converts a proto field |field_value| to a deserialized representation of
  its contents for use by code outside of this module. The deserialized value
  can contain real ndb models and other python objects, instead of only the
  python serialized versions. |field_descriptor| is used to check for repeated
  fields and can be None."""
  if isinstance(field_value, uworker_msg_pb2.UworkerEntityWrapper):
    assert not is_input
    field_value = deserialize_wrapped_entity(field_value)
  elif isinstance(field_value, uworker_msg_pb2.Json):
    field_value = json.loads(field_value.serialized)
  elif isinstance(field_value, entity_pb2.Entity):
    assert is_input
    field_value = UworkerEntityWrapper(model._entity_from_protobuf(field_value))  # pylint: disable=protected-access
  elif field_descriptor is not None and (
      field_descriptor.label == field_descriptor.LABEL_REPEATED):
    initial_field_value = field_value
    # We can pass None as the descriptor because we know it won't be repeated.
    field_value = [
        deserialize_proto_field(element, None, is_input)
        for element in initial_field_value
    ]
  elif isinstance(field_value, message.Message):
    # This must come last! Otherwise it subsumes more specific types.
    field_value = proto_to_deserialized_msg_object(field_value, is_input)
  return field_value


def deserialize_uworker_input(serialized_uworker_input):
  """Deserializes input for the untrusted part of a task."""
  uworker_input_proto = uworker_msg_pb2.Input()
  uworker_input_proto.ParseFromString(serialized_uworker_input)
  uworker_input = proto_to_deserialized_msg_object(
      uworker_input_proto, is_input=True)
  return uworker_input


def serialize_uworker_input(uworker_input):
  """Serializes and returns |uworker_input| as JSON. Can handle ndb entities."""
  return uworker_input.serialize()


def serialize_and_upload_uworker_input(uworker_input) -> str:
  """Serializes input for the untrusted portion of a task."""
  signed_input_download_url, input_gcs_url = get_uworker_input_urls()
  # Get URLs for the uworker'ps output. We need a signed upload URL so it can
  # write its output. Also get a download URL in case the caller wants to read
  # the output.
  signed_output_upload_url, output_gcs_url = get_uworker_output_urls(
      input_gcs_url)

  assert not getattr(uworker_input, 'uworker_output_upload_url', None)
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
  changed = json.dumps(list(wrapped_entity.get_changed_attrs()))  # pylint: disable=protected-access
  changed = uworker_msg_pb2.Json(serialized=changed)
  wrapped_entity_proto = uworker_msg_pb2.UworkerEntityWrapper(
      entity=entity_proto, changed=changed)
  return wrapped_entity_proto


def serialize_and_upload_uworker_output(uworker_output, upload_url):
  """Serializes |uworker_output| and uploads it to |upload_url."""
  uworker_output = serialize_uworker_output(uworker_output)
  storage.upload_signed_url(uworker_output, upload_url)


def download_input_based_on_output_url(output_url):
  input_url = uworker_output_path_to_input_path(output_url)
  serialized_uworker_input = storage.read_data(input_url)
  return deserialize_uworker_input(serialized_uworker_input)


def download_and_deserialize_uworker_output(output_url: str):
  """Downloads and deserializes uworker output."""
  serialized_uworker_output = storage.read_data(output_url)

  uworker_output = deserialize_uworker_output(serialized_uworker_output)

  # Now download the input, which is stored securely so that the uworker cannot
  # tamper with it.
  uworker_input = download_input_based_on_output_url(output_url)

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


def proto_to_deserialized_msg_object(serialized_msg_proto, is_input):
  """Converts a |serialized_msg_proto| to a deserialized representation of its
  contents for use by code outside of this module. The deserialized object can
  contain real ndb models and other python objects, instead of only the python
  serialized versions."""
  deserialized_msg = DeserializedUworkerMsg()
  for field_name, field_value, descriptor in get_proto_fields(
      serialized_msg_proto):
    field_value = deserialize_proto_field(field_value, descriptor, is_input)
    setattr(deserialized_msg, field_name, field_value)
  return deserialized_msg


def deserialize_uworker_output(uworker_output_str):
  """Deserializes uworker's execute output for postprocessing. Returns a dict
  that can be passed as kwargs to postprocess. Changes made db entities that
  were modified during the untrusted portion of the task will be done to those
  entities here."""
  # Deserialize the proto.
  uworker_output_proto = uworker_msg_pb2.Output()
  uworker_output_proto.ParseFromString(uworker_output_str)
  uworker_output = proto_to_deserialized_msg_object(
      uworker_output_proto, is_input=False)
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
    self._wrapped_changed_attributes = set()
    self._wrapper_initial_dict = self._entity.__dict__['_values'].copy()

  def __getattr__(self, attribute):
    if attribute in [
        '_entity', '_wrapped_changed_attributes', '_wrapper_initial_dict'
    ]:
      # Allow setting and changing _entity and _wrapped_changed_attributes.
      # Stack overflow in __init__ otherwise.
      return super().__getattr__(attribute)  # pylint: disable=no-member
    return getattr(self._entity, attribute)

  def __setattr__(self, attribute, value):
    if attribute in [
        '_entity', '_wrapped_changed_attributes', '_wrapper_initial_dict'
    ]:
      # Allow setting and changing _entity. Stack overflow in __init__
      # otherwise.
      super().__setattr__(attribute, value)
      return
    self._wrapped_changed_attributes.add(attribute)
    setattr(self._entity, attribute, value)

  def get_changed_attrs(self):
    """Gets changed attributes."""
    # TODO(metzman): Use __dict__ comparision method in get_changed_attrs to
    # track all changes.
    # Get attributes changed by methods too.
    current_dict = self._entity.__dict__['_values']
    changed = self._wrapped_changed_attributes.copy()
    wrapper_initial_dict = self._wrapper_initial_dict
    for key, value in wrapper_initial_dict.items():
      if key in changed:
        continue
      try:
        if value != current_dict[key]:
          changed.add(key)
      except KeyError:
        changed.add(key)
    return changed


class UworkerMsg:
  """Convenience class for results utask_function. This is useful for ensuring
  we are returning values for fields expected by main or postprocess."""

  # Child must implement.
  PROTO_CLS = None

  def __init__(self, **kwargs):
    self.proto = self.PROTO_CLS()  # pylint: disable=not-callable
    for key, value in kwargs.items():
      setattr(self, key, value)

    assert self.PROTO_CLS is not None

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


class FuzzTaskOutput(UworkerMsg):
  """Class representing an unserialized FuzzTaskOutput message from
  fuzz_task."""

  PROTO_CLS = uworker_msg_pb2.FuzzTaskOutput

  def save_rich_type(self, attribute, value):
    field = getattr(self.proto, attribute)
    if isinstance(value, (dict, list)):
      save_json_field(field, value)
      return

    raise ValueError(f'{value} is of type {type(value)}. Can\'t serialize.')


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

    # TODO(metzman): Remove this once everything is migrated. This is only
    # needed because some functions need to support utasks and non-utasks at the
    # same time.
    if isinstance(value, uworker_msg_pb2.Input):
      field.CopyFrom(value)
      return

    if isinstance(value, UworkerMsg):
      field.CopyFrom(value.proto)
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

    if isinstance(value, UworkerMsg):
      field.CopyFrom(value.proto)
      return

    if not isinstance(value, ndb.Model):
      raise ValueError(f'{value} is of type {type(value)}. Can\'t serialize.')

    entity_proto = model._entity_to_protobuf(value)  # pylint: disable=protected-access
    field.CopyFrom(entity_proto)


class UpdateFuzzerAndDataBundleInput(UworkerInput):
  """Input for setup.update_fuzzer_and_data_bundle in uworker_main."""
  PROTO_CLS = uworker_msg_pb2.UpdateFuzzerAndDataBundlesInput

  def save_rich_type(self, attribute, value):
    field = getattr(self.proto, attribute)
    if isinstance(field, collections.Sequence):
      # This the way to tell if it's a repeated field.
      # We can't get the type of the repeated field directly.
      value = list(value)
      if len(value) == 0:
        return
      assert isinstance(value[0], ndb.Model), value[0]
      field.extend([model._entity_to_protobuf(entity) for entity in value])  # pylint: disable=protected-access
      return

    super().save_rich_type(attribute, value)


class DeserializedUworkerMsg:

  def __init__(self, testcase=None, error=None, **kwargs):
    self.testcase = testcase
    self.error = error
    for key, value in kwargs.items():
      setattr(self, key, value)
