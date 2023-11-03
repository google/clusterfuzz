"""TODO(titouan)

...
"""

import abc
import dataclasses
import json
from typing import Any
from typing import Dict
from typing import Generic
from typing import List
from typing import Tuple
from typing import Type
from typing import TypeVar
from typing import Union

from google.cloud import ndb
from google.cloud.datastore_v1.proto import entity_pb2
from google.cloud.ndb import model  # pyright: ignore[reportMissingModuleSource]
from google.protobuf import message

from clusterfuzz._internal.datastore import data_types
#from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.protos import uworker_msg_pb2

T = TypeVar('T', bound=message.Message)


# WIP, seems too complicated
class ComplexProtoConvertible(Generic[T], abc.ABC):

  @abc.abstractmethod
  def _make_proto(self) -> T:
    pass

  @abc.abstractmethod
  def _fields(self) -> Tuple[dataclasses.Field, ...]:
    pass

  def copy_to_proto(self) -> T:
    proto = self._make_proto()

    fields = self._fields()
    descriptor = proto.DESCRIPTOR
    assert len(descriptor.fields) == len(fields)

    for field in fields:
      field_descriptor = descriptor.fields_by_name.get(field.name)
      if field_descriptor is None:
        raise ValueError(
            f'{type(self).__name__} has a field named {field.name} that does ' +
            f'not exist in proto {descriptor.name}')

      if field_descriptor.label == field_descriptor.LABEL_REPEATED:
        assert field.type is list

    return proto

  def copy_from_proto(self, proto: T):
    return


class ProtoConvertible(Generic[T], abc.ABC):

  @abc.abstractmethod
  def to_proto(self) -> T:
    pass

  @classmethod
  @abc.abstractmethod
  def from_proto(cls, T) -> "ProtoConvertible[T]":
    pass


def json_to_proto(value: Any) -> uworker_msg_pb2.Json:
  serialized = json.dumps(value)
  return uworker_msg_pb2.Json(serialized=serialized)


def json_from_proto(proto: uworker_msg_pb2.Json) -> Any:
  return json.loads(proto.serialized)


def model_to_proto(mdl: ndb.Model) -> entity_pb2.Entity:
  return model._entity_to_protobuf(mdl)  # pyright: ignore


def model_from_proto(entity: entity_pb2.Entity) -> ndb.Model:
  return model._entity_from_protobuf(entity)  # pyright: ignore


@dataclasses.dataclass
class AnalyzeTaskInput(ProtoConvertible[uworker_msg_pb2.AnalyzeTaskInput]):
  """Input for analyze_task.uworker_main."""
  bad_revisions: List[int]

  def to_proto(self) -> uworker_msg_pb2.AnalyzeTaskInput:
    return uworker_msg_pb2.AnalyzeTaskInput(bad_revisions=self.bad_revisions)

  @classmethod
  def from_proto(cls,
                 proto: uworker_msg_pb2.AnalyzeTaskInput) -> "AnalyzeTaskInput":
    return cls(bad_revisions=list(proto.bad_revisions))


_input = AnalyzeTaskInput([])


@dataclasses.dataclass
class AnalyzeTaskOutput(ProtoConvertible[uworker_msg_pb2.AnalyzeTaskOutput]):

  def to_proto(self) -> uworker_msg_pb2.AnalyzeTaskOutput:
    return uworker_msg_pb2.AnalyzeTaskOutput()

  @classmethod
  def from_proto(cls, _proto: uworker_msg_pb2.AnalyzeTaskOutput):
    return cls()
