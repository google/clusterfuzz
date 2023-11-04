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
"""TODO(titouan)

...
"""

import abc
import dataclasses
import json
from typing import Any
from typing import Generic
from typing import List
from typing import Tuple
from typing import TypeVar

from google.cloud import ndb
from google.cloud.datastore_v1.proto import entity_pb2
from google.cloud.ndb import model  # pyright: ignore[reportMissingModuleSource]
from google.protobuf import message

from clusterfuzz._internal.datastore import data_types
#from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.protos import uworker_msg_pb2

T = TypeVar('T', bound=message.Message)


# WIP, seems too complicated, abandoned for now.
class ComplexProtoConvertible(Generic[T], abc.ABC):
  """WIP attempt to define a superclass that would generate proto conversion
  automatically based on proto and dataclass field descriptors.

  Seems too complicated, abandoned for now.
  """

  @abc.abstractmethod
  def _make_proto(self) -> T:
    """TODO."""

  @abc.abstractmethod
  def _fields(self) -> Tuple[dataclasses.Field, ...]:
    """TODO."""

  def copy_to_proto(self) -> T:
    """TODO."""
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
    """TODO."""
    del proto


# TODO: Is this useful at all?
class ProtoConvertible(Generic[T], abc.ABC):

  @abc.abstractmethod
  def to_proto(self) -> T:
    pass

  @classmethod
  @abc.abstractmethod
  def from_proto(cls, proto: T) -> "ProtoConvertible[T]":
    pass


def json_to_proto(value: Any) -> uworker_msg_pb2.Json:
  """TODO
  """
  serialized = json.dumps(value)
  return uworker_msg_pb2.Json(serialized=serialized)


def json_from_proto(proto: uworker_msg_pb2.Json) -> Any:
  """TODO
  """
  return json.loads(proto.serialized)


def model_to_proto(mdl: ndb.Model) -> entity_pb2.Entity:
  """TODO
  """
  return model._entity_to_protobuf(mdl)  # pyright: ignore # pylint: disable=protected-access


def model_from_proto(entity: entity_pb2.Entity) -> ndb.Model:
  """TODO
  """
  return model._entity_from_protobuf(entity)  # pyright: ignore # pylint: disable=protected-access


@dataclasses.dataclass
class AnalyzeTaskInput(ProtoConvertible[uworker_msg_pb2.AnalyzeTaskInput]):
  """Input for `analyze_task.uworker_main()`.

  See `uworker_msg_pb2.AnalyzeTaskInput` for field documentation.
  """

  bad_revisions: List[int]

  def to_proto(self) -> uworker_msg_pb2.AnalyzeTaskInput:
    """TODO.
    """
    return uworker_msg_pb2.AnalyzeTaskInput(bad_revisions=self.bad_revisions)

  @classmethod
  def from_proto(cls,
                 proto: uworker_msg_pb2.AnalyzeTaskInput) -> "AnalyzeTaskInput":
    """TODO.
    """
    return cls(bad_revisions=list(proto.bad_revisions))


# message Input {
#   optional google.datastore.v1.Entity testcase_upload_metadata = 2;
#   optional string job_type = 6;
#   // uworker_io is the only module that should be using this.
#   optional string uworker_output_upload_url = 7;
#   optional google.datastore.v1.Entity variant = 8;
#   optional string original_job_type = 9;
#   optional string fuzzer_name = 10;
#   optional SetupInput setup_input = 11;
#   optional AnalyzeTaskInput analyze_task_input = 12;
#   optional CorpusPruningTaskInput corpus_pruning_task_input = 13;
#   optional FuzzTaskInput fuzz_task_input = 14;
#   optional MinimizeTaskInput minimize_task_input = 15;
#   optional ProgressionTaskInput progression_task_input = 16;
#   optional RegressionTaskInput regression_task_input = 17;
#   optional SymbolizeTaskInput symbolize_task_input = 18;
#   optional string module_name = 19;
# }
@dataclasses.dataclass
class Input(ProtoConvertible[uworker_msg_pb2.Input]):
  """Input for uworkers.

  See `Input` proto definition for more details.
  """

  testcase: data_types.Testcase
  uworker_env: Any
  testcase_id: str

  def to_proto(self) -> uworker_msg_pb2.Input:
    testcase = model_to_proto(self.testcase)
    uworker_env = json_to_proto(self.uworker_env)
    return uworker_msg_pb2.Input(
        testcase=testcase,
        testcase_id=self.testcase_id,
        uworker_env=uworker_env,
    )

  @classmethod
  def from_proto(cls, proto: uworker_msg_pb2.Input):
    testcase = model_from_proto(proto.testcase)
    assert isinstance(testcase, data_types.Testcase)

    uworker_env = json_from_proto(proto.uworker_env)
    return cls(
        testcase=testcase,
        testcase_id=proto.testcase_id,
        uworker_env=uworker_env,
    )


@dataclasses.dataclass
class AnalyzeTaskOutput(ProtoConvertible[uworker_msg_pb2.AnalyzeTaskOutput]):

  def to_proto(self) -> uworker_msg_pb2.AnalyzeTaskOutput:
    return uworker_msg_pb2.AnalyzeTaskOutput()

  @classmethod
  def from_proto(cls, proto: uworker_msg_pb2.AnalyzeTaskOutput):
    del proto
    return cls()
