"""TODO(titouan)

...
"""

from dataclass import dataclass
from typing import List
from typing import Generic
from typing import TypeVar

from google.cloud import ndb
from google.cloud.datastore_v1.proto import entity_pb2
from google.cloud.ndb import model
from google.protobuf import message

from clusterfuzz._internal.datastore import data_types
#from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.protos import uworker_msg_pb2


T = TypeVar('T', bound=message.Message)


class ProtoConvertible(Generic[T]):
  def __init__(self, message_type: type[T]):
    self._message_type = message_type


@dataclass
class AnalyzeTaskInput(ProtoConvertible[uworker_msg_pb2.AnalyzeTaskInput]):
  """Input for analyze_task.uworker_main."""
  bad_revisions: List[int]
