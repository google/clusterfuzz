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
"""Issue tracker comments."""

import datetime
import re
from typing import List
from typing import Optional


class Comment:
  """Class representing a single comment update."""

  def __init__(self) -> None:
    self.author: Optional[str] = None
    self.cc: Optional[List[str]] = None
    self.comment: Optional[str] = None
    self.components: List[str] = []
    self.created: Optional[datetime.datetime] = None
    self.labels: List[str] = []
    self.summary: Optional[str] = None
    self.status: Optional[str] = None
    self.owner: Optional[str] = None
    self.id: int = 0

  def has_label_containing(self, expression: str) -> bool:
    return any(self.get_labels_containing(expression))

  def get_labels_containing(self, expression: str) -> List[str]:
    regex = re.compile(expression, re.DOTALL | re.IGNORECASE)
    return [label for label in self.labels if regex.search(label)]

  def has_label_matching(self, expression: str) -> bool:
    return any(self.get_labels_matching(expression))

  def get_labels_matching(self, expression: str) -> List[str]:
    regex = re.compile(expression + r'\Z', re.DOTALL | re.IGNORECASE)
    return [label for label in self.labels if regex.match(label)]

  def get_labels_by_prefix(self, prefix: str) -> List[str]:
    return self.get_labels_matching('%s.*' % prefix)

  def has_label(self, value: str) -> bool:
    for label in self.labels:
      if label.lower() == value.lower():
        return True

    return False
