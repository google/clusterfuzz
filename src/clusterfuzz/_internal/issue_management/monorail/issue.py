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
"""Helper classes for managing issues."""

import datetime
import re
from typing import Any
from typing import Dict
from typing import Iterable
from typing import List
from typing import Optional
from typing import Set
from typing import TYPE_CHECKING

if TYPE_CHECKING:
  from .comment import Comment
  from .issue_tracker_manager import IssueTrackerManager


def get_values_containing(target: Iterable[str], expression: str) -> List[str]:
  regex = re.compile(expression, re.DOTALL | re.IGNORECASE)
  return [value for value in target if regex.search(value)]


def get_values_matching(target: Iterable[str], expression: str) -> List[str]:
  regex = re.compile(expression + r'\Z', re.DOTALL | re.IGNORECASE)
  return [value for value in target if regex.match(value)]


def has_values_containing(target: Iterable[str], expression: str) -> bool:
  return any(get_values_containing(target, expression))


def has_values_matching(target: Iterable[str], expression: str) -> bool:
  return any(get_values_matching(target, expression))


def has_value(target: Iterable[str], value: str) -> bool:
  for target_value in target:
    if target_value.lower() == value.lower():
      return True

  return False


class ChangeList(list):
  """List that tracks changes for incremental updates."""

  def __init__(self, seq: Iterable[Any] = ()) -> None:
    super().__init__(seq)
    self.added: Set[Any] = set()
    self.removed: Set[Any] = set()

  def append(self, p_object: Any) -> None:
    list.append(self, p_object)

    if p_object in self.removed:
      self.removed.remove(p_object)
    else:
      self.added.add(p_object)

  def remove(self, value: Any) -> None:
    list.remove(self, value)

    if value in self.added:
      self.added.remove(value)
    else:
      self.removed.add(value)

  def is_changed(self) -> bool:
    return (len(self.added) + len(self.removed)) > 0

  def reset(self) -> None:
    self.added.clear()
    self.removed.clear()


class Issue:
  """Class representing a single issue."""

  def __init__(self) -> None:
    self.blocking: Optional[List[int]] = None
    self.blocked_on: Optional[List[int]] = None
    self.body: Optional[str] = None
    self.depends_on: Optional[List[int]] = None
    self.cc: ChangeList = ChangeList()
    self.closed: Optional[datetime.datetime] = None
    self.comment: Optional[str] = ''
    self.components: ChangeList = ChangeList()
    self.created: Optional[datetime.datetime] = None
    self.id: int = 0
    self.labels: ChangeList = ChangeList()
    self.merged_into: Optional[int] = None
    self.merged_into_project: Optional[str] = None
    self.open: bool = False
    self.owner: Optional[str] = None
    self.reporter: Optional[str] = None
    self.status: Optional[str] = None
    self.stars: int = 0
    self.summary: Optional[str] = None
    self.updated: Optional[datetime.datetime] = None

    self.dirty: bool = False
    self.send_email: bool = True
    self.new: bool = True
    self.itm: Optional['IssueTrackerManager'] = None
    self.project_name: Optional[str] = None
    self.comments: Optional[List['Comment']] = None
    self.comment_count: int = 0
    self.first_comment: Optional['Comment'] = None
    self.last_comment: Optional['Comment'] = None
    self.changed: Set[str] = set()

  def __getattribute__(self, item: str) -> Any:
    if item in ['body'] and not object.__getattribute__(self, item):
      comment = self.get_first_comment()
      if comment:
        self.__setattr__(item, comment.comment)

    return object.__getattribute__(self, item)

  def __setattr__(self, name: str, value: Any) -> None:
    self.__dict__[name] = value
    if 'changed' in self.__dict__:
      self.__dict__['changed'].add(name)

    # Automatically set the project name if the itm is set.
    if name == 'itm' and value and hasattr(value, 'project_name'):
      self.__dict__['project_name'] = value.project_name

    # Treat comments and dirty flag specially.
    if name not in ('dirty', 'body', 'comments', 'itm', 'new', 'comment_count',
                    'first_comment', 'last_comment', 'project_name', 'changed',
                    'send_email'):
      self.__dict__['dirty'] = True

    if name in ('dirty') and not value:
      self.labels.reset()
      self.cc.reset()
      if 'changed' in self.__dict__:
        self.changed.clear()

  def __getstate__(self) -> Dict[str, Any]:
    """Ensure that we don't pickle the itm.

    This would raise an exception due to the way the apiary folks did their
    information (i.e. OAuth kicking us once again).
    """
    result_dict = self.__dict__.copy()
    del result_dict['itm']
    return result_dict

  def __setstate__(self, new_dict: Dict[str, Any]) -> None:
    self.__dict__.update(new_dict)
    self.itm = None

  def _remove_tracked_value(self, target: ChangeList, value: str) -> None:
    for existing_value in target:
      if existing_value.lower() == value.lower():
        target.remove(existing_value)
        self.dirty = True
        return

  def add_component(self, component: str) -> None:
    if not self.has_component(component):
      self.components.append(component)
      self.dirty = True

  def remove_component(self, component: str) -> None:
    if self.has_component(component):
      self._remove_tracked_value(self.components, component)
      self.add_component('-%s' % component)

  def remove_components_by_prefix(self, prefix: str) -> None:
    components = self.get_components_by_prefix(prefix)
    for component in components:
      self.remove_component(component)

  def add_label(self, label: str) -> None:
    if not self.has_label(label):
      self.labels.append(label)
      self.dirty = True

  def remove_label(self, label: str) -> None:
    if self.has_label(label):
      self._remove_tracked_value(self.labels, label)
      self.add_label('-%s' % label)

  def remove_label_by_prefix(self, prefix: str) -> None:
    labels = self.get_labels_by_prefix(prefix)
    for label in labels:
      self.remove_label(label)

  def add_cc(self, cc: str) -> None:
    if not self.has_cc(cc):
      self.cc.append(cc)
      self.dirty = True

  def remove_cc(self, cc: str) -> None:
    if self.has_cc(cc):
      self.cc.remove(cc)
      self.dirty = True

  def get_components_by_prefix(self, prefix: str) -> List[str]:
    return get_values_matching(self.components, '%s.*' % prefix)

  def get_components_containing(self, expression: str) -> List[str]:
    return get_values_containing(self.components, expression)

  def get_components_matching(self, expression: str) -> List[str]:
    return get_values_matching(self.components, expression)

  def has_components_containing(self, expression: str) -> bool:
    return has_values_containing(self.components, expression)

  def has_components_matching(self, expression: str) -> bool:
    return has_values_matching(self.components, expression)

  def has_component(self, value: str) -> bool:
    return has_value(self.components, value)

  def get_labels_by_prefix(self, prefix: str) -> List[str]:
    return get_values_matching(self.labels, '%s.*' % prefix)

  def get_labels_containing(self, expression: str) -> List[str]:
    return get_values_containing(self.labels, expression)

  def get_labels_matching(self, expression: str) -> List[str]:
    return get_values_matching(self.labels, expression)

  def has_label_by_prefix(self, prefix: str) -> bool:
    return has_values_containing(self.labels, '%s.*' % prefix)

  def has_label_containing(self, expression: str) -> bool:
    return has_values_containing(self.labels, expression)

  def has_label_matching(self, expression: str) -> bool:
    return has_values_matching(self.labels, expression)

  def has_label(self, value: str) -> bool:
    return has_value(self.labels, value)

  def has_cc(self, value: str) -> bool:
    return has_value(self.cc, value)

  def has_comment_with_label(self, label: str) -> bool:
    comments = self.get_comments()
    if not comments:
      return False
    for comment in comments:
      if comment.has_label(label):
        return True
    return False

  def has_comment_with_label_by_prefix(self, prefix: str) -> bool:
    comments = self.get_comments()
    if not comments:
      return False
    for comment in comments:
      if comment.get_labels_by_prefix(prefix):
        return True
    return False

  def get_comments(self) -> Optional[List['Comment']]:
    if not self.comments and self.itm:
      self.comments = self.itm.get_comments(self.id)
      self.comment_count = len(self.comments)
    return self.comments

  def get_first_comment(self) -> Optional['Comment']:
    if not self.first_comment and self.itm:
      self.first_comment = self.itm.get_first_comment(self.id)
    return self.first_comment

  def get_last_comment(self) -> Optional['Comment']:
    if not self.last_comment and self.itm:
      self.last_comment = self.itm.get_last_comment(self.id)
    return self.last_comment

  def get_comment_count(self) -> int:
    if not self.comment_count and self.itm:
      self.comment_count = self.itm.get_comment_count(self.id)
    return self.comment_count

  def save(self, send_email: Optional[bool] = None) -> None:
    if self.itm:
      self.itm.save(self, send_email)

  def refresh(self) -> 'Issue':
    if self.itm:
      self.comments = None
      self.last_comment = None
      self.comment_count = 0
      self.itm.refresh(self)
    return self
