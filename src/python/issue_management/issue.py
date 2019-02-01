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

import re


def get_values_containing(target, expression):
  regex = re.compile(expression, re.DOTALL | re.IGNORECASE)
  return [value for value in target if regex.search(value)]


def get_values_matching(target, expression):
  regex = re.compile(expression + r'\Z', re.DOTALL | re.IGNORECASE)
  return [value for value in target if regex.match(value)]


def has_values_containing(target, expression):
  return any(get_values_containing(target, expression))


def has_values_matching(target, expression):
  return any(get_values_matching(target, expression))


def has_value(target, value):
  for target_value in target:
    if target_value.lower() == value.lower():
      return True

  return False


class ChangeList(list):
  """List that tracks changes for incremental updates."""

  def __init__(self, seq=()):
    super(ChangeList, self).__init__(seq)
    self.added = set()
    self.removed = set()

  def append(self, p_object):
    list.append(self, p_object)

    if p_object in self.removed:
      self.removed.remove(p_object)
    else:
      self.added.add(p_object)

  def remove(self, value):
    list.remove(self, value)

    if value in self.added:
      self.added.remove(value)
    else:
      self.removed.add(value)

  def is_changed(self):
    return (len(self.added) + len(self.removed)) > 0

  def reset(self):
    self.added.clear()
    self.removed.clear()


class Issue(object):
  """Class representing a single issue."""

  def __init__(self):
    self.blocking = None
    self.blocked_on = None
    self.body = None
    self.depends_on = None
    self.cc = ChangeList()
    self.closed = None
    self.comment = ''
    self.components = ChangeList()
    self.created = None
    self.id = 0
    self.labels = ChangeList()
    self.merged_into = None
    self.merged_into_project = None
    self.open = False
    self.owner = None
    self.reporter = None
    self.status = None
    self.stars = 0
    self.summary = None
    self.updated = None

    self.dirty = False
    self.send_email = True
    self.new = True
    self.itm = None
    self.project_name = None
    self.comments = None
    self.comment_count = 0
    self.first_comment = None
    self.last_comment = None
    self.changed = set()

  def __getattribute__(self, item):
    if item in ['body'] and not object.__getattribute__(self, item):
      comment = self.get_first_comment()
      self.__setattr__(item, comment.comment)

    return object.__getattribute__(self, item)

  def __setattr__(self, name, value):
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

  def __getstate__(self):
    """Ensure that we don't pickle the itm.

    This would raise an exception due to the way the apiary folks did their
    information (i.e. OAuth kicking us once again).
    """
    result_dict = self.__dict__.copy()
    del result_dict['itm']
    return result_dict

  def __setstate__(self, new_dict):
    self.__dict__.update(new_dict)
    self.itm = None

  def _remove_tracked_value(self, target, value):
    for existing_value in target:
      if existing_value.lower() == value.lower():
        target.remove(existing_value)
        self.dirty = True
        return

  def add_component(self, component):
    if not self.has_component(component):
      self.components.append(component)
      self.dirty = True

  def remove_component(self, component):
    if self.has_component(component):
      self._remove_tracked_value(self.components, component)
      self.add_component('-%s' % component)

  def remove_components_by_prefix(self, prefix):
    components = self.get_components_by_prefix(prefix)
    for component in components:
      self.remove_label(component)

  def add_label(self, label):
    if not self.has_label(label):
      self.labels.append(label)
      self.dirty = True

  def remove_label(self, label):
    if self.has_label(label):
      self._remove_tracked_value(self.labels, label)
      self.add_label('-%s' % label)

  def remove_label_by_prefix(self, prefix):
    labels = self.get_labels_by_prefix(prefix)
    for label in labels:
      self.remove_label(label)

  def add_cc(self, cc):
    if not self.has_cc(cc):
      self.cc.append(cc)
      self.dirty = True

  def remove_cc(self, cc):
    if self.has_cc(cc):
      self.cc.remove(cc)
      self.dirty = True

  def get_components_by_prefix(self, prefix):
    return get_values_matching(self.components, '%s.*' % prefix)

  def get_components_containing(self, expression):
    return get_values_containing(self.components, expression)

  def get_components_matching(self, expression):
    return get_values_matching(self.components, expression)

  def has_components_containing(self, expression):
    return has_values_containing(self.components, expression)

  def has_components_matching(self, expression):
    return has_values_matching(self.components, expression)

  def has_component(self, value):
    return has_value(self.components, value)

  def get_labels_by_prefix(self, prefix):
    return get_values_matching(self.labels, '%s.*' % prefix)

  def get_labels_containing(self, expression):
    return get_values_containing(self.labels, expression)

  def get_labels_matching(self, expression):
    return get_values_matching(self.labels, expression)

  def has_label_by_prefix(self, prefix):
    return has_values_containing(self.labels, '%s.*' % prefix)

  def has_label_containing(self, expression):
    return has_values_containing(self.labels, expression)

  def has_label_matching(self, expression):
    return has_values_matching(self.labels, expression)

  def has_label(self, value):
    return has_value(self.labels, value)

  def has_cc(self, value):
    return has_value(self.cc, value)

  def has_comment_with_label(self, label):
    for comment in self.get_comments():
      if comment.has_label(label):
        return True
    return False

  def has_comment_with_label_by_prefix(self, prefix):
    for comment in self.get_comments():
      if comment.get_labels_by_prefix(prefix):
        return True
    return False

  def get_comments(self):
    if not self.comments and self.itm:
      self.comments = self.itm.get_comments(self.id)
      self.comment_count = len(self.comments)
    return self.comments

  def get_first_comment(self):
    if not self.first_comment and self.itm:
      self.first_comment = self.itm.get_first_comment(self.id)
    return self.first_comment

  def get_last_comment(self):
    if not self.last_comment and self.itm:
      self.last_comment = self.itm.get_last_comment(self.id)
    return self.last_comment

  def get_comment_count(self):
    if not self.comment_count and self.itm:
      self.comment_count = self.itm.get_comment_count(self.id)
    return self.comment_count

  def save(self, send_email=None):
    if self.itm:
      self.itm.save(self, send_email)

  def refresh(self):
    if self.itm:
      self.comments = None
      self.last_comment = None
      self.comment_count = 0
      self.itm.refresh(self)
    return self
