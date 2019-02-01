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

import re


class Comment(object):
  """Class representing a single comment update."""

  def __init__(self):
    self.author = None
    self.cc = None
    self.comment = None
    self.components = []
    self.created = None
    self.labels = []
    self.summary = None
    self.status = None
    self.owner = None
    self.id = 0

  def has_label_containing(self, expression):
    return any(self.get_labels_containing(expression))

  def get_labels_containing(self, expression):
    regex = re.compile(expression, re.DOTALL | re.IGNORECASE)
    return [label for label in self.labels if regex.search(label)]

  def has_label_matching(self, expression):
    return any(self.get_labels_matching(expression))

  def get_labels_matching(self, expression):
    regex = re.compile(expression + r'\Z', re.DOTALL | re.IGNORECASE)
    return [label for label in self.labels if regex.match(label)]

  def get_labels_by_prefix(self, prefix):
    return self.get_labels_matching('%s.*' % prefix)

  def has_label(self, value):
    for label in self.labels:
      if label.lower() == value.lower():
        return True

    return False
