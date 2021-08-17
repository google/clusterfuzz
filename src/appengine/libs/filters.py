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
"""Filter methods for parsing params. Every search use case is the same.
  There are params for filters, and there is a keyword that contains filters
  inside."""
# pylint: disable=invalid-name

import re
import sys

from clusterfuzz._internal.datastore import search_tokenizer
from libs import helpers

KEYWORD_FIELD_REGEX = (
    '(?: +|^)%s:((?:"[^"]*")|(?:\'[^\']*\')|(?:[^ ]*))(?: +|$)')


def is_empty(value):
  """Determine if the param's value is considered as empty."""
  return not value


def has_params(params, filters):
  """Check if there's any param."""
  return any(params.get(fltr.param_key) for fltr in filters)


def extract_keyword_field(keyword, field):
  """Extract the value from the keyword given the field and return the new
    keyword."""
  regex = re.compile(KEYWORD_FIELD_REGEX % field, flags=re.IGNORECASE)
  match = re.search(regex, keyword)

  if match:
    value = match.group(1)
    if value.startswith('"') and value.endswith('"'):
      value = value.strip('"')
    elif value.startswith("'") and value.endswith("'"):
      value = value.strip("'")
    return re.sub(regex, ' ', keyword), value
  return keyword, None


def get_boolean(value):
  """Convert yes/no to boolean or raise Exception."""
  if value == 'yes':
    return True
  if value == 'no':
    return False
  raise ValueError("The value must be 'yes' or 'no'.")


def get_string(value):
  """Get sanitized string."""
  return value.strip()


class Filter(object):
  """Base filter."""

  def add(self, query, params):
    """Set query according to params."""
    raise NotImplementedError


class SimpleFilter(Filter):
  """A simple filter that reads value from only one key."""

  def __init__(self,
               field,
               param_key,
               transformers=None,
               required=False,
               operator=None):
    self.field = field
    self.param_key = param_key
    self.transformers = transformers or []
    self.required = required
    self.extras = {}
    if operator:
      self.extras['operator'] = operator

  def add(self, query, params):
    """Set query according to params."""
    value = params.get(self.param_key)
    if is_empty(value):
      if self.required:
        raise helpers.EarlyExitException("'%s' is required." % self.param_key,
                                         400)
      return

    try:
      for transformer in self.transformers:
        value = transformer(value)
    except ValueError:
      raise helpers.EarlyExitException(
          "Invalid '%s': %s" % (self.param_key, sys.exc_info()[1]), 400)

    query.filter(self.field, value, **self.extras)


def String(field, param_key, required=False):
  """Return a string filter."""
  return SimpleFilter(
      field, param_key, transformers=[get_string], required=required)


def Boolean(field, param_key, required=False):
  """Return a boolean filter that converts yes/no to True/False."""
  return SimpleFilter(
      field, param_key, transformers=[get_boolean], required=required)


def NegativeBoolean(field, param_key, required=False):
  """Return a boolean filter that converts yes/no to False/True."""
  return SimpleFilter(
      field,
      param_key,
      transformers=[get_boolean, lambda v: not v],
      required=required)


def Int(field, param_key, required=False, operator=None):
  """return an int filter."""
  return SimpleFilter(
      field,
      param_key,
      transformers=[int],
      required=required,
      operator=operator)


class Keyword(SimpleFilter):
  """Extract keyword fields and filter by the rest."""

  def __init__(self, keyword_filters, field, param_key):
    self.keyword_filters = keyword_filters
    super(Keyword, self).__init__(field, param_key, required=False)

  def add(self, query, params):
    """Add filter."""
    value = params.get(self.param_key, '')
    for fltr in self.keyword_filters:
      value, raw_value = extract_keyword_field(value, fltr.param_key)
      fltr.add(query, {fltr.param_key: raw_value})

    for keyword in value.split(' '):
      keyword = search_tokenizer.prepare_search_keyword(keyword)
      if is_empty(keyword):
        continue
      query.filter(self.field, keyword)


def add(query, params, filters):
  """Add filters to query, given the param."""
  for fltr in filters:
    fltr.add(query, params)
