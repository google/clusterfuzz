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

# pylint: disable=protected-access
"""Script to convert python Datastore types to Go and protobufs."""

import ast
import inspect
import os
import re
import subprocess

from src.python.datastore import data_types

LICENSE_HEADER = """// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
"""

GO_TYPES_HEADER = ('// Package types contains Datastore types '
                   '(auto-generated from src/python/datastore/data_types.py).\n'
                   '// Please modify data_types.py and run '
                   '`python butler.py generate_datastore_models` '
                   'if you wish to modify a model.\n'
                   'package types\n\n'
                   'import (\n'
                   '\t"time"\n\n'
                   '\t"cloud.google.com/go/datastore"\n'
                   ')\n\n')


class GenerateDataStoreModelsException(Exception):
  """Base exception class."""


class PropertyOrderVisitor(ast.NodeVisitor):
  """Visitor to collect property name ordering."""

  def __init__(self, ds_model, sort_order):
    super(PropertyOrderVisitor, self).__init__()
    self.order = 0
    self._sort_order = sort_order
    self._ds_model = ds_model

  def visit_ClassDef(self, node):  # pylint: disable=invalid-name
    """Class definition visitor."""
    if node.name != self._ds_model.__name__:
      ast.NodeVisitor.generic_visit(self, node)
      return

    for expr in node.body:
      if expr.__class__.__name__ != 'Assign':
        continue

      self._sort_order[expr.targets[0].id] = self.order
      self.order += 1


class DsType(object):
  """Wrapper for a Datastore type (db or ndb)."""

  def __init__(self, ds_type, ndb=False):
    self.ndb = ndb
    self._ds_type = ds_type

  @property
  def type_name(self):
    return self._ds_type.__class__.__name__

  @property
  def indexed(self):
    if self.ndb:
      return self._ds_type._indexed

    return self._ds_type.indexed

  @property
  def repeated(self):
    if self.ndb:
      return self._ds_type._repeated

    return False

  @property
  def item_type(self):
    return self._ds_type.item_type

  @property
  def modelclass(self):
    if not self.ndb:
      raise GenerateDataStoreModelsException(
          'DB properties do not have modelclass property.')

    return self._ds_type._modelclass


class DsModel(object):
  """Wrapper for a Datastore model (db or ndb)."""

  def __init__(self, ds_model, data_types_ast):
    self.ndb = _is_model_ndb(ds_model)
    self._ds_model = ds_model

    # Preserve order of properties, as Python does not preserve the order in
    # which they were declared.
    sort_order = {}
    PropertyOrderVisitor(ds_model, sort_order).visit(data_types_ast)

    if self.ndb:
      self.properties = ds_model._properties.items()
    else:
      self.properties = ds_model.properties().items()

    self.properties = [
        (name, DsType(value, self.ndb)) for name, value in self.properties
    ]
    self.properties.sort(key=lambda item: sort_order[item[0]])

  @property
  def name(self):
    return self._ds_model.__name__


def _is_model_ndb(ds_model):
  """Return whether or not the model is ndb."""
  for cls in inspect.getmro(ds_model):
    if 'google.appengine.ext.ndb' in cls.__module__:
      return True

  return False


def snake_case_to_camel_case(name):
  """Convert name from snake case to camel case for Go."""
  parts = name.split('_')
  return capitalize_acronyms(''.join(part.capitalize() for part in parts))


def capitalize_acronyms(name):
  """Capitalize acronyms."""
  known_acronyms = [
      'Cc',
      'Cl',
      'Cpu',
      'Db',
      'Gce',
      'Gcs',
      'Html',
      'Http',
      'Id',
      'Os',
      'Tls',
      'Url',
  ]

  for acronym in known_acronyms:
    # Match occurrences either at end of string, or before the start of another
    # word, or 's' (plural).
    pattern = acronym + '([A-Zs]|$)'
    name = re.sub(pattern, acronym.upper() + r'\1', name)

  return name


def py_to_go_type(py_type):
  """Return the Go equivalent for a python type."""
  if py_type in [str, unicode, basestring]:
    return 'string'

  if py_type == int:
    return 'int'

  if py_type == long:
    return 'int64'

  if py_type == float:
    return 'float64'

  raise GenerateDataStoreModelsException('Unknown python type ' +
                                         py_type.__class__.__name__)


def db_to_go_type(prop):
  """Return the Go equivalent for a python db type."""
  go_type = ''

  if prop.type_name == 'StringProperty':
    go_type = 'string'
  elif prop.type_name == 'TextProperty':
    go_type = 'string'
  elif prop.type_name == 'IntegerProperty':
    go_type = 'int'
  elif prop.type_name == 'BooleanProperty':
    go_type = 'bool'
  elif prop.type_name == 'FloatProperty':
    go_type = 'float64'
  elif prop.type_name == 'ListProperty':
    go_type = '[]' + py_to_go_type(prop.item_type)
  elif prop.type_name == 'StringListProperty':
    go_type = '[]string'
  elif (prop.type_name == 'DateTimeProperty' or
        prop.type_name == 'DateProperty'):
    go_type = 'time.Time'
  elif prop.type_name == 'StructuredProperty':
    go_type = prop.modelclass.__name__
  elif prop.type_name == 'BlobProperty':
    go_type = '[]byte'
  else:
    raise GenerateDataStoreModelsException('Unknown type ' + prop.type_name)

  if prop.repeated:
    return '[]' + go_type

  return go_type


def db_to_go_struct(db_type):
  """Convert a datastore type to a Go struct."""
  result = 'type %s struct {\n' % db_type.name
  result += '\tKey *datastore.Key `datastore:"__key__"`\n'

  for name, prop in db_type.properties:
    noindex = ''

    if (not prop.indexed or prop.type_name == 'TextProperty' or
        prop.type_name == 'BlobProperty'):
      noindex = ',noindex'
    metadata = '`datastore:"%s%s"`' % (name, noindex)

    result += '\t%s %s %s\n' % (snake_case_to_camel_case(name),
                                db_to_go_type(prop), metadata)
  result += '}\n'

  return result


def generate_go(go_output_path, models):
  """Generate Go code for the models."""
  with open(go_output_path, 'w') as f:
    f.write(LICENSE_HEADER)
    f.write('\n')
    f.write(GO_TYPES_HEADER)

    for model in models:
      f.write('// ' + model.name + ' is auto-generated from data_types.py.\n')
      f.write(db_to_go_struct(model))
      f.write('\n')

  subprocess.check_output(['gofmt', '-w', go_output_path])


def _is_model_class(obj):
  """Return whether or not the given object is a Model class."""
  if not inspect.isclass(obj):
    return False

  if obj.__name__ == 'Model':
    # Base model class, don't include.
    return False

  return 'Model' in [o.__name__ for o in inspect.getmro(obj)]


def execute(_):
  """Generate Datastore models for Go."""
  output_path = os.path.join(os.environ['ROOT_DIR'], 'src', 'go', 'cloud', 'db',
                             'types', 'types.go')

  data_types_path = data_types.__file__.rstrip('c')
  with open(data_types_path) as f:
    data_types_ast = ast.parse(f.read())

  models = []
  for _, obj in inspect.getmembers(data_types):
    if not _is_model_class(obj):
      continue

    models.append(DsModel(obj, data_types_ast))
    # Flatten nested classes (up to 1 nesting).
    for _, subobj in inspect.getmembers(obj):
      if _is_model_class(subobj):
        models.append(DsModel(subobj, data_types_ast))

  generate_go(output_path, models)
  # TODO(ochang): Generate protobufs for RPCs.
