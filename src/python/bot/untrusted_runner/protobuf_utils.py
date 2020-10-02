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
"""Protobuf helpers."""


def get_protobuf_field(result, buf, field_name):
  """Add protobuf field to dict, if the field exists."""
  if buf.HasField(field_name):
    result[field_name] = getattr(buf, field_name)


def encode_utf8_if_unicode(data):
  """Encode string as utf-8 if it's unicode."""
  if isinstance(data, str):
    return data.encode('utf-8')

  return data
