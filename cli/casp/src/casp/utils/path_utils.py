# Copyright 2025 Google LLC
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
"""Manages the CASP path search and manegement.

This module provides a set of utilities related 
to file and directory path manipulation and discovery.
"""

import os
from pathlib import Path

def find_butler(start_path: Path) -> Path | None:
  """Find the butler.py script in the directory tree."""
  current_path = os.path.abspath(start_path)
  butler_path = os.path.join(current_path, 'butler.py')
  if os.path.exists(butler_path):
    return Path(butler_path)
  return None