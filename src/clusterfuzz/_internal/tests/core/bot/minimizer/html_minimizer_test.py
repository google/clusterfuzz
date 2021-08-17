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
"""Tests for the HTML minimizer."""

import unittest

from clusterfuzz._internal.bot.minimizer import html_minimizer
from clusterfuzz._internal.tests.test_libs import helpers


class HTMLMinimizerTest(unittest.TestCase):
  """Test for HTML Minimizer."""

  def setUp(self):
    helpers.patch_environ(self)
    helpers.patch(self, [(
        'js_minimizer',
        'clusterfuzz._internal.bot.minimizer.js_minimizer.JSMinimizer.minimize'
    ), (
        'html_minimizer',
        'clusterfuzz._internal.bot.minimizer.chunk_minimizer.ChunkMinimizer.minimize'
    ), ('line_minimizer',
        'clusterfuzz._internal.bot.minimizer.delta_minimizer.DeltaMinimizer.minimize'
       )])

    # HTML Minimizer passes data to a series of sub-minimizers. These take a
    # long time to run. We just want to test that the results are being handled
    # correctly.
    self.mock.js_minimizer.side_effect = self._mock_js_minimization
    self.mock.html_minimizer.side_effect = self._mock_html_minimization
    self.mock.line_minimizer.side_effect = self._mock_line_minimization

    self._html_data_begin = b"""
    <!-- /mnt/fuzzer/gecko-tests/layout/reftests/bugs/256180-2.html -->
    <!DOCTYPE html>
    <html>
    <head>
    <meta charset="utf-8">
    <font></font>
    <script>"""

    self._script_data = b"""
    function a() {
        var a = 0;
    }
    
    function b() {
        var b = document.createTextNode("PASS");
    }"""

    self._html_data_end = b"""</script>
    <style>
        div {
            display: table-cell;
        }
    </style>
    </html>"""

    self._simple_test = (
        self._html_data_begin + self._script_data + self._html_data_end)

    self._minimizer = html_minimizer.HTMLMinimizer(self._mock_test_function())

  def _mock_test_function(self):
    return True

  def _mock_js_minimization(self, minimizer, data):
    """Mock js_minimization. Returns simple js_minimized code."""
    # pylint: disable=unused-argument
    return minimizer.token_combiner(
        [b'var b = document.createTextNode("PASS")\n'])

  def _mock_html_minimization(self, minimizer, data):
    """Mock html minimization. Returns minimized top tags when its called for
    the first section, otherwise returns minimized bottom section"""
    # The first 3 times the html_minimizer is called will be for the begining.
    if b'<html>' in data:
      return minimizer.token_combiner([b'<html>\n<script>\n'])

    return minimizer.token_combiner([b'</script>\n</html>'])

  def _mock_line_minimization(self, minimizer, data):
    """Mock line minimization. Assume data is already line-minimized."""
    # pylint: disable=unused-argument
    return data

  def test_get_tokens_and_metadata_splits_correct_number(self):
    """Test that the html minimizer splits the data into the correct number of
    sections."""
    tokens = self._minimizer.get_tokens_and_metadata(self._simple_test)

    self.assertEqual(len(tokens), 3)

  def test_get_tokens_and_metadata_splits_correct_types(self):
    """Test that each of the sections the data is split into for minimization
    are classified correctly."""
    tokens = self._minimizer.get_tokens_and_metadata(self._simple_test)

    self.assertEqual(tokens[0].token_type, self._minimizer.Token.TYPE_HTML)
    self.assertEqual(tokens[1].token_type, self._minimizer.Token.TYPE_SCRIPT)
    self.assertEqual(tokens[2].token_type, self._minimizer.Token.TYPE_HTML)

  def test_get_tokens_and_metadata_splits_correct_data(self):
    """Test that each of the sections the data is split into for minimization
    contains the correct data"""
    tokens = self._minimizer.get_tokens_and_metadata(self._simple_test)

    self.assertEqual(tokens[0].data, self._html_data_begin)
    self.assertEqual(tokens[1].data, self._script_data)
    self.assertEqual(tokens[2].data, self._html_data_end)

  def test_minimization_returns_correct_result(self):
    """Test that the minimizer goes through all of the correct sub-minimizers
    gives the correct tokenizers, and returns the minimized product."""
    minimized = b'<html>\n<script>\nvar b = document.createTextNode("PASS")' \
                b'\n</script>\n</html>'
    res = self._minimizer.minimize(self._simple_test)
    self.assertEqual(res, minimized)

  def test_combine_worker_tokens_with_prefix_and_suffix(self):
    """Test that combine worker tokens works the way that the minimizer expects
    it to."""
    prefix = b'PRE'
    suffix = b'POST'
    tokens = [b'Here', b'Are', b'The', b'Tokens']

    combo = self._minimizer.combine_worker_tokens(tokens, prefix, suffix)

    self.assertEqual(combo, b'PREHereAreTheTokensPOST')
