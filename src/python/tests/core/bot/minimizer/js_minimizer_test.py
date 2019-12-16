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
"""Tests for the Antlr Tokenizer."""

from bot.minimizer import js_minimizer
from bot.tokenizer import antlr_tokenizer
from bot.tokenizer.grammars.JavaScriptLexer import JavaScriptLexer
from tests.test_libs import helpers
import unittest


class JSMinimizerTest(unittest.TestCase):
  """Test for Javascript Minimizer"""

  def setUp(self):
    self._tests_to_queue = []

    helpers.patch_environ(self)
    helpers.patch(self, [
        'bot.minimizer.minimizer.Testcase.prepare_test',
        'bot.minimizer.minimizer.Testcase.process'
    ])

    helpers.patch_environ(self)
    self.mock.prepare_test.side_effect = self._mock_prepare_test
    self.mock.process.side_effect = self._mock_process()

    self._tokenizer = antlr_tokenizer.AntlrTokenizer(JavaScriptLexer)
    self._minimizer = js_minimizer.JSMinimizer(
        self._mock_test_function(),
        tokenizer=self._tokenizer.tokenize,
        token_combiner=self._tokenizer.combine)

  def _mock_process(self):
    return

  def _mock_prepare_test(self, testcase, hypothesis):
    txt = ""
    for index in hypothesis:
      txt += testcase.tokens[index]

    self._tests_to_queue.append(txt)

  def _mock_test_function(self):
    return True

  def test_minimize_empty_string(self):
    data = ""

    self._minimizer.minimize(data)

    self.assertEqual(self._tests_to_queue, [])

  def test_bracket_hypotheses_1(self):
    """Hypothesis is: Remove from start of line to open brace and the closing
    brace. e.g.: if (statement_that_evaluates_to_true) { crash() } -> crash()"""
    data = "if(boolean) { crash }"

    self._minimizer.minimize(data)

    self.assertIn("if(boolean) {}", self._tests_to_queue)

  def test_bracket_hypotheses_2(self):
    """Hypothesis is: Remove previous tokens and from the closing brace to the
    next one. e.g.: try { crash() } catch(e) {} -> crash()"""
    data = "try{ crash() } catch(e){ }"
    self._minimizer.minimize(data)

    self.assertIn("try{} catch(e){ }", self._tests_to_queue)

  def test_handle_if_else(self):
    data = "if(boolean) {crash} else { do_something_else }"

    self._minimizer.minimize(data)

    self.assertIn("if(boolean) {}", self._tests_to_queue)
    self.assertIn("if(boolean) {} else { do_something_else }",
                  self._tests_to_queue)
    self.assertIn("if(boolean) {crash} else {}", self._tests_to_queue)

  def test_remove_function_call(self):
    data = "function name(param1, param2){ stuff inside function }"

    self._minimizer.minimize(data)

    self.assertIn("function name(param1, param2){}", self._tests_to_queue)

  def test_handle_bracket_with_new_line(self):
    data = """try{\n\tcrash()\n}\ncatch(e){\n\n}"""

    self._minimizer.minimize(data)

    self.assertIn("try{}", self._tests_to_queue)
    self.assertIn("try{}\ncatch(e){\n\n}", self._tests_to_queue)

  def test_handle_function_with_new_lines(self):
    data = "function name(param1,\n\t\tparam2){\n\tstuff inside function\n}"

    self._minimizer.minimize(data)

    self.assertIn("function name(param1,\n\t\tparam2){}", self._tests_to_queue)

  def test_handle_paren_hypothesis_1(self):
    """Hypothesis is Remove the parentheses and the previous token.
      e.g.: assertTrue(crash()); -> crash()"""
    data = "assertTrue(crash());"

    self._minimizer.minimize(data)

    self.assertIn("assertTrue()", self._tests_to_queue)

  def test_handle_paren_hypothesis_2(self):
    """Hypothesis is Remove everything between the parentheses.
      e.g.: crash(junk, more_junk) -> crash()"""
    data = "crash(junk, more_junk)"

    self._minimizer.minimize(data)

    self.assertIn("junk, more_junk", self._tests_to_queue)

  def test_handle_paren_hypothesis_3(self):
    """Hypothesis is Like 1, but to start of line instead of previous token.
        e.g.: leftover_junk = (function() {
             });"""
    data = "leftover_junk = (function(){\n})"

    self._minimizer.minimize(data)

    self.assertIn("leftover_junk = (function(){\n})", self._tests_to_queue)

  def test_handle_paren_hypothesis_4(self):
    """Hypothesis is Like 3, but also from the closing brace to the next one.
      e.g.: (function(global) { })(this);"""
    data = "(function(global) { })(this)"

    self._minimizer.minimize(data)

    self.assertIn("(function(global) { })(this)", self._tests_to_queue)

  def test_handle_comma_hypothesis_1(self):
    """Hypothesis is: Remove comma and left-hand-side.
      e.g.: f(whatever, crash()) -> f(crash())"""
    data = "f(whatever, crash())"

    self._minimizer.minimize(data)

    self.assertIn("whatever,", self._tests_to_queue)

  def test_handle_comma_hypothesis_2(self):
    """Hypothesis is Remove comma and right-hand-side.
      e.g.: f(crash(),whatever) -> f(crash())"""
    data = "f(crash(), whatever)"

    self._minimizer.minimize(data)

    self.assertIn(", whatever", self._tests_to_queue)
