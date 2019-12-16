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
"""Tests for the Java Script minimizer."""

import unittest

from bot.minimizer import js_minimizer
from bot.tokenizer import antlr_tokenizer
from bot.tokenizer.grammars.JavaScriptLexer import JavaScriptLexer
from tests.test_libs import helpers


class JSMinimizerTest(unittest.TestCase):
  """Test for Javascript Minimizer"""

  def setUp(self):
    self._hypotheses_tested = []

    helpers.patch_environ(self)
    helpers.patch(self, [
        'bot.minimizer.minimizer.Testcase.prepare_test',
        'bot.minimizer.minimizer.Testcase.process'
    ])

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
    txt = ''
    for index in hypothesis:
      txt += testcase.tokens[index]

    self._hypotheses_tested.append(txt)

  def _mock_test_function(self):
    return True

  def test_minimize_empty_string(self):
    """Minimizer does not break on empty data"""
    data = ''

    self._minimizer.minimize(data)

    self.assertEqual(self._hypotheses_tested, [])

  def test_if_hypothesis(self):
    """e.g.: if (statement_that_evaluates_to_true) { crash() } -> crash()"""
    data = "if(boolean) { crash }"

    self._minimizer.minimize(data)

    self.assertIn("if(boolean) {}", self._hypotheses_tested)

  def test_try_catch_hypothesis(self):
    """e.g.: try { crash() } catch(e) {} -> crash()"""
    data = "try{ crash() } catch(e){ }"
    self._minimizer.minimize(data)

    self.assertIn("try{} catch(e){ }", self._hypotheses_tested)

  def test_handle_if_else(self):
    """Make sure the minimizer runs all of the other hypothesis cleanly on
      if else"""
    data = "if(boolean) {crash} else { do_something_else }"

    self._minimizer.minimize(data)

    self.assertIn("if(boolean) {}", self._hypotheses_tested)
    self.assertIn("if(boolean) {} else { do_something_else }",
                  self._hypotheses_tested)
    self.assertIn("if(boolean) {crash} else {}", self._hypotheses_tested)

  def test_remove_function_call(self):
    """Test that it removes functions calls effectively"""
    data = "function name(param1, param2){ stuff inside function }"

    self._minimizer.minimize(data)

    self.assertIn("function name(param1, param2){}", self._hypotheses_tested)

  def test_handle_bracket_with_new_line(self):
    """Test for try/catch with extra whitespace"""
    data = """try{\n\tcrash()\n}\ncatch(e){\n\n}"""

    self._minimizer.minimize(data)

    self.assertIn("try{}", self._hypotheses_tested)
    self.assertIn("try{}\ncatch(e){\n\n}", self._hypotheses_tested)

  def test_handle_function_with_new_lines(self):
    """Test for functions with extra whitespace"""
    data = "function name(param1,\n\t\tparam2){\n\tstuff inside function\n}"

    self._minimizer.minimize(data)

    self.assertIn("function name(param1,\n\t\tparam2){}",
                  self._hypotheses_tested)

  def test_remove_outer_paren(self):
    """e.g.: assertTrue(crash()); -> crash()"""
    data = "assertTrue(crash());"

    self._minimizer.minimize(data)

    self.assertIn("assertTrue()", self._hypotheses_tested)

  def test_remove_inside_paren(self):
    """Hypothesis is Remove everything between the parentheses.
      e.g.: crash(junk, more_junk) -> crash()"""
    data = "crash(junk, more_junk)"

    self._minimizer.minimize(data)

    self.assertIn("junk, more_junk", self._hypotheses_tested)

  def test_remove_paren_to_start_of_line(self):
    """e.g.: leftover_junk = (function() {
             });"""
    data = "leftover_junk = (function(){\n})"

    self._minimizer.minimize(data)

    self.assertIn("leftover_junk = (function(){\n})", self._hypotheses_tested)

  def test_remove_paren_with_attached_brackets(self):
    """e.g.: (function(global) { })(this);"""
    data = "(function(global) { })(this)"

    self._minimizer.minimize(data)

    self.assertIn("(function(global) { })(this)", self._hypotheses_tested)

  def test_remove_left_of_comma(self):
    """e.g.: f(whatever, crash()) -> f(crash())"""
    data = "f(whatever, crash())"

    self._minimizer.minimize(data)

    self.assertIn("whatever,", self._hypotheses_tested)

  def test_remove_right_of_comma(self):
    """e.g.: f(crash(),whatever) -> f(crash())"""
    data = "f(crash(), whatever)"

    self._minimizer.minimize(data)

    self.assertIn(", whatever", self._hypotheses_tested)
