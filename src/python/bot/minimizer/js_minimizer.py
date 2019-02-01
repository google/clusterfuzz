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
"""Minimizer used for additional reduction on javascript test cases."""

import delta_minimizer
import minimizer
import js_tokenizer
import utils


class JSMinimizer(minimizer.Minimizer):
  """Intended as a second-pass minimizer to remove unneeded tokens from JS."""

  def _execute(self, data):
    testcase = minimizer.Testcase(data, self)

    brace_stack = []
    paren_stack = []
    last_start_of_line_token = 0

    for index, token in enumerate(testcase.tokens):
      if token == '{':
        brace_stack.append((last_start_of_line_token, index))

      elif token == '}' and brace_stack:
        previous_line_start, previous_end = brace_stack.pop()

        # Move |previous_line_start| to the first non-empty string.
        while previous_line_start > 0:
          if testcase.tokens[previous_line_start].strip():
            break
          previous_line_start -= 1

        # Two hypotheses for tokens grouped by curly braces:
        # 1) Remove from start of line to curly brace and the closing brace.
        #    e.g.: if (statement_that_evaluates_to_true) { crash() } -> crash()
        hypothesis = range(previous_line_start, previous_end + 1) + [index]
        testcase.prepare_test(hypothesis)

        # 2) Remove previous tokens and from the closing brace to the next one.
        #    e.g.: try { crash() } catch(e) {} -> crash()
        future_index = len(testcase.tokens)
        for future_index in xrange(index + 1, len(testcase.tokens)):
          if testcase.tokens[future_index] == '}':
            break
        if future_index != len(testcase.tokens):
          lookahead_hypothesis = hypothesis + range(index + 1, future_index + 1)
          testcase.prepare_test(lookahead_hypothesis)

      elif token == '(':
        paren_stack.append((last_start_of_line_token, index))

      elif token == ')' and paren_stack:
        # Three hypotheses for tokens grouped by parentheses:
        # 1) Remove the parentheses and the previous token.
        #    e.g.: assertTrue(crash()); -> crash()
        previous_line_start, previous_end = paren_stack.pop()
        if previous_end > 0:
          hypothesis = [previous_end - 1, previous_end, index]
          testcase.prepare_test(hypothesis)

        # 2) Remove everything between the parentheses.
        #    e.g. crash(junk, more_junk) -> crash()
        if index - previous_end > 1:
          hypothesis = range(previous_end + 1, index)
          testcase.prepare_test(hypothesis)

        # 3) Like 1, but to start of line instead of previous token.
        #    e.g.: leftover_junk = (function() {
        #          });
        hypothesis = range(previous_line_start, previous_end + 1) + [index]
        testcase.prepare_test(hypothesis)

        # 4) Like 3, but also from the closing brace to the next one.
        #    e.g.: (function(global) { })(this);
        future_index = len(testcase.tokens)
        for future_index in xrange(index + 1, len(testcase.tokens)):
          if testcase.tokens[future_index] == ')':
            break
        if future_index != len(testcase.tokens):
          lookahead_hypothesis = range(previous_line_start, future_index + 1)
          testcase.prepare_test(lookahead_hypothesis)

      elif token == ',':
        # Two hypotheses for commas:
        # 1) Remove comma and left-hand-side.
        #    e.g.: f(whatever, crash()) -> f(crash())
        if index > 0:
          hypothesis = [index - 1, index]
          testcase.prepare_test(hypothesis)

        # 2) Remove comma and right-hand-side.
        #    e.g.: f(crash(), whatever) -> f(crash())
        if index + 1 < len(testcase.tokens):
          hypothesis = [index, index + 1]
          testcase.prepare_test(hypothesis)

      # Keep track of where the previous line started.
      elif token.endswith('\n'):
        last_start_of_line_token = index + 1

    testcase.process()
    return testcase

  @staticmethod
  def run(data,
          thread_count=minimizer.DEFAULT_THREAD_COUNT,
          file_extension='.js'):
    """Attempt to minimize a javascript test case."""
    line_minimizer = delta_minimizer.DeltaMinimizer(
        utils.test, max_threads=thread_count, file_extension=file_extension)
    comment_minimizer = delta_minimizer.DeltaMinimizer(
        utils.test,
        max_threads=thread_count,
        tokenizer=js_tokenizer.comment_tokenizer,
        token_combiner=js_tokenizer.combine_tokens,
        file_extension=file_extension)
    bracket_minimizer = JSMinimizer(
        utils.test,
        max_threads=thread_count,
        tokenizer=js_tokenizer.bracket_tokenizer,
        token_combiner=js_tokenizer.combine_tokens,
        file_extension=file_extension)
    paren_minimizer = JSMinimizer(
        utils.test,
        max_threads=thread_count,
        tokenizer=js_tokenizer.paren_tokenizer,
        token_combiner=js_tokenizer.combine_tokens,
        file_extension=file_extension)
    comma_minimizer = JSMinimizer(
        utils.test,
        max_threads=thread_count,
        tokenizer=js_tokenizer.comma_tokenizer,
        token_combiner=js_tokenizer.combine_tokens,
        file_extension=file_extension)

    result = comment_minimizer.minimize(data)
    result = line_minimizer.minimize(result)
    result = bracket_minimizer.minimize(result)
    result = paren_minimizer.minimize(result)
    result = comma_minimizer.minimize(result)
    result = line_minimizer.minimize(result)
    return result
